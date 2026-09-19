import { describe, it, expect } from "vitest";
import { buildInspectReportData } from "./inspect.ts";
import { reportParams } from "#core/lib/test/report-data.node.ts";

const START = "buildcage haproxy starting 1787471970000";
const ALLOWED =
  "buildcage 1787471975 https GET 200 708 ts=-- reason=- dst=104.16.1.34:443 https://registry.npmjs.org/pkg";
const REFUSED =
  "buildcage 1787471976 https POST 403 0 ts=PR reason=- dst=1.2.3.4:443 https://evil.example.com/exfil?d=SECRET";
const TLS_PASS =
  "buildcage 1787471977 pass tls 3421 ts=-- reason=- dst=10.0.0.9:5432 sni=db.example.com";
/** What the resolver service echoes before CoreDNS starts. */
const DNS_START = "2026-08-23 16:44:58.000000000  buildcage coredns starting";

describe("buildInspectReportData", () => {
  it("puts everything in one timeline, oldest first", async () => {
    const dns = ["2026-08-23 16:45:00.000000000  [INFO] buildcage dns denied name=z.example.com."];
    const r = await buildInspectReportData(
      [START, REFUSED, ALLOWED, TLS_PASS],
      dns,
      reportParams(),
    );
    expect(r.timeline.length).toBe(4);
    expect(r.timeline.every((e, i) => i === 0 || r.timeline[i - 1].time <= e.time)).toBe(true);
  });

  it("aggregates each side into host rows a rule could be written from", async () => {
    const r = await buildInspectReportData([START, ALLOWED, REFUSED], [], reportParams());
    expect(r.passed[0].host).toBe("registry.npmjs.org");
    expect(r.passed[0].port).toBe("443");
    expect(r.passed[0].ruleType).toBe("HTTPS");
    expect(r.blocked[0].host).toBe("evil.example.com");
    expect(r.blocked[0].reason).toBe("not-allowed");
  });

  it("drops a blocked DNS row from the tables once the same host's request is also blocked", async () => {
    // evil.example.com is REFUSED's host: the DNS-only record adds nothing a
    // reader could not already tell from the request row.
    const dns = [
      "2026-08-23 16:45:00.000000000  [INFO] buildcage dns denied name=evil.example.com.",
    ];
    const r = await buildInspectReportData([START, REFUSED], dns, reportParams());
    expect(r.blocked.length).toBe(1);
    expect(r.blocked[0].ruleType).toBe("HTTPS");
    // The raw timeline is untouched: only the host tables collapse it.
    expect(r.timeline.some((e) => e.protocol === "dns")).toBe(true);
  });

  it("keeps a blocked DNS row when the name was never actually requested", async () => {
    const dns = [
      "2026-08-23 16:45:00.000000000  [INFO] buildcage dns denied name=secret-in-a-name.attacker.example.",
    ];
    const r = await buildInspectReportData([START], dns, reportParams());
    expect(r.blocked.length).toBe(1);
    expect(r.blocked[0].ruleType).toBe("DNS");
  });

  it("gives a passthrough the rule kind that would permit it", async () => {
    const r = await buildInspectReportData([START, TLS_PASS], [], reportParams());
    expect(r.passed[0].ruleType).toBe("TLS");
    expect(r.passed[0].host).toBe("db.example.com");
    expect(r.passed[0].port).toBe("5432");
  });

  it("does not count an origin's own 403 as blocked", async () => {
    // fail_on_blocked defaults to true, so a registry answering 403 to an
    // unauthenticated fetch would otherwise fail a build that was not blocked.
    const relayed =
      "buildcage 3 https GET 403 90 ts=-- reason=- dst=1.1.1.1:443 https://reg.example.com/pkg";
    const r = await buildInspectReportData([START, relayed], [], reportParams());
    expect(r.blockedCount).toBe(0);
  });

  it("counts every blocked event, not just the distinct hosts", async () => {
    const r = await buildInspectReportData([START, REFUSED, REFUSED], [], reportParams());
    expect(r.blocked.length).toBe(1);
    expect(r.blockedCount).toBe(2);
  });

  it("reports a name the resolver refused, which never reached the proxy", async () => {
    // Otherwise exfiltration through the query alone would leave no trace.
    const dns = [
      "2026-08-23 16:45:00.000000000  [INFO] buildcage dns denied name=SECRET.att.example.",
    ];
    const r = await buildInspectReportData([START], dns, reportParams());
    expect(r.blocked[0].ruleType).toBe("DNS");
    expect(r.blocked[0].reason).toBe("dns-not-allowed");
    expect(r.blockedCount).toBe(1);
  });

  it("keeps a resolved name out of the host tables", async () => {
    // The request that followed is already a row; listing both doubles it.
    const dns = [
      "2026-08-23 16:45:00.000000000  [INFO] buildcage dns allowed name=registry.npmjs.org.",
    ];
    const r = await buildInspectReportData([START, ALLOWED], dns, reportParams());
    expect(r.passed.length).toBe(1);
    // It is still in the timeline, which the job output is built from.
    expect(r.timeline.filter((e) => e.protocol === "dns").length).toBe(1);
  });

  it("keeps a discovery lookup out of both tables and out of blockedCount", async () => {
    // apt asks for this on every repository it fetches from and falls through
    // to the plain name, so counting it as blocked would fail a build that
    // worked, over a row no rule could take away.
    const dns = [
      "2026-08-23 16:45:00.000000000  [INFO] buildcage dns discovery name=_http._tcp.deb.debian.org. type=SRV",
    ];
    const r = await buildInspectReportData([START], dns, reportParams());
    expect(r.blocked.length).toBe(0);
    expect(r.blockedCount).toBe(0);
    expect(r.passed.length).toBe(0);
    // Recorded, not hidden: the details section reads the timeline.
    expect(r.timeline.length).toBe(1);
    expect(r.timeline[0].action).toBe("discovery");
    expect(r.timeline[0].queryType).toBe("SRV");
  });

  it("keeps a name that resolved and was never connected to", async () => {
    // The only evidence that a rule covers more than the build used.
    const dns = [
      "2026-08-23 16:45:00.000000000  [INFO] buildcage dns allowed name=unused.example.com.",
    ];
    const r = await buildInspectReportData([START, ALLOWED], dns, reportParams());
    expect(r.passed.some((row) => row.host === "unused.example.com")).toBe(true);
    expect(r.blocked.length).toBe(0);
  });

  it("keeps an audited name that was never connected to in audit mode", async () => {
    const dns = [
      "2026-08-23 16:45:00.000000000  [INFO] buildcage dns allowed name=looked-up.example.com.",
    ];
    const r = await buildInspectReportData([START], dns, reportParams({ mode: "audit" }));
    expect(r.passed.length).toBe(1);
    expect(r.passed[0].host).toBe("looked-up.example.com");
    expect(r.passed[0].ruleType).toBe("DNS");
  });

  it("says a refused service name takes a different remedy from an ordinary one", async () => {
    // Naming the service name in a rule silences the row without making the
    // record resolve. The host below it is what a rule is written against, so
    // the row has to say which kind of name it is.
    const dns = [
      "2026-08-23 16:45:00.000000000  [INFO] buildcage dns service-denied name=_mongodb._tcp.c0.example.net. type=SRV",
      "2026-08-23 16:45:01.000000000  [INFO] buildcage dns denied name=evil.example.com.",
    ];
    const r = await buildInspectReportData([START], dns, reportParams());
    const service = r.blocked.find((row) => row.host.startsWith("_mongodb"));
    const plain = r.blocked.find((row) => row.host === "evil.example.com");
    expect(service?.reason).toBe("dns-service-not-allowed");
    expect(plain?.reason).toBe("dns-not-allowed");
  });

  it("keeps a refused service name silenceable by known_blocked_rules", async () => {
    // Neither remedy makes the record resolve; this is the one that leaves the
    // rules alone, so it has to keep working on a name with no port.
    const dns = [
      "2026-08-23 16:45:00.000000000  [INFO] buildcage dns service-denied name=_mongodb._tcp.c0.example.net. type=SRV",
    ];
    const r = await buildInspectReportData(
      [START],
      dns,
      reportParams({ knownBlockedRules: ["_mongodb._tcp.c0.example.net:*"] }),
    );
    expect(r.blocked[0].expected).toBe(true);
  });

  it("lets a refused name be declared expected", async () => {
    // The row has no port, so without special handling no writable rule could
    // ever match it and fail_on_blocked would fail the job with no way out.
    const dns = [
      "2026-08-23 16:45:00.000000000  [INFO] buildcage dns denied name=telemetry.example.com.",
    ];
    const r = await buildInspectReportData(
      [START],
      dns,
      reportParams({ knownBlockedRules: ["telemetry.example.com:*"] }),
    );
    expect(r.blocked[0].expected).toBe(true);
  });

  it("marks everything as audited when nothing was being enforced", async () => {
    const r = await buildInspectReportData([START, ALLOWED], [], reportParams({ mode: "audit" }));
    expect(r.timeline[0].action).toBe("audit");
  });

  it("fails closed on a log with no startup marker", async () => {
    // An empty log means either "saw nothing" or "never ran"; only the marker
    // tells them apart, and reporting "nothing was blocked" for a proxy that
    // never started would be the dangerous reading.
    const missing = await buildInspectReportData([], [DNS_START], reportParams());
    expect(missing.logLooksPlausible).toBe(false);
    expect(missing.startedAt === undefined).toBe(true);

    const present = await buildInspectReportData([START], [DNS_START], reportParams());
    expect(present.logLooksPlausible).toBe(true);
    expect(present.startedAt).toBe(1787471970);
  });

  it("fails closed when a restart's marker is all that is left of the proxy log", async () => {
    // startedAt still reads from the second marker, so only the head check
    // notices the beginning is gone.
    const r = await buildInspectReportData([ALLOWED, START], [DNS_START], reportParams());
    expect(r.startedAt).toBe(1787471970);
    expect(r.logLooksPlausible).toBe(false);
  });

  it("fails closed on a proxy line it cannot read, wherever the log begins", async () => {
    // What survived says nothing about what the rest of the line said.
    const unreadable = REFUSED.slice(0, 40);
    const r = await buildInspectReportData(
      [START, ALLOWED, unreadable],
      [DNS_START],
      reportParams(),
    );
    expect(r.logLooksPlausible).toBe(false);
    expect(r.passed.length).toBe(1);
  });

  it("fails closed when the resolver log lost its beginning, even with the proxy log whole", async () => {
    // A refused name reaches no proxy, so the resolver log is its only trace.
    const dns = [
      "2026-08-23 16:45:00.000000000  [INFO] buildcage dns allowed name=ok.example.com.",
    ];
    const r = await buildInspectReportData([START], dns, reportParams());
    expect(r.startedAt).toBe(1787471970);
    expect(r.logLooksPlausible).toBe(false);
  });
});
