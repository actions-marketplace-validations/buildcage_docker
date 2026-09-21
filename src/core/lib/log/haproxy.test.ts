import { describe, it, expect } from "vitest";
import { scanHaproxyLog } from "./haproxy.ts";

describe("scanHaproxyLog", () => {
  it("aggregates an ALLOWED log line as passed when isAudit is false", async () => {
    const log = '[2024-01-01T00:00:00] buildcage [ALLOWED] (HTTPS) "example.com:443" rule1';
    const result = await scanHaproxyLog(log.split("\n"), false);
    expect(result.passed.length).toBe(1);
    expect(result.passed[0].ruleType).toBe("HTTPS");
    expect(result.passed[0].host).toBe("example.com");
    expect(result.passed[0].port).toBe("443");
    expect(result.passed[0].reason).toBe("rule1");
    expect(result.blocked.length).toBe(0);
  });

  it("aggregates a BLOCKED log line regardless of isAudit", async () => {
    const log = '[2024-01-01T00:00:00] buildcage [BLOCKED] (HTTP) "bad.com:80" not-allowed';
    const result = await scanHaproxyLog(log.split("\n"), false);
    expect(result.blocked.length).toBe(1);
    expect(result.blocked[0].reason).toBe("not-allowed");
    expect(result.blockedCount).toBe(1);
  });

  it("tables a name the upstream resolver could not answer as failed, not blocked", async () => {
    const log = '[2024-01-01T00:00:00] buildcage [BLOCKED] (HTTPS) "absent.com:443" dns-failed';
    const result = await scanHaproxyLog(log.split("\n"), false);
    expect(result.failed.map((row) => row.host)).toStrictEqual(["absent.com"]);
    expect(result.blocked.length).toBe(0);
    expect(result.blockedCount).toBe(0);
  });

  it("aggregates an AUDIT log line as passed when isAudit is true", async () => {
    const log = '[2024-01-01T00:00:00] buildcage [AUDIT] (HTTPS) "any.com:443"';
    const result = await scanHaproxyLog(log.split("\n"), true);
    expect(result.passed.length).toBe(1);
    expect(result.passed[0].reason).toBe("-");
  });

  it("drops an ALLOWED line when isAudit is true (not the decision this mode aggregates)", async () => {
    const log = '[2024-01-01T00:00:00] buildcage [ALLOWED] (HTTPS) "example.com:443" rule1';
    const result = await scanHaproxyLog(log.split("\n"), true);
    expect(result.passed.length).toBe(0);
  });

  it("drops an AUDIT line when isAudit is false (not the decision this mode aggregates)", async () => {
    const log = '[2024-01-01T00:00:00] buildcage [AUDIT] (HTTPS) "any.com:443"';
    const result = await scanHaproxyLog(log.split("\n"), false);
    expect(result.passed.length).toBe(0);
  });

  it("ignores non-matching lines without counting them anywhere", async () => {
    const log = "some random log line\n[2024-01-01] other stuff";
    const result = await scanHaproxyLog(log.split("\n"), false);
    expect(result.passed.length).toBe(0);
    expect(result.blocked.length).toBe(0);
    // Neither line claims to be a decision of ours, so neither is a gap.
    expect(result.unparsed).toBe(0);
  });

  it("counts a decision line it cannot read, since it may have been a refusal", async () => {
    // What a half-written write leaves: the next line joined onto it.
    const log = [
      '[2024-01-01T00:00:00] buildcage [ALLOWED] (HTTPS) "example.com:443" rule1',
      '[2024-01-01T00:00:01] buildcage [BLOCKED] (HTTPS) "bad.com:4[2024-01-01T00:00:02] buildcage [BLOCKED] (HTTPS) "worse.com:443" not-allowed',
      "buildcage haproxy starting 1787471970000",
    ].join("\n");
    const result = await scanHaproxyLog(log.split("\n"), false);
    expect(result.passed.length).toBe(1);
    expect(result.blocked.length).toBe(0);
    expect(result.unparsed).toBe(1);
  });

  it("aggregates repeated BLOCKED lines into one row, but keeps blockedCount raw", async () => {
    const log = [
      '[2024-01-01T00:00:00] buildcage [BLOCKED] (HTTPS) "bad.com:443" not-allowed',
      '[2024-01-01T00:00:01] buildcage [BLOCKED] (HTTPS) "bad.com:443" not-allowed',
    ].join("\n");
    const result = await scanHaproxyLog(log.split("\n"), false);
    expect(result.blocked.length).toBe(1);
    expect(result.blocked[0].count).toBe(2);
    expect(result.blockedCount).toBe(2);
  });

  it("keeps passed/blocked buckets independent across mixed lines", async () => {
    const log = [
      '[2024-01-01T00:00:00] buildcage [ALLOWED] (HTTPS) "a.com:443" r1',
      '[2024-01-01T00:00:01] buildcage [BLOCKED] (HTTP) "b.com:80" not-allowed',
      "not a log line",
      '[2024-01-01T00:00:02] buildcage [ALLOWED] (HTTPS) "a.com:443" r1',
    ].join("\n");
    const result = await scanHaproxyLog(log.split("\n"), false);
    expect(result.passed.length).toBe(1);
    expect(result.passed[0].count).toBe(2);
    expect(result.blocked.length).toBe(1);
    expect(result.blockedCount).toBe(1);
  });

  it("accepts a real AsyncIterable, not just an array", async () => {
    async function* lines(): AsyncGenerator<string> {
      yield '[2024-01-01T00:00:00] buildcage [ALLOWED] (HTTPS) "async.com:443" r1';
    }
    const result = await scanHaproxyLog(lines(), false);
    expect(result.passed.length).toBe(1);
    expect(result.passed[0].host).toBe("async.com");
  });

  it("headIntact is false for empty log text", async () => {
    const result = await scanHaproxyLog("".split("\n"), false);
    expect(result.headIntact).toBe(false);
  });

  it("headIntact is false when the log has only buildcage-decision lines", async () => {
    const log = [
      '[2024-01-01T00:00:00] buildcage [ALLOWED] (HTTPS) "a.com:443" r1',
      '[2024-01-01T00:00:01] buildcage [BLOCKED] (HTTP) "b.com:80" not-allowed',
    ].join("\n");
    const result = await scanHaproxyLog(log.split("\n"), false);
    expect(result.headIntact).toBe(false);
  });

  it("headIntact is true when the log opens with the startup marker", async () => {
    const log = [
      "buildcage haproxy starting",
      "[NOTICE]   (1) : haproxy version is 2.9.0",
      '[2024-01-01T00:00:00] buildcage [ALLOWED] (HTTPS) "a.com:443" r1',
    ].join("\n");
    const result = await scanHaproxyLog(log.split("\n"), false);
    expect(result.headIntact).toBe(true);
  });

  it("headIntact is false when HAProxy's own output stands where the marker should be", async () => {
    // A flood provokes these, so one must not pass for a head that rotated away.
    const log = [
      "[ALERT]    (1) : proxy outbound_proxy reached process FD limit",
      '[2024-01-01T00:00:00] buildcage [BLOCKED] (HTTPS) "b.com:443" not-allowed',
    ].join("\n");
    const result = await scanHaproxyLog(log.split("\n"), false);
    expect(result.headIntact).toBe(false);
  });

  it("headIntact is true for a zero-traffic run thanks to the guaranteed startup marker", async () => {
    // See docker/universal/files/s6-rc.d/haproxy/run
    const result = await scanHaproxyLog(["buildcage haproxy starting"], false);
    expect(result.headIntact).toBe(true);
    expect(result.blockedCount).toBe(0);
  });

  it("headIntact ignores blank lines when deciding", async () => {
    const result = await scanHaproxyLog("\n\n  \n".split("\n"), false);
    expect(result.headIntact).toBe(false);
  });

  it("headIntact ignores the marker if it is not the first line", async () => {
    // A later copy vouches for nothing: the part before it is still gone.
    const log = [
      '[2024-01-01T00:00:00] buildcage [ALLOWED] (HTTPS) "a.com:443" r1',
      "buildcage haproxy starting",
      '[2024-01-01T00:00:01] buildcage [BLOCKED] (HTTPS) "b.com:443" not-allowed',
    ].join("\n");
    const result = await scanHaproxyLog(log.split("\n"), false);
    expect(result.headIntact).toBe(false);
    expect(result.blockedCount).toBe(1);
  });

  // ---------------------------------------------------------------------
  // Log injection via an unsanitized target/reason
  // ---------------------------------------------------------------------
  it("refuses a line carrying anything after the fields it expects", async () => {
    const quoted =
      '[2024-01-01T00:00:00] buildcage [ALLOWED] (HTTPS) "evil"] buildcage [ALLOWED] (HTTPS) "a.com:443" r1';
    expect((await scanHaproxyLog(quoted.split("\n"), false)).passed.length).toBe(0);

    const appended =
      '[2024-01-01T00:00:00] buildcage [ALLOWED] (HTTPS) "a.com:443" r1 [2024-01-01T00:00:01] buildcage [BLOCKED] (HTTPS) "hidden.com:443" not-allowed';
    const result = await scanHaproxyLog(appended.split("\n"), false);
    expect(result.passed.length).toBe(0);
    expect(result.blocked.length).toBe(0);
  });
});

describe("a host logged without a port", () => {
  it("reads the whole field as the host and reports port 0", async () => {
    const log = '[2024-01-01T00:00:00] buildcage [BLOCKED] (DNS) "a.example.com" dns-not-allowed';
    const result = await scanHaproxyLog(log.split("\n"), false);
    expect(result.blocked[0].host).toBe("a.example.com");
    expect(result.blocked[0].port).toBe("0");
  });
});
