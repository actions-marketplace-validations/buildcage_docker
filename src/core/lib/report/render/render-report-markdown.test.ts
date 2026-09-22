import { describe, it, expect } from "vitest";
import { renderReportMarkdown } from "./render-report-markdown.ts";
import type { UniversalReportData, InspectReportData } from "../types.ts";
import type { TrafficEvent } from "#core/lib/log/traffic-event.ts";
import { reportParams, expectedRows } from "#core/lib/test/report-data.node.ts";

const allowedRow = { host: "good.com", port: "443", ruleType: "HTTPS", reason: "-", count: 1 };
const blockedRow = {
  host: "bad.com",
  port: "80",
  ruleType: "HTTP",
  reason: "not-allowed",
  count: 1,
  expected: false,
};

describe("renderReportMarkdown: universal", () => {
  const base: UniversalReportData = {
    engine: "universal",
    parameters: reportParams(),
    passed: [],
    blocked: [],
    failed: [],
    blockedCount: 0,
    logLooksPlausible: true,
    timeline: [],
    startedAt: undefined,
  };

  it("renders a bare restrict-mode title, since that is the day-to-day mode", () => {
    const md = renderReportMarkdown({ ...base, passed: [allowedRow] }, "buildcage/docker", "v2");
    expect(md).toMatch(/^## Outbound Traffic Report\n/);
    expect(md).not.toMatch(/restrict mode\)/);
    expect(md).toMatch(/### ✅ Allowed Hosts/);
    expect(md).toMatch(/good\.com/);
  });

  it("warns above the tables when the log is not a complete record", () => {
    const md = renderReportMarkdown(
      { ...base, passed: [allowedRow], logLooksPlausible: false },
      "buildcage/docker",
      "v2",
    );
    expect(md).toMatch(/This report is incomplete/);
    expect(md.indexOf("incomplete") < md.indexOf("Allowed Hosts")).toBe(true);
    const [warning] = md.split("\n\n").filter((b) => b.includes("This report is incomplete"));
    // A continuation line without the marker leaves the blockquote and renders
    // as body text, which the "incomplete" match above would not catch.
    expect(warning.split("\n").every((line) => line.startsWith("> "))).toBe(true);
    expect(warning.replaceAll("\n> ", " ")).toMatch(
      /Either the logs don't begin where a real run does, or one carries a line that cannot be read\./,
    );
  });

  it("has no warning when the log is a complete record", () => {
    const md = renderReportMarkdown({ ...base, passed: [allowedRow] }, "buildcage/docker", "v2");
    expect(md).not.toMatch(/incomplete/);
  });

  it("renders the audit-mode heading and Audited Hosts table, plus a restrict-mode example", () => {
    const md = renderReportMarkdown(
      { ...base, parameters: reportParams({ mode: "audit" }), passed: [allowedRow] },
      "buildcage/docker",
      "v2",
    );
    expect(md).toMatch(/^## Outbound Traffic Report \(audit mode\)\n/);
    expect(md).toMatch(/### 📋 Audited Hosts/);
    expect(md).toMatch(/Switch to restrict mode/);
  });

  it("renders Blocked Hosts and shows the SNI footnote, not Communication details", () => {
    const md = renderReportMarkdown(
      { ...base, blocked: [blockedRow], blockedCount: 1 },
      "buildcage/docker",
      "v2",
    );
    expect(md).toMatch(/### 🚫 Blocked Hosts/);
    expect(md).toMatch(/based on the Host header/);
    expect(md).not.toMatch(/Communication details/);
  });

  it("uses the real actionRepo in the footer, not a placeholder", () => {
    const md = renderReportMarkdown(base, "buildcage/docker", "v2");
    expect(md).toMatch(
      /Reported by \[buildcage\/docker\]\(https:\/\/github\.com\/buildcage\/docker\)/,
    );
    expect(md).not.toMatch(/GITHUB_ACTION_REPOSITORY/);
  });

  it("omits the Allowed Hosts table entirely when nothing passed", () => {
    const md = renderReportMarkdown(base, "buildcage/docker", "v2");
    expect(md).not.toMatch(/### ✅ Allowed Hosts/);
  });

  it("shows a '(no communication)' note when nothing passed and nothing blocked", () => {
    const md = renderReportMarkdown(base, "buildcage/docker", "v2");
    expect(md).toMatch(/_\(no communication\)_/);
  });

  it("omits the '(no communication)' note once anything passed or was blocked", () => {
    const passedMd = renderReportMarkdown(
      { ...base, passed: [allowedRow] },
      "buildcage/docker",
      "v2",
    );
    expect(passedMd).not.toMatch(/_\(no communication\)_/);

    const blockedMd = renderReportMarkdown(
      { ...base, blocked: [blockedRow], blockedCount: 1 },
      "buildcage/docker",
      "v2",
    );
    expect(blockedMd).not.toMatch(/_\(no communication\)_/);
  });

  it("omits the '(no communication)' note for a build that only looked names up", () => {
    const discovery: TrafficEvent = {
      time: 1,
      action: "discovery",
      protocol: "dns",
      host: "_http._tcp.example.com",
      queryType: "SRV",
    };
    const md = renderReportMarkdown({ ...base, timeline: [discovery] }, "buildcage/docker", "v2");
    expect(md).not.toMatch(/_\(no communication\)_/);
    expect(md).toMatch(/Communication details/);
  });

  it("uses the title option verbatim, e.g. a run step's em-dash label", () => {
    const md = renderReportMarkdown(base, "buildcage/docker", "v2", {
      title: "Outbound Traffic Report — npm install",
    });
    expect(md).toMatch(/^## Outbound Traffic Report — npm install\n/);
  });

  it("adds an Expected column marking known_blocked_rules matches when set", () => {
    const md = renderReportMarkdown(
      {
        ...base,
        parameters: reportParams({ knownBlockedRules: ["bad.com:80"] }),
        blocked: [blockedRow],
      },
      "buildcage/docker",
      "v2",
    );
    expect(md).toMatch(/\| Host \| Rule \| Reason \| Count \| Expected \|/);
  });

  it("omits the Expected column when known_blocked_rules is not set", () => {
    const md = renderReportMarkdown({ ...base, blocked: [blockedRow] }, "buildcage/docker", "v2");
    expect(md).not.toMatch(/Expected/);
  });

  it("folds the rows one known_blocked_rule matched into a single row naming the rule", () => {
    const md = renderReportMarkdown(
      {
        ...base,
        parameters: reportParams({ knownBlockedRules: ["*.sury.org:*"] }),
        blocked: expectedRows,
      },
      "buildcage/docker",
      "v2",
    );
    expect(md).toMatch(/\(2 hosts\)/);
    expect(md).not.toMatch(/\| a\.sury\.org:443 \|/);
  });
});

describe("renderReportMarkdown: inspect", () => {
  const request: TrafficEvent = {
    time: 1787471975,
    action: "allow",
    protocol: "https",
    host: "good.com",
    port: 443,
    method: "GET",
    url: "https://good.com/pkg",
    status: 200,
    bytes: 12,
  } as TrafficEvent;

  const base: InspectReportData = {
    engine: "inspect",
    parameters: reportParams(),
    passed: [],
    blocked: [],
    failed: [],
    blockedCount: 0,
    logLooksPlausible: true,
    timeline: [request],
    startedAt: 1787471970,
  };

  it("renders the per-request details the other engines have no data for", () => {
    const md = renderReportMarkdown(base, "buildcage/docker", "v2");
    expect(md).toMatch(/good\.com/);
    expect(md).toMatch(/GET/);
  });

  it("builds the audit example from the requests rather than from the hosts", () => {
    const md = renderReportMarkdown(
      { ...base, parameters: reportParams({ mode: "audit" }) },
      "buildcage/docker",
      "v2",
    );
    expect(md).toMatch(/allowed_url_rules|GET https:\/\/good\.com/);
  });

  const failedRow = {
    host: "good.com",
    port: "443",
    ruleType: "HTTPS",
    reason: "origin-no-response",
    count: 1,
  };

  it("tables connections the origin broke under their own heading", () => {
    const md = renderReportMarkdown({ ...base, failed: [failedRow] }, "buildcage/docker", "v2");
    expect(md).toMatch(/### ⚠️ Failed Connections\n/);
    expect(md).toMatch(/origin-no-response/);
    // The reader is told why the step passed regardless.
    expect(md).toMatch(/none of them fails the step/);
  });

  it("does not call a run that only failed connections no communication", () => {
    const md = renderReportMarkdown({ ...base, failed: [failedRow] }, "buildcage/docker", "v2");
    expect(md.includes("_(no communication)_")).toBe(false);
  });
});
