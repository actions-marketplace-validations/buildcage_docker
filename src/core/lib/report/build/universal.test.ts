import { describe, it, expect } from "vitest";
import { buildUniversalReportData } from "./universal.ts";
import { reportParams } from "#core/lib/test/report-data.node.ts";

describe("buildUniversalReportData", () => {
  it("aggregates allowed/blocked in restrict mode", async () => {
    const log = [
      '[2024-01-01T00:00:00] buildcage [ALLOWED] (HTTPS) "good.com:443" -',
      '[2024-01-01T00:00:00] buildcage [BLOCKED] (HTTP) "bad.com:80" not-allowed',
    ].join("\n");
    const result = await buildUniversalReportData(log.split("\n"), reportParams());
    expect(result.engine).toBe("universal");
    expect(result.passed.length).toBe(1);
    expect(result.passed[0].host).toBe("good.com");
    expect(result.blocked.length).toBe(1);
    expect(result.blocked[0].host).toBe("bad.com");
    expect(result.blockedCount).toBe(1);
  });

  it("aggregates audited traffic in audit mode instead of allowed", async () => {
    const log = '[2024-01-01T00:00:00] buildcage [AUDIT] (HTTPS) "any.com:443"';
    const result = await buildUniversalReportData(log.split("\n"), reportParams({ mode: "audit" }));
    expect(result.passed.length).toBe(1);
    expect(result.passed[0].host).toBe("any.com");
  });

  it("annotates blocked rows against knownBlockedRules", async () => {
    const log =
      '[2024-01-01T00:00:00] buildcage [BLOCKED] (HTTPS) "noisy.example.com:443" not-allowed';
    const result = await buildUniversalReportData(
      log.split("\n"),
      reportParams({ knownBlockedRules: ["noisy.example.com:443"] }),
    );
    expect(result.blocked[0].expected).toBe(true);
  });

  it("returns empty passed/blocked and blockedCount 0 for empty log text", async () => {
    const result = await buildUniversalReportData("".split("\n"), reportParams());
    expect(result.passed).toStrictEqual([]);
    expect(result.blocked).toStrictEqual([]);
    expect(result.blockedCount).toBe(0);
    expect(result.logLooksPlausible).toBe(false);
  });

  it("logLooksPlausible is true for a genuinely quiet run (the startup marker, zero blocked)", async () => {
    const log = [
      "buildcage haproxy starting",
      '[2024-01-01T00:00:00] buildcage [ALLOWED] (HTTPS) "good.com:443" -',
    ].join("\n");
    const result = await buildUniversalReportData(log.split("\n"), reportParams());
    expect(result.blockedCount).toBe(0);
    expect(result.logLooksPlausible).toBe(true);
  });

  it("logLooksPlausible is false when a decision line could not be read", async () => {
    const log = [
      "buildcage haproxy starting",
      '[2024-01-01T00:00:00] buildcage [BLOCKED] (HTTPS) "bad.com:4',
    ].join("\n");
    const result = await buildUniversalReportData(log.split("\n"), reportParams());
    expect(result.blockedCount).toBe(0);
    expect(result.logLooksPlausible).toBe(false);
  });

  it("blockedCount counts raw events, not aggregated rows", async () => {
    const log = [
      '[2024-01-01T00:00:00] buildcage [BLOCKED] (HTTPS) "bad.com:443" not-allowed',
      '[2024-01-01T00:00:01] buildcage [BLOCKED] (HTTPS) "bad.com:443" not-allowed',
    ].join("\n");
    const result = await buildUniversalReportData(log.split("\n"), reportParams());
    expect(result.blockedCount).toBe(2);
    expect(result.blocked.length).toBe(1);
    expect(result.blocked[0].count).toBe(2);
  });

  it("logLooksPlausible is false when the log's oldest segments are gone", async () => {
    // Rotation drops the startup marker first, then the earliest decisions.
    const log = [
      '[2024-01-01T00:00:00] buildcage [ALLOWED] (HTTPS) "flood.com:443" -',
      '[2024-01-01T00:00:01] buildcage [BLOCKED] (HTTPS) "noisy.example.com:443" not-allowed',
    ].join("\n");
    const result = await buildUniversalReportData(
      log.split("\n"),
      reportParams({ knownBlockedRules: ["noisy.example.com:443"] }),
    );
    expect(result.blockedCount).toBe(1);
    expect(result.blocked[0].expected).toBe(true);
    expect(result.logLooksPlausible).toBe(false);
  });
});
