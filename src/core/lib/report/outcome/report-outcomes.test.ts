import { describe, it, expect } from "vitest";

import { describeReportOutcomes } from "./report-outcomes.ts";
import { reportParams } from "#core/lib/test/report-data.node.ts";
import type { TrafficEvent } from "#core/lib/log/traffic-event.ts";
import type { InspectReportData, UniversalReportData } from "../types.ts";

function universal(overrides: Partial<UniversalReportData> = {}): UniversalReportData {
  return {
    engine: "universal",
    parameters: reportParams(),
    passed: [],
    blocked: [],
    blockedCount: 0,
    logLooksPlausible: true,
    ...overrides,
  };
}

function inspect(timeline: TrafficEvent[]): InspectReportData {
  return {
    engine: "inspect",
    parameters: reportParams(),
    passed: [],
    blocked: [],
    blockedCount: 0,
    logLooksPlausible: true,
    startedAt: 1787471970,
    timeline,
  };
}

const incomplete: TrafficEvent = {
  time: 1787471975,
  action: "incomplete",
  protocol: "http",
  host: "(unknown)",
  port: 8080,
  reason: "bad-request",
  destination: "172.20.0.1:8080",
};

// The blocked decision itself is blocked-outcome.ts's, tested there. What is
// left here is which emissions a report produces and in what order.
describe("describeReportOutcomes", () => {
  const options = { failOnBlocked: true, engineLabel: "proxy" } as const;

  it("always opens with the blocked-connections check, silent though it is here", () => {
    const [blocked, ...rest] = describeReportOutcomes(universal(), options);
    expect(blocked.level).toBe("none");
    expect(blocked.shouldFail).toBe(false);
    expect(rest).toStrictEqual([]);
  });

  it("says nothing more for an engine that reports no timeline", () => {
    expect(describeReportOutcomes(universal({ blockedCount: 1 }), options).length).toBe(1);
  });

  it("says nothing more for a timeline every rule could decide", () => {
    const timeline: TrafficEvent[] = [
      { time: 1787471975, action: "allow", protocol: "https", host: "a.example.com", port: 443 },
    ];
    expect(describeReportOutcomes(inspect(timeline), options).length).toBe(1);
  });

  it("warns about requests no rule decided, counting each one", () => {
    const outcomes = describeReportOutcomes(inspect([incomplete, incomplete]), options);
    expect(outcomes.length).toBe(2);
    expect(outcomes[1].level).toBe("warning");
    expect(outcomes[1].message.startsWith("2 request(s) buildcage proxy could not act on")).toBe(
      true,
    );
  });

  it("never fails the step over one: no rule refused it and none can clear it", () => {
    const outcomes = describeReportOutcomes(inspect([incomplete]), options);
    expect(outcomes.every((outcome) => !outcome.shouldFail)).toBe(true);
  });

  it("names the action reporting, as the blocked message does", () => {
    const [, warning] = describeReportOutcomes(inspect([incomplete]), {
      failOnBlocked: false,
      engineLabel: "sandbox",
    });
    expect(warning.message.includes("buildcage sandbox")).toBe(true);
  });

  it("avoids the word the report already uses for a log that lost its beginning", () => {
    const [, warning] = describeReportOutcomes(inspect([incomplete]), options);
    expect(warning.message.includes("incomplete")).toBe(false);
  });
});
