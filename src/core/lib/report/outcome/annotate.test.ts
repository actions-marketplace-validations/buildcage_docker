import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { applyOutcomeAnnotation, type OutcomeEmission } from "./annotate.ts";
import type { Annotation } from "#core/lib/actions/annotation.ts";

function recorder(): { annotation: Annotation; calls: [keyof Annotation, string][] } {
  const calls: [keyof Annotation, string][] = [];
  return {
    calls,
    annotation: {
      notice: (m) => calls.push(["notice", m]),
      warning: (m) => calls.push(["warning", m]),
      error: (m) => calls.push(["error", m]),
    },
  };
}

function emission(overrides: Partial<OutcomeEmission> = {}): OutcomeEmission {
  return { level: "none", message: "outcome", shouldFail: false, ...overrides };
}

describe("applyOutcomeAnnotation", () => {
  // This is the one function under test that writes to global process state,
  // and vitest reads the same field to decide the run's own exit code.
  let previousExitCode: typeof process.exitCode;

  beforeEach(() => {
    previousExitCode = process.exitCode;
  });

  afterEach(() => {
    process.exitCode = previousExitCode;
  });

  it("emits an error annotation for level error", () => {
    const { annotation, calls } = recorder();
    applyOutcomeAnnotation(annotation, emission({ level: "error", message: "blocked" }));
    expect(calls).toStrictEqual([["error", "blocked"]]);
  });

  it("emits a notice annotation for level notice", () => {
    const { annotation, calls } = recorder();
    applyOutcomeAnnotation(annotation, emission({ level: "notice", message: "audited" }));
    expect(calls).toStrictEqual([["notice", "audited"]]);
  });

  it("emits nothing for level none", () => {
    const { annotation, calls } = recorder();
    applyOutcomeAnnotation(annotation, emission({ level: "none" }));
    expect(calls).toStrictEqual([]);
  });

  it("fails the step when shouldFail is set", () => {
    const { annotation } = recorder();
    process.exitCode = 0;
    applyOutcomeAnnotation(annotation, emission({ level: "error", shouldFail: true }));
    expect(process.exitCode).toBe(1);
  });

  it("leaves the exit code alone when shouldFail is not set", () => {
    const { annotation } = recorder();
    process.exitCode = 0;
    applyOutcomeAnnotation(annotation, emission({ level: "error", shouldFail: false }));
    expect(process.exitCode).toBe(0);
  });

  it("fails the step even when there is no annotation to emit", () => {
    const { annotation, calls } = recorder();
    process.exitCode = 0;
    applyOutcomeAnnotation(annotation, emission({ level: "none", shouldFail: true }));
    expect(calls).toStrictEqual([]);
    expect(process.exitCode).toBe(1);
  });
});
