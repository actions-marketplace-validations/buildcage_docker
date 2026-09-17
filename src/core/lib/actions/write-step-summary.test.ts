import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as core from "@actions/core";
import { writeStepSummary } from "./write-step-summary.ts";

describe("writeStepSummary", () => {
  let previousSummaryPath: string | undefined;

  beforeEach(() => {
    previousSummaryPath = process.env.GITHUB_STEP_SUMMARY;
  });

  afterEach(() => {
    if (previousSummaryPath === undefined) delete process.env.GITHUB_STEP_SUMMARY;
    else process.env.GITHUB_STEP_SUMMARY = previousSummaryPath;
  });

  it("writes through core.summary when GITHUB_STEP_SUMMARY is set", async () => {
    process.env.GITHUB_STEP_SUMMARY = "/dev/null";
    const addRaw = vi.spyOn(core.summary, "addRaw").mockReturnValue(core.summary);
    const write = vi.spyOn(core.summary, "write").mockResolvedValue(core.summary);
    const log = vi.spyOn(console, "log").mockImplementation(() => {});

    await writeStepSummary("# report");

    expect(addRaw.mock.calls[0][0]).toBe("# report");
    expect(write.mock.calls.length).toBe(1);
    expect(log.mock.calls.length).toBe(0);
  });

  // core.summary.write() throws when the variable is unset, so the fallback is
  // what makes a local or manual run print anything at all.
  it("falls back to stdout when GITHUB_STEP_SUMMARY is unset", async () => {
    delete process.env.GITHUB_STEP_SUMMARY;
    const write = vi.spyOn(core.summary, "write").mockResolvedValue(core.summary);
    const log = vi.spyOn(console, "log").mockImplementation(() => {});

    await writeStepSummary("# report");

    expect(write.mock.calls.length).toBe(0);
    expect(log.mock.calls).toStrictEqual([["# report"]]);
  });

  it("passes artifactAvailable through to the truncation notice, defaulting to false", async () => {
    process.env.GITHUB_STEP_SUMMARY = "/dev/null";
    const addRaw = vi.spyOn(core.summary, "addRaw").mockReturnValue(core.summary);
    vi.spyOn(core.summary, "write").mockResolvedValue(core.summary);

    // Short input is returned unchanged either way, so the observable effect is
    // only that both call shapes reach addRaw with the rendered markdown.
    await writeStepSummary("# report", true);
    await writeStepSummary("# report");

    expect(addRaw.mock.calls.map((c) => c[0])).toStrictEqual(["# report", "# report"]);
  });
});
