/**
 * Unit tests for report-step.ts
 *
 * Run with: vp test run report/src/lib/report-step.test.ts
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

import { runReportStep, type ReportStepDeps } from "./report-step.ts";
import { REPORT_ACTION_SCRIPT_PATH } from "#core/lib/docker/report-source.ts";
import { ReportError } from "./errors.ts";

// Every collaborator is tested in its own file; what is left to check here is
// the order they run in, what each one is handed, and which of them still run
// when an earlier step fails.
const mocks = {
  readBuilderName: vi.fn(),
  readTrafficArtifactInputs: vi.fn(),
  createDocker: vi.fn(),
  findReportSourceContainer: vi.fn(),
  copyFromContainerImage: vi.fn(),
  runReportScript: vi.fn(),
  uploadTrafficArtifact: vi.fn(),
  makeScratchDir: vi.fn(),
  removeScratchDir: vi.fn(),
  warn: vi.fn(),
};

// A bag of doubles, not a partially-typed stand-in: every step is replaced, so
// the cast says what the shape already is.
const deps = mocks as unknown as ReportStepDeps;

const SCRATCH = "/tmp/buildcage-report-abc123";
const CONTAINER = "container-abc123";
/** `buildcage-` + the first 12 hex of sha256("buildcage") — the same name
 *  setup derives from its own builder_name input. */
const PROJECT_NAME = "buildcage-eeb358f947ee";

let prevExitCode: number | string | null | undefined;

beforeEach(() => {
  prevExitCode = process.exitCode;
  process.exitCode = undefined;
  vi.resetAllMocks();
  mocks.readBuilderName.mockReturnValue("buildcage");
  mocks.readTrafficArtifactInputs.mockReturnValue({ wanted: false });
  mocks.createDocker.mockReturnValue({ docker: true });
  mocks.findReportSourceContainer.mockReturnValue(CONTAINER);
  mocks.makeScratchDir.mockReturnValue(SCRATCH);
  mocks.runReportScript.mockReturnValue(0);
  mocks.uploadTrafficArtifact.mockResolvedValue(undefined);
});

afterEach(() => {
  process.exitCode = prevExitCode;
});

describe("runReportStep", () => {
  it("finds the container by the project name the builder name derives to", async () => {
    await runReportStep({}, deps);
    expect(mocks.findReportSourceContainer).toHaveBeenCalledWith(
      { docker: true },
      PROJECT_NAME,
      "buildcage",
    );
  });

  it("copies the report script out of the container's image and runs it against that container", async () => {
    await runReportStep({}, deps);
    expect(mocks.copyFromContainerImage).toHaveBeenCalledWith(
      CONTAINER,
      REPORT_ACTION_SCRIPT_PATH,
      `${SCRATCH}/report-action.js`,
    );
    expect(mocks.runReportScript).toHaveBeenCalledWith(
      `${SCRATCH}/report-action.js`,
      CONTAINER,
      expect.anything(),
    );
  });

  it("reproduces the script's exit status as this step's own", async () => {
    mocks.runReportScript.mockReturnValue(1);
    await runReportStep({}, deps);
    expect(process.exitCode).toBe(1);
  });

  it("removes the scratch directory it made", async () => {
    await runReportStep({}, deps);
    expect(mocks.removeScratchDir).toHaveBeenCalledWith(SCRATCH);
  });
});

describe("the COMPOSE_PROJECT_NAME override, which is this repo's own test hook", () => {
  it("is ignored without the build-test-hooks flag, however the environment is set", async () => {
    await runReportStep({ COMPOSE_PROJECT_NAME: "somebody-elses-project" }, deps);
    expect(mocks.findReportSourceContainer).toHaveBeenCalledWith(
      expect.anything(),
      PROJECT_NAME,
      "buildcage",
    );
  });

  it("takes the name as given once the flag is set", async () => {
    await runReportStep(
      { BUILDCAGE_BUILD_TEST_HOOKS: "1", COMPOSE_PROJECT_NAME: "buildcage-e2e" },
      deps,
    );
    expect(mocks.findReportSourceContainer).toHaveBeenCalledWith(
      expect.anything(),
      "buildcage-e2e",
      "buildcage",
    );
  });
});

describe("the traffic artifact", () => {
  it("names no traffic file, and uploads nothing, when none was asked for", async () => {
    await runReportStep({}, deps);
    expect(mocks.runReportScript.mock.calls[0][2].trafficFile).toBe(undefined);
    expect(mocks.uploadTrafficArtifact).not.toHaveBeenCalled();
  });

  it("names a file inside the scratch dir, so only what this step created is uploaded", async () => {
    mocks.readTrafficArtifactInputs.mockReturnValue({ wanted: true, retentionDays: 7 });
    await runReportStep({}, deps);
    expect(mocks.runReportScript.mock.calls[0][2].trafficFile).toBe(`${SCRATCH}/traffic.json`);
    expect(mocks.uploadTrafficArtifact).toHaveBeenCalledWith(
      `${SCRATCH}/traffic.json`,
      "buildcage",
      mocks.warn,
      { retentionDays: 7, reportScriptFinished: true },
    );
  });

  it("uploads before the scratch dir is removed, the file living inside it", async () => {
    mocks.readTrafficArtifactInputs.mockReturnValue({ wanted: true });
    const order: string[] = [];
    mocks.uploadTrafficArtifact.mockImplementation(async () => void order.push("upload"));
    mocks.removeScratchDir.mockImplementation(() => void order.push("remove"));
    await runReportStep({}, deps);
    expect(order).toStrictEqual(["upload", "remove"]);
  });

  it("still uploads when the report script was never launched, saying it did not finish", async () => {
    // The traffic JSON is most wanted on the run that failed, and a file
    // missing because the script never ran says nothing about the engine.
    mocks.readTrafficArtifactInputs.mockReturnValue({ wanted: true });
    mocks.runReportScript.mockImplementation(() => {
      throw new ReportError("node is not on PATH", "REPORT_SCRIPT_FAILED");
    });
    await expect(runReportStep({}, deps)).rejects.toThrow(ReportError);
    expect(mocks.uploadTrafficArtifact).toHaveBeenCalledWith(
      `${SCRATCH}/traffic.json`,
      "buildcage",
      mocks.warn,
      { retentionDays: undefined, reportScriptFinished: false },
    );
    expect(mocks.removeScratchDir).toHaveBeenCalledWith(SCRATCH);
  });
});
