import { describe, it, expect, vi, afterEach } from "vitest";

import {
  artifactName,
  uploadTrafficArtifact,
  wantsTrafficArtifact,
  type UploadArtifact,
} from "./traffic-artifact.ts";

const FILE = "/tmp/buildcage-report-abc/traffic.json";

/** @actions/core reads its inputs straight out of the INPUT_* environment. */
function setInput(name: string, value: string): void {
  vi.stubEnv(`INPUT_${name.toUpperCase()}`, value);
}

/** Records every upload's arguments; resolves unless `fail` is given. */
function fakeUpload(fail?: Error): { upload: UploadArtifact; calls: unknown[][] } {
  const calls: unknown[][] = [];
  return {
    calls,
    upload(name, files, rootDirectory, options) {
      calls.push([name, files, rootDirectory, options]);
      return fail ? Promise.reject(fail) : Promise.resolve(undefined);
    },
  };
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("wantsTrafficArtifact", () => {
  it("reads the upload_traffic_artifact input", () => {
    setInput("upload_traffic_artifact", "true");
    expect(wantsTrafficArtifact()).toBe(true);
    setInput("upload_traffic_artifact", "false");
    expect(wantsTrafficArtifact()).toBe(false);
  });

  it("is false when the input is unset, as when run from source", () => {
    expect(wantsTrafficArtifact()).toBe(false);
  });

  it("is false for a value getBooleanInput refuses", () => {
    setInput("upload_traffic_artifact", "yes");
    expect(wantsTrafficArtifact()).toBe(false);
  });
});

describe("artifactName", () => {
  it("is unsuffixed for the default builder", () => {
    expect(artifactName("buildcage")).toBe("buildcage-traffic");
  });

  it("is suffixed per builder, so two builders in one job don't collide", () => {
    expect(artifactName("second")).toBe("buildcage-traffic-second");
  });
});

describe("uploadTrafficArtifact", () => {
  it("uploads the file from its own directory, under the builder's name", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const { upload, calls } = fakeUpload();

    await uploadTrafficArtifact(FILE, "second", { fileExists: () => true, upload });

    expect(calls).toStrictEqual([
      [
        "buildcage-traffic-second",
        [FILE],
        "/tmp/buildcage-report-abc",
        { retentionDays: undefined },
      ],
    ]);
    expect(log).toHaveBeenCalledWith("Uploaded the traffic JSON as buildcage-traffic-second");
  });

  it("passes a positive traffic_artifact_retention_days through", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    setInput("traffic_artifact_retention_days", "7");
    const { upload, calls } = fakeUpload();

    await uploadTrafficArtifact(FILE, "buildcage", { fileExists: () => true, upload });

    expect(calls[0][3]).toStrictEqual({ retentionDays: 7 });
  });

  it.each(["", "0", "-1", "forever"])(
    "leaves the retention to the repository's own default for %o",
    async (input) => {
      vi.spyOn(console, "log").mockImplementation(() => {});
      setInput("traffic_artifact_retention_days", input);
      const { upload, calls } = fakeUpload();

      await uploadTrafficArtifact(FILE, "buildcage", { fileExists: () => true, upload });

      expect(calls[0][3]).toStrictEqual({ retentionDays: undefined });
    },
  );

  it("warns and uploads nothing when the engine produced no traffic JSON", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const { upload, calls } = fakeUpload();

    await uploadTrafficArtifact(FILE, "buildcage", { fileExists: () => false, upload });

    expect(calls).toStrictEqual([]);
    expect(log.mock.calls[0][0]).toContain("Only proxy_engine: inspect does.");
  });

  it("warns rather than throwing when the upload fails", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const { upload } = fakeUpload(new Error("artifact service unavailable"));

    await expect(
      uploadTrafficArtifact(FILE, "buildcage", { fileExists: () => true, upload }),
    ).resolves.toBeUndefined();

    expect(log).toHaveBeenCalledWith(
      "::warning::Could not upload the traffic artifact: artifact service unavailable",
    );
  });
});
