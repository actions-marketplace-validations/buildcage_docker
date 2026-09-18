import { describe, it, expect, vi } from "vitest";

import { artifactName, uploadTrafficArtifact, type UploadArtifact } from "./traffic-artifact.ts";

const FILE = "/tmp/buildcage-report-abc/traffic.json";

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

  it("passes the retention it was given through", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const { upload, calls } = fakeUpload();

    await uploadTrafficArtifact(FILE, "buildcage", {
      retentionDays: 7,
      fileExists: () => true,
      upload,
    });

    expect(calls[0][3]).toStrictEqual({ retentionDays: 7 });
  });

  it("warns and uploads nothing when the engine produced no traffic JSON", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const { upload, calls } = fakeUpload();

    await uploadTrafficArtifact(FILE, "buildcage", { fileExists: () => false, upload });

    expect(calls).toStrictEqual([]);
    expect(log.mock.calls[0][0]).toContain("Only proxy_engine: inspect does.");
  });

  it("stays quiet about a missing file when the report script never finished", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const { upload, calls } = fakeUpload();

    await uploadTrafficArtifact(FILE, "buildcage", {
      reportScriptFinished: false,
      fileExists: () => false,
      upload,
    });

    expect(calls).toStrictEqual([]);
    expect(log).not.toHaveBeenCalled();
  });

  it("still uploads a file the report script wrote before it died", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const { upload, calls } = fakeUpload();

    await uploadTrafficArtifact(FILE, "buildcage", {
      reportScriptFinished: false,
      fileExists: () => true,
      upload,
    });

    expect(calls[0][0]).toBe("buildcage-traffic");
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
