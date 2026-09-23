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
  const silent = () => {};

  it("uploads the file from its own directory, under the builder's name", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const { upload, calls } = fakeUpload();

    await uploadTrafficArtifact(FILE, "second", silent, { fileExists: () => true, upload });

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

    await uploadTrafficArtifact(FILE, "buildcage", silent, {
      retentionDays: 7,
      fileExists: () => true,
      upload,
    });

    expect(calls[0][3]).toStrictEqual({ retentionDays: 7 });
  });

  it("uploads nothing, and stays quiet, when no file was written", async () => {
    const warn = vi.fn();
    const { upload, calls } = fakeUpload();

    await uploadTrafficArtifact(FILE, "buildcage", warn, { fileExists: () => false, upload });

    expect(calls).toStrictEqual([]);
    expect(warn).not.toHaveBeenCalled();
  });

  it("warns rather than throwing when the upload fails", async () => {
    const warn = vi.fn();
    const { upload } = fakeUpload(new Error("artifact service unavailable"));

    await expect(
      uploadTrafficArtifact(FILE, "buildcage", warn, { fileExists: () => true, upload }),
    ).resolves.toBeUndefined();

    expect(warn).toHaveBeenCalledWith(
      "Could not upload the traffic artifact: artifact service unavailable",
    );
  });
});
