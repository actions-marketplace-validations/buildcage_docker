import { existsSync } from "node:fs";
import { dirname } from "node:path";
import * as core from "@actions/core";

import { errorMessage } from "#core/lib/errors.ts";
import { annotate } from "#core/lib/actions/annotation.ts";
import { DEFAULT_BUILDER_NAME } from "#core/lib/docker/report-source.ts";

export function wantsTrafficArtifact(): boolean {
  try {
    return core.getBooleanInput("upload_traffic_artifact");
  } catch {
    // Unset, as in the dev and test invocations that run this from source
    // rather than through action.yml's own defaults.
    return false;
  }
}

/** Fixed so a workflow can name it, suffixed per builder against collisions. */
export function artifactName(builderName: string): string {
  return builderName === DEFAULT_BUILDER_NAME
    ? "buildcage-traffic"
    : `buildcage-traffic-${builderName}`;
}

export type UploadArtifact = (
  name: string,
  files: string[],
  rootDirectory: string,
  options: { retentionDays?: number },
) => Promise<unknown>;

/**
 * Imported lazily so a run that asks for no artifact does not load it.
 *
 * Untested by design: the default behind the seam above, which only hands
 * @actions/artifact what the tested caller decided.
 */
/* v8 ignore start */
const uploadViaActionsArtifact: UploadArtifact = async (name, files, rootDirectory, options) => {
  const { DefaultArtifactClient } = await import("@actions/artifact");
  return new DefaultArtifactClient().uploadArtifact(name, files, rootDirectory, options);
};
/* v8 ignore stop */

export interface UploadTrafficArtifactOptions {
  /** False when report-action.js died before it could write the file, so its
   *  absence says nothing about the engine. */
  reportScriptFinished?: boolean;
  /** `fileExists`/`upload` are injectable so tests can assert on the arguments
   *  instead of mocking node:fs and @actions/artifact directly. */
  fileExists?: (file: string) => boolean;
  upload?: UploadArtifact;
}

/**
 * Upload the traffic JSON, when the engine produced one. Best-effort: the exit
 * decision is already made, so a failed upload only warns.
 */
export async function uploadTrafficArtifact(
  file: string,
  builderName: string,
  {
    reportScriptFinished = true,
    fileExists = existsSync,
    upload = uploadViaActionsArtifact,
  }: UploadTrafficArtifactOptions = {},
): Promise<void> {
  if (!fileExists(file)) {
    // Only the inspect engine writes the file.
    if (reportScriptFinished) {
      annotate.warning(
        "upload_traffic_artifact was set, but this engine produces no traffic JSON. " +
          "Only proxy_engine: inspect does.",
      );
    }
    return;
  }
  const days = Number(core.getInput("traffic_artifact_retention_days") || "");
  const name = artifactName(builderName);
  try {
    await upload(name, [file], dirname(file), {
      retentionDays: Number.isFinite(days) && days > 0 ? days : undefined,
    });
    console.log(`Uploaded the traffic JSON as ${name}`);
  } catch (e) {
    annotate.warning(`Could not upload the traffic artifact: ${errorMessage(e)}`);
  }
}
