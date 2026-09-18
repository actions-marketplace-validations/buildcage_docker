import { existsSync } from "node:fs";
import { dirname } from "node:path";

import { errorMessage } from "#core/lib/errors.ts";
import { annotate } from "#core/lib/actions/annotation.ts";
import { DEFAULT_BUILDER_NAME } from "#core/lib/docker/report-source.ts";

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
  /** Undefined leaves the retention to the repository's own default. */
  retentionDays?: number;
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
    retentionDays,
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
  const name = artifactName(builderName);
  try {
    await upload(name, [file], dirname(file), { retentionDays });
    console.log(`Uploaded the traffic JSON as ${name}`);
  } catch (e) {
    annotate.warning(`Could not upload the traffic artifact: ${errorMessage(e)}`);
  }
}
