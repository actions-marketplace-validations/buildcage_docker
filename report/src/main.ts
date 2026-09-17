import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import * as core from "@actions/core";

import { describeDockerFailure } from "#core/lib/actions/docker-error.ts";
import { resolveProjectName } from "#core/lib/docker/compose-project-name.ts";
import { createDocker } from "#core/lib/docker/client.ts";
import { REPORT_ACTION_SCRIPT_PATH } from "#core/lib/docker/report-source.ts";
import { ActionError, errorMessage } from "#core/lib/errors.ts";
import { copyFromContainerImage } from "./lib/copy-from-image.ts";
import { ReportError } from "./lib/errors.ts";
import { findReportSourceContainer } from "./lib/find-report-source.ts";
import { uploadTrafficArtifact, wantsTrafficArtifact } from "./lib/traffic-artifact.ts";

// Untested by design, down to the end of the file: every step main() calls is
// tested directly, and what it adds is the docker/node invocations themselves.
/* v8 ignore start */

// Gates the COMPOSE_PROJECT_NAME override to this repo's own CI/dev testing.
const PROJECT_NAME_OVERRIDE_ENABLED = process.env.BUILDCAGE_BUILD_TEST_HOOKS === "1";

async function main(): Promise<void> {
  const builderName = core.getInput("builder_name") || "buildcage";
  const projectName = resolveProjectName(
    builderName,
    PROJECT_NAME_OVERRIDE_ENABLED ? process.env.COMPOSE_PROJECT_NAME : undefined,
  );
  const docker = createDocker();

  const containerId = findReportSourceContainer(docker, projectName, builderName);

  // Pull report-action.js out of the (Sigstore-verified) image and run it
  // with node, inheriting stdio. It owns everything downstream —
  // fetching the container's env/logs, rendering the Job Summary, the
  // fail_on_blocked exit decision — so this step just reproduces its exit
  // code as its own.
  const scratchDir = mkdtempSync(join(tmpdir(), "buildcage-report-"));
  try {
    const reportActionPath = join(scratchDir, "report-action.js");

    try {
      copyFromContainerImage(containerId, REPORT_ACTION_SCRIPT_PATH, reportActionPath);
    } catch (e) {
      throw new ReportError(
        describeDockerFailure(e, {
          operation: "docker cp (fetching report-action.js from the builder image)",
        }),
        "DOCKER_UNAVAILABLE",
      );
    }

    // The path is handed to the script, so only a file this step created is
    // ever uploaded. Only the inspect engine writes it.
    const trafficFile = wantsTrafficArtifact() ? join(scratchDir, "traffic.json") : undefined;

    // A separate catch from the docker cp above, so the error the user
    // sees names the actual failure instead of a misleading Docker message.
    try {
      execFileSync("node", [reportActionPath, containerId], {
        stdio: "inherit",
        env: trafficFile ? { ...process.env, BUILDCAGE_TRAFFIC_FILE: trafficFile } : process.env,
      });
    } catch (e) {
      // A numeric exit status means report-action.js ran and already
      // explained itself via its own inherited stdio — just reproduce it.
      // Upload the artifact even then; a failing run is when it is most wanted.
      const status = (e as { status?: number | null }).status;
      if (typeof status === "number") {
        if (trafficFile) await uploadTrafficArtifact(trafficFile, builderName);
        process.exitCode = status;
        return;
      }
      throw new ReportError(
        `Failed to run report-action.js: ${errorMessage(e)}`,
        "REPORT_SCRIPT_FAILED",
      );
    }
    if (trafficFile) await uploadTrafficArtifact(trafficFile, builderName);
  } finally {
    rmSync(scratchDir, { recursive: true, force: true });
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    if (err instanceof ActionError) {
      console.log(`::error::${err.message}`);
    } else {
      console.log(`::error::Unexpected error in report: ${errorMessage(err)}`);
    }
    process.exit(1);
  });
}
/* v8 ignore stop */
