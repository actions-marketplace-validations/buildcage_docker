import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { describeDockerFailure } from "#core/lib/actions/docker-error.ts";
import { resolveProjectName } from "#core/lib/docker/compose-project-name.ts";
import { createDocker } from "#core/lib/docker/client.ts";
import { REPORT_ACTION_SCRIPT_PATH } from "#core/lib/docker/report-source.ts";
import { errorMessage } from "#core/lib/errors.ts";
import { exitOnFatalError } from "#core/lib/actions/fatal.ts";
import { copyFromContainerImage } from "./lib/copy-from-image.ts";
import { ReportError } from "./lib/errors.ts";
import { findReportSourceContainer } from "./lib/find-report-source.ts";
import { readBuilderName } from "./lib/inputs.ts";
import { uploadTrafficArtifact, wantsTrafficArtifact } from "./lib/traffic-artifact.ts";

// Untested by design, down to the end of the file: every step main() calls is
// tested directly, and what it adds is the docker/node invocations themselves.
/* v8 ignore start */

// Gates the COMPOSE_PROJECT_NAME override to this repo's own CI/dev testing.
const PROJECT_NAME_OVERRIDE_ENABLED = process.env.BUILDCAGE_BUILD_TEST_HOOKS === "1";

async function main(): Promise<void> {
  const builderName = readBuilderName();
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
  // The path is handed to the script, so only a file this step created is
  // ever uploaded. Only the inspect engine writes it.
  let trafficFile: string | undefined;
  let reportScriptFinished = false;
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

    trafficFile = wantsTrafficArtifact() ? join(scratchDir, "traffic.json") : undefined;

    // A separate catch from the docker cp above, so the error the user
    // sees names the actual failure instead of a misleading Docker message.
    try {
      execFileSync("node", [reportActionPath, containerId], {
        stdio: "inherit",
        env: trafficFile ? { ...process.env, BUILDCAGE_TRAFFIC_FILE: trafficFile } : process.env,
      });
    } catch (e) {
      const status = (e as { status?: number | null }).status;
      if (typeof status !== "number") {
        throw new ReportError(
          `Failed to run report-action.js: ${errorMessage(e)}`,
          "REPORT_SCRIPT_FAILED",
        );
      }
      // A numeric exit status means report-action.js ran and already
      // explained itself via its own inherited stdio, so just reproduce it.
      process.exitCode = status;
    }
    reportScriptFinished = true;
  } finally {
    // Uploaded from here so every path that ran the script keeps the file:
    // a failing run is when it is most wanted.
    if (trafficFile) {
      await uploadTrafficArtifact(trafficFile, builderName, { reportScriptFinished });
    }
    rmSync(scratchDir, { recursive: true, force: true });
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch(exitOnFatalError("report"));
}
/* v8 ignore stop */
