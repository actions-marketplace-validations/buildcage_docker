import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { resolveProjectName } from "#core/lib/docker/compose-project-name.ts";
import { createDocker } from "#core/lib/docker/client.ts";
import { REPORT_ACTION_SCRIPT_PATH } from "#core/lib/docker/report-source.ts";
import { annotate } from "#core/lib/actions/annotation.ts";
import { exitOnFatalError } from "#core/lib/actions/fatal.ts";
import { copyFromContainerImage } from "./lib/copy-from-image.ts";
import { findReportSourceContainer } from "./lib/find-report-source.ts";
import { readBuilderName, readTrafficArtifactInputs } from "./lib/inputs.ts";
import { runReportScript } from "./lib/run-report-script.ts";
import { uploadTrafficArtifact } from "./lib/traffic-artifact.ts";

// Untested by design, down to the end of the file: every step main() calls is
// tested directly, and what it adds is the docker/node invocations themselves.
/* v8 ignore start */

// Gates the COMPOSE_PROJECT_NAME override to this repo's own CI/dev testing.
const PROJECT_NAME_OVERRIDE_ENABLED = process.env.BUILDCAGE_BUILD_TEST_HOOKS === "1";

async function main(): Promise<void> {
  const builderName = readBuilderName();
  const trafficArtifact = readTrafficArtifactInputs(annotate.warning);
  const projectName = resolveProjectName(
    builderName,
    PROJECT_NAME_OVERRIDE_ENABLED ? process.env.COMPOSE_PROJECT_NAME : undefined,
  );
  const docker = createDocker();

  const containerId = findReportSourceContainer(docker, projectName, builderName);

  const scratchDir = mkdtempSync(join(tmpdir(), "buildcage-report-"));
  // The path is handed to the script, so only a file this step created is
  // ever uploaded. Only the inspect engine writes it.
  const trafficFile = trafficArtifact.wanted ? join(scratchDir, "traffic.json") : undefined;
  let reportScriptFinished = false;
  try {
    const reportActionPath = join(scratchDir, "report-action.js");
    copyFromContainerImage(containerId, REPORT_ACTION_SCRIPT_PATH, reportActionPath);

    process.exitCode = runReportScript(reportActionPath, containerId, { trafficFile });
    reportScriptFinished = true;
  } finally {
    // Uploaded from here so every path that ran the script keeps the file:
    // a failing run is when it is most wanted.
    if (trafficFile) {
      await uploadTrafficArtifact(trafficFile, builderName, annotate.warning, {
        retentionDays: trafficArtifact.retentionDays,
        reportScriptFinished,
      });
    }
    rmSync(scratchDir, { recursive: true, force: true });
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch(exitOnFatalError("report"));
}
/* v8 ignore stop */
