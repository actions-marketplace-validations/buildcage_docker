/**
 * Generates and emits the explicit engine's outbound-traffic report.
 * Baked into the image, copied out of it (not out of the running container)
 * by the `report` action on every run, and run with `node report-action.js
 * <container-id>`. Runs on the runner, not inside the container, reaching in
 * via core/lib/docker/client.ts. That includes `buildctl`, which runs inside
 * the container through `docker exec` rather than having to be on the runner.
 *
 * Everything but the buildctl fetch and the extra log group is
 * core/lib/report/action-main.ts.
 */
import { type Docker } from "#core/lib/docker/client.ts";
import { runReportAction } from "#core/lib/report/action-main.ts";
import { buildExplicitReportData } from "#core/lib/report/build/explicit.ts";
import { renderCommunicationDetailsBody } from "#core/lib/report/render/communication-details.ts";
import { errorMessage } from "#core/lib/errors.ts";
import { wrapLogGroup } from "#core/lib/actions/log.ts";
import { selectAllRefs } from "#core/lib/log/build-histories.ts";
import { parseVertexAllowedLog, type VertexAllowedEntry } from "#core/lib/log/vertex.ts";

const LOG_FILE = "/var/log/buildkitd/current";

/** Every build since the container started, not just the latest: a
 *  workflow may run several before calling report once. Best-effort: a
 *  buildctl failure here leaves the per-command breakdown empty. */
function collectBuilds(docker: Docker, containerId: string): VertexAllowedEntry[][] {
  try {
    const historiesOutput = docker.exec(containerId, [
      "buildctl",
      "debug",
      "histories",
      "--format",
      "{{json .}}",
    ]);
    const refs = selectAllRefs(historiesOutput);
    return refs.map((ref) => {
      const rawJsonOutput = docker.exec(containerId, [
        "buildctl",
        "debug",
        "logs",
        "--progress=rawjson",
        ref,
      ]);
      return parseVertexAllowedLog(rawJsonOutput);
    });
  } catch (e) {
    console.error(
      `(failed to fetch allowed/audited traffic detail via buildctl: ${errorMessage(e)})`,
    );
    return [];
  }
}

runReportAction({
  proxyEngine: "explicit",
  build: (docker, containerId, parameters) =>
    buildExplicitReportData(
      docker.readFileLines(containerId, LOG_FILE),
      collectBuilds(docker, containerId),
      parameters,
    ),
  // This engine alone can attribute a request to the RUN step that made it,
  // so it alone has a per-step breakdown worth printing to the job log.
  logSections: (report) =>
    report.engine === "explicit"
      ? wrapLogGroup(
          "HTTP Proxy communication logs",
          renderCommunicationDetailsBody(report.proxyLogs.builds, report.proxyLogs.denied),
        )
      : [],
}).catch((e) => {
  console.log(`::error::Unexpected error in report-action: ${errorMessage(e)}`);
  process.exit(1);
});
