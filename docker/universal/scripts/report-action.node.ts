/**
 * Generates and emits the universal engine's outbound-traffic report.
 * Baked into the image, copied out of it (not out of the running container)
 * by the `report` action on every run, and run with `node report-action.js
 * <container-id>`. Runs on the runner, not inside the container, reaching in
 * via core/lib/docker/client.ts — so `report` itself never needs to know this
 * engine's log path or env var names.
 *
 * Everything but this engine's log path is core/lib/report/action-main.ts.
 */
import { readRotatedLog } from "#core/lib/docker/rotated-log.ts";
import { runReportAction } from "#core/lib/report/action-main.ts";
import { buildUniversalReportData } from "#core/lib/report/build/universal.ts";
import { errorMessage } from "#core/lib/errors.ts";

const LOG_DIR = "/var/log/haproxy";

runReportAction({
  proxyEngine: "universal",
  build: (docker, containerId, parameters) =>
    buildUniversalReportData(readRotatedLog(docker, containerId, LOG_DIR), parameters),
}).catch((e) => {
  console.log(`::error::Unexpected error in report-action: ${errorMessage(e)}`);
  process.exit(1);
});
