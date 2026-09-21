import { scanBuildkitdLog } from "#core/lib/log/buildkitd.ts";
import { aggregateAllowedHosts, annotateKnownBlocked } from "./aggregate.ts";
import type { VertexAllowedEntry } from "#core/lib/log/vertex.ts";
import type { GenReportParameters, ExplicitReportData } from "../types.ts";

/** Pure: no I/O; callers fetch lines/builds/parameters themselves. */
export async function buildExplicitReportData(
  lines: AsyncIterable<string> | Iterable<string>,
  builds: VertexAllowedEntry[][],
  parameters: GenReportParameters,
): Promise<ExplicitReportData> {
  const { blocked: blockedRawRows, denied, hasNonDenialContent } = await scanBuildkitdLog(lines);
  const blocked = annotateKnownBlocked(blockedRawRows, parameters.knownBlockedRules);
  // blockedCount equals blocked.length here, unlike the other engines:
  // buildkitd's denial log has no finer per-event granularity to count.
  const blockedCount = blocked.length;

  const passed = aggregateAllowedHosts(builds);

  return {
    engine: "explicit",
    parameters,
    passed,
    blocked,
    // buildkitd's log records what it refused and nothing else, so a request
    // that failed after being allowed never appears in it.
    failed: [],
    blockedCount,
    logLooksPlausible: hasNonDenialContent,
    proxyLogs: {
      builds,
      denied,
    },
  };
}
