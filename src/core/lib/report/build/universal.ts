import { scanHaproxyLog } from "#core/lib/log/haproxy.ts";
import { annotateKnownBlocked } from "./aggregate.ts";
import type { GenReportParameters, UniversalReportData } from "../types.ts";

/**
 * Pure — no I/O; the caller (report-action.node.ts) fetches lines/parameters
 * itself. An empty input naturally yields passed:[]/blocked:[]/blockedCount:0,
 * so no special-case branch is needed.
 */
export async function buildUniversalReportData(
  lines: AsyncIterable<string> | Iterable<string>,
  parameters: GenReportParameters,
): Promise<UniversalReportData> {
  const isAudit = parameters.mode === "audit";
  const {
    passed,
    blocked: blockedRawRows,
    blockedCount,
    logHeadIntact,
    unparsed,
  } = await scanHaproxyLog(lines, isAudit);
  const blocked = annotateKnownBlocked(blockedRawRows, parameters.knownBlockedRules);

  return {
    engine: "universal",
    parameters,
    passed,
    blocked,
    blockedCount,
    // A decision line this cannot read is a decision the report is missing, and
    // it may well have been a refusal, so it counts the same as a log whose
    // beginning is gone.
    logLooksPlausible: logHeadIntact && unparsed === 0,
  };
}
