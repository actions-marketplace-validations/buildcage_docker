import { createAnnotation } from "#core/lib/actions/annotation.ts";
import { describeBlockedOutcome } from "./blocked-outcome.ts";
import { applyOutcomeAnnotation } from "./annotate.ts";
import type { ReportData } from "../types.ts";

export interface EmitBlockedOutcomeOptions {
  failOnBlocked: boolean;
  summaryFile: string | undefined;
}

export function emitBlockedOutcome(
  report: ReportData,
  { failOnBlocked, summaryFile }: EmitBlockedOutcomeOptions,
): void {
  const outcome = describeBlockedOutcome({
    isAudit: report.parameters.mode === "audit",
    failOnBlocked,
    blockedCount: report.blockedCount,
    blockedRows: report.blocked,
    logLooksPlausible: report.logLooksPlausible,
    engineLabel: "proxy",
    engine: report.engine,
  });

  applyOutcomeAnnotation(createAnnotation(Boolean(summaryFile)), outcome);
}
