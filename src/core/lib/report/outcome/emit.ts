import { createAnnotation } from "#core/lib/actions/annotation.ts";
import { describeReportOutcomes } from "./report-outcomes.ts";
import { applyOutcomeAnnotations } from "./annotate.ts";
import type { ReportData } from "../types.ts";

export interface EmitReportOutcomesOptions {
  failOnBlocked: boolean;
  summaryFile: string | undefined;
}

export function emitReportOutcomes(
  report: ReportData,
  { failOnBlocked, summaryFile }: EmitReportOutcomesOptions,
): void {
  const outcomes = describeReportOutcomes(report, { failOnBlocked, engineLabel: "proxy" });

  applyOutcomeAnnotations(createAnnotation(Boolean(summaryFile)), outcomes);
}
