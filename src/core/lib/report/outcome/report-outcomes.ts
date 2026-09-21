import type { OutcomeEmission } from "./annotate.ts";
import { describeBlockedOutcome } from "./blocked-outcome.ts";
import type { ReportData } from "../types.ts";

export interface DescribeReportOutcomesOptions {
  failOnBlocked: boolean;
  /** Which action is reporting; see BuildBlockedMessageOptions.engineLabel. */
  engineLabel: "sandbox" | "proxy";
}

/**
 * Every annotation a finished report calls for, in the order they should be
 * emitted. Both actions build their annotations from here, so neither can grow
 * one the other lacks.
 *
 * The blocked-connections check always speaks, if only with level "none": it is
 * the one that decides the step's outcome. Anything after it is an aside about
 * traffic no rule decided, which fails nothing.
 */
export function describeReportOutcomes(
  report: ReportData,
  { failOnBlocked, engineLabel }: DescribeReportOutcomesOptions,
): OutcomeEmission[] {
  const emissions: OutcomeEmission[] = [
    describeBlockedOutcome({
      isAudit: report.parameters.mode === "audit",
      failOnBlocked,
      blockedCount: report.blockedCount,
      blockedRows: report.blocked,
      logLooksPlausible: report.logLooksPlausible,
      engineLabel,
      engine: report.engine,
    }),
  ];
  const undecided = describeUndecidedRequests(report, engineLabel);
  if (undecided) emissions.push(undecided);
  return emissions;
}

/**
 * The warning for requests that never reached a rule, or undefined when there
 * were none.
 *
 * Neither host table holds them and `fail_on_blocked` does not either, so the
 * collapsed Communication details section is their only trace and a reader who
 * never opens it would not know a request had gone nowhere. Only `inspect`
 * produces them, and only `inspect` has that section, so the message can name
 * it.
 *
 * The wording avoids "incomplete", which the report already uses for a log
 * whose beginning is gone (see describeBlockedOutcome) and under the same ⚠️:
 * two ⚠️ warnings about different things would otherwise read as one, and
 * "this report may not be a full record" is a far bigger claim than "one
 * request went nowhere".
 */
function describeUndecidedRequests(
  report: ReportData,
  engineLabel: "sandbox" | "proxy",
): OutcomeEmission | undefined {
  if (report.engine !== "inspect") return undefined;
  const count = report.timeline.filter((event) => event.action === "incomplete").length;
  if (count === 0) return undefined;
  return {
    level: "warning",
    shouldFail: false,
    message:
      `${count} request(s) buildcage ${engineLabel} could not act on, shown with ⚠️ in ` +
      "Communication details. Each ended before a whole request had arrived, so no rule decided " +
      "it and none reached an origin: the client closed, timed out, or sent something that could " +
      "not be read as HTTP. None of them fails the step.",
  };
}
