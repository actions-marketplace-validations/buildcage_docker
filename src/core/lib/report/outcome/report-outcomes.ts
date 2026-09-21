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
  const failed = describeFailedConnections(report, engineLabel);
  if (failed) emissions.push(failed);
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

/**
 * The notice for connections that failed after the rules had allowed them, or
 * undefined when there were none.
 *
 * A notice where describeUndecidedRequests warns: these have a table of their
 * own, so it only has to say that the step passed although connections failed.
 * Counted off the rows rather than a timeline, which only `inspect` has.
 */
function describeFailedConnections(
  report: ReportData,
  engineLabel: "sandbox" | "proxy",
): OutcomeEmission | undefined {
  const count = report.failed.reduce((total, row) => total + row.count, 0);
  if (count === 0) return undefined;
  return {
    level: "notice",
    shouldFail: false,
    message:
      `${count} connection(s) failed after buildcage ${engineLabel} allowed them, listed under ` +
      "Failed Connections. The origin broke off, or its name could not be resolved upstream: no " +
      "rule refused them and none can change the outcome, so none of them fails the step.",
  };
}
