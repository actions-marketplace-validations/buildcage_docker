import { completeRulePort, convertRule } from "#core/lib/acl/wildcard-rules.ts";
import type { AggregatedEntry } from "#core/lib/log/aggregate.ts";

export interface AnnotatedBlockedRow extends AggregatedEntry {
  expected: boolean;
  /** The rule that matched, port-completed, for the report to group rows by.
   *  Undefined exactly when `expected` is false. */
  expectedBy?: string;
}

export interface ExpectedFlag {
  expected: boolean;
}

/**
 * Tag each aggregated blocked-hosts row with whether its `host:port` matches a
 * known_blocked_rules pattern, and with the rule that matched it.
 *
 * knownBlockedRules is as returned by parseAndValidateKnownBlockedRules. A
 * missing port is completed here too, so a value set straight in the
 * environment behaves like one that came through the action's input, and
 * `expectedBy` reports the completed text rather than the shorthand.
 */
export function annotateKnownBlocked(
  blockedRows: AggregatedEntry[],
  knownBlockedRules: string[],
): AnnotatedBlockedRow[] {
  const matchers = knownBlockedRules.map((rule) => {
    const completed = completeRulePort(rule);
    return { rule: completed, re: new RegExp(convertRule(completed)) };
  });
  return blockedRows.map((row) => {
    // Which of several covering rules a row is grouped under is arbitrary, so
    // it is the one written earliest.
    const matched = matchers.find(({ re }) => re.test(targetOf(row)));
    return matched
      ? { ...row, expected: true, expectedBy: matched.rule }
      : { ...row, expected: false };
  });
}

/**
 * What a known_blocked_rules pattern is tested against, normally `host:port`.
 *
 * A row with no port is a refused name, connected to nothing. It is tested as
 * port 0, which `host:*` matches (compiling to `host:\d+`) but `host:443` does
 * not, which is right since no port was involved. Without this a refused name
 * could never be marked expected.
 */
function targetOf(row: AggregatedEntry): string {
  return `${row.host}:${row.port === "-" ? "0" : row.port}`;
}
