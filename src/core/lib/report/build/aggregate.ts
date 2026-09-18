import { completeRulePort, convertRule } from "#core/lib/acl/wildcard-rules.ts";
import { parseIdentifier } from "#core/lib/log/parse-identifier.ts";
import { aggregate, type AggregatedEntry, type LogEntry } from "#core/lib/log/aggregate.ts";
import type { VertexAllowedEntry } from "#core/lib/log/vertex.ts";

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
 * not -- right, since no port was involved. Without this a refused name could
 * never be marked expected.
 */
function targetOf(row: AggregatedEntry): string {
  return `${row.host}:${row.port === "-" ? "0" : row.port}`;
}

/**
 * Build the host-aggregated allowed/audited table from the same per-build
 * vertex data vertex.ts's parseVertexAllowedLog() produces for the
 * per-command breakdown.
 *
 * Which decision the rows came from is not carried: the table shows the hosts
 * a build reached, and the heading above it says whether they were allowed or
 * merely audited (see render-report-markdown.ts).
 */
export function aggregateAllowedHosts(
  builds: Pick<VertexAllowedEntry, "entries">[][],
): AggregatedEntry[] {
  const entries: LogEntry[] = [];
  for (const vertices of builds) {
    for (const { entries: vertexEntries } of vertices) {
      for (const { url } of vertexEntries) {
        const parsed = parseIdentifier(url);
        if (!parsed) continue;
        entries.push({
          ruleType: parsed.scheme === "https" ? "HTTPS" : "HTTP",
          host: parsed.host,
          port: parsed.port,
          reason: "-",
        });
      }
    }
  }
  return aggregate(entries);
}
