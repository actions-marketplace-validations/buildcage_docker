import { scanInspectLog, scanInspectDnsLog } from "#core/lib/log/inspect.ts";
import { connectedHosts, isRedundantDns, type TrafficEvent } from "#core/lib/log/traffic-event.ts";
import { aggregate, type LogEntry } from "#core/lib/log/aggregate.ts";
import { annotateKnownBlocked } from "./aggregate.ts";
import type { GenReportParameters, InspectReportData } from "../types.ts";

/** How a protocol appears in the host tables, matching the rule kind that
 *  would permit it. */
const RULE_TYPE: Record<TrafficEvent["protocol"], string> = {
  https: "HTTPS",
  http: "HTTP",
  tls: "TLS",
  tcp: "IP",
  dns: "DNS",
};

/** Reduce an event to the host row a rule is written against. A dns event has
 *  no port, having connected to nothing. */
function toHostRow(event: TrafficEvent): LogEntry {
  return {
    host: event.host,
    port: event.port === undefined ? "-" : String(event.port),
    ruleType: RULE_TYPE[event.protocol],
    reason: event.reason ?? "-",
  };
}

/**
 * Build the report data from the proxy and resolver logs. Pure: the caller
 * fetches both logs and the parameters.
 *
 * The resolver log matters because a refused name never reached the proxy, so
 * a DNS-only exfiltration attempt would otherwise leave no trace.
 */
export async function buildInspectReportData(
  proxyLines: AsyncIterable<string> | Iterable<string>,
  dnsLines: AsyncIterable<string> | Iterable<string>,
  parameters: GenReportParameters,
): Promise<InspectReportData> {
  const isAudit = parameters.mode === "audit";
  // Independent inputs (separate `docker exec` log streams, no data
  // dependency between them), so read concurrently rather than paying their
  // combined latency serially.
  const [
    { events: proxyEvents, startedAt, headIntact: proxyHeadIntact, unparsed },
    { events: dnsEvents, headIntact: dnsHeadIntact },
  ] = await Promise.all([
    scanInspectLog(proxyLines, isAudit),
    scanInspectDnsLog(dnsLines, isAudit),
  ]);

  const timeline = [...proxyEvents, ...dnsEvents].sort((a, b) => a.time - b.time);

  const passedRows: LogEntry[] = [];
  const blockedRows: LogEntry[] = [];
  const connected = connectedHosts(timeline);
  for (const event of timeline) {
    // Decided by no rule, so it belongs in neither table. The timeline keeps it.
    if (event.action === "discovery" || event.action === "incomplete") continue;
    // A lookup the build then connected on only doubles the connection's row.
    // One with no connection behind it is the sole trace of a name reached for
    // and never used, in audit as much as in restrict.
    if (isRedundantDns(event, connected)) continue;
    (event.action === "block" ? blockedRows : passedRows).push(toHostRow(event));
  }

  const blocked = annotateKnownBlocked(aggregate(blockedRows), parameters.knownBlockedRules);

  return {
    engine: "inspect",
    parameters,
    passed: aggregate(passedRows),
    blocked,
    // Every blocked event is counted, not just the distinct hosts the table
    // collapses them into.
    blockedCount: blockedRows.length,
    // Either log losing its beginning loses evidence the other cannot vouch
    // for, and an unreadable line is the same gap mid-log.
    logLooksPlausible: proxyHeadIntact && dnsHeadIntact && unparsed === 0,
    startedAt,
    timeline,
  };
}
