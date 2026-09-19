/**
 * Log parsing library for HAProxy buildcage logs. aggregate() lives
 * separately in core/lib/log/aggregate.js and is not re-exported here.
 */
import { createIncrementalAggregator, type AggregatedEntry } from "./aggregate.ts";
import { splitHostPort } from "./authority.ts";
import { PROXY_START_MARKER } from "./start-marker.ts";

export interface HaproxyLogScanResult {
  /** ALLOWED entries in restrict mode, AUDIT entries in audit mode, never
   *  both (see `isAudit`). */
  passed: AggregatedEntry[];
  blocked: AggregatedEntry[];
  /** Raw BLOCKED line count, pre-aggregation: distinct from blocked.length. */
  blockedCount: number;
  /** True iff the log opens with the startup marker. Anything else means its
   *  beginning is gone, rotated away or erased. Only the marker counts:
   *  HAProxy's own output appears mid-run and could stand in for it. */
  headIntact: boolean;
  /** Lines carrying the marker below yet matching no format above. Each is a
   *  decision the report cannot account for. */
  unparsed: number;
}

// The quoted field and reason are restricted to the charset the generators
// actually emit (host/IP/port, and a kebab-case reason), and the line is
// anchored at both ends, so a forged target or reason is never parsed as a
// decision.
const logPattern =
  /^\[[^\]]*\]\s+buildcage\s+\[(AUDIT|ALLOWED|BLOCKED)\]\s+\((\w+)\)\s+"([A-Za-z0-9._:-]+)"\s*([A-Za-z0-9-]*)\s*$/;

/** What a decision line carries and nothing else does: the startup marker has
 *  no bracket after the name. A cut line keeps it, only its tail being lost. */
const DECISION_MARKER = "buildcage [";

/**
 * Single forward pass over the log: matching lines fold directly into
 * incremental aggregators (never collected into a flat array first).
 *
 * `isAudit` picks which decision counts as "passed" (AUDIT vs ALLOWED); the
 * other one, if it somehow appears, is dropped rather than aggregated.
 */
export async function scanHaproxyLog(
  lines: AsyncIterable<string> | Iterable<string>,
  isAudit: boolean,
): Promise<HaproxyLogScanResult> {
  const passed = createIncrementalAggregator();
  const blocked = createIncrementalAggregator();
  const passedDecision = isAudit ? "AUDIT" : "ALLOWED";
  let blockedCount = 0;
  let headIntact: boolean | undefined;
  let unparsed = 0;

  for await (const line of lines) {
    const m = line.match(logPattern);
    if (!m) {
      const trimmed = line.trim();
      if (trimmed === "") continue;
      headIntact ??= trimmed.startsWith(PROXY_START_MARKER);
      if (trimmed.includes(DECISION_MARKER)) unparsed++;
      continue;
    }
    headIntact ??= false;
    const [, decision, ruleType, hostPort, reason] = m;
    const { host, port } = splitHostPort(hostPort);
    const entry = { host, port: port ?? "0", ruleType, reason: reason || "-" };

    if (decision === passedDecision) {
      passed.add(entry);
    } else if (decision === "BLOCKED") {
      blocked.add(entry);
      blockedCount++;
    }
  }

  return {
    passed: passed.toSortedArray(),
    blocked: blocked.toSortedArray(),
    blockedCount,
    headIntact: headIntact ?? false,
    unparsed,
  };
}
