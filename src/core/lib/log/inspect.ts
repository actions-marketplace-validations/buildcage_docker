/**
 * Parsers for the `inspect` engine's two logs, whose formats are emitted by
 * haproxy-config.ts and coredns-config.ts. Four kinds of line:
 *
 *   buildcage <ms> <https|http> <method> <status> <bytes> ts=<st> dst=<addr>:<port> <url>
 *   buildcage <ms> pass <tls|tcp> <bytes> ts=<st> dst=<addr>:<port> sni=<name|->
 *   <timestamp>  [INFO] buildcage dns <allowed|denied> name=<name>.
 *   buildcage haproxy starting <ms>
 *
 * A fifth, `buildcage dns reverse name=<name>.`, is deliberately none of them:
 * no rule can name a reverse zone, so an event for it would be a report row no
 * rule could ever take away. It stays in the resolver log alone.
 *
 * <ms> is milliseconds since the epoch (HAProxy's date(0,ms), or qjs's
 * Date.now() for the startup line, printed before HAProxy itself is even
 * running); TrafficEvent's own time is in seconds, so parsing divides it
 * back down.
 *
 * The passthrough line is the only record of undecrypted traffic; the dns line
 * the only record of a refused name, which never reaches the proxy. Any other
 * line is HAProxy's or CoreDNS's own output and is skipped.
 *
 * The URL and the SNI are last on their lines because the build chooses how
 * long they are, so anything that cuts a line costs only their tail while the
 * decision, the status and the destination survive. Nothing should cut one:
 * haproxy's own `len` is above the longest request it accepts and s6-log's
 * line limit is above that again (see haproxy-config.ts and the haproxy-log
 * `run` script). What is left is a write larger than a pipe's atomic size
 * landing half-written, which joins two lines into one; `unparsed` below
 * counts that rather than letting it pass as nothing having happened. A line
 * the pipe dropped whole leaves no trace at all and cannot be counted.
 */

import type { TrafficAction, TrafficEvent } from "./traffic-event.ts";

export type { TrafficAction, TrafficEvent, TrafficProtocol } from "./traffic-event.ts";

// Both stay anchored at the end, and the trailing field stays \S+ rather than
// .+: two lines joined by a half-written write would otherwise parse as one
// event with a nonsense URL instead of being counted as unreadable.
const REQUEST = /^buildcage (\d+) (https?) (\S+) (-?\d+) (\d+) ts=(\S*) dst=(\S+):(\d+) (\S+)$/;
const PASSTHROUGH = /^buildcage (\d+) pass (tls|tcp) (\d+) ts=(\S*) dst=(\S+):(\d+) sni=(\S+)$/;
const DNS = /^(\S+ \S+)\s+.*buildcage dns (allowed|denied) name=(\S+?)\.?$/;
/** Echoed before CoreDNS starts, so it is always the log's first line (see
 *  inspect/files/s6-rc.d/coredns/run). s6-log stamps this log, hence the
 *  suffix test. */
const DNS_START_MARKER = "buildcage coredns starting";

/** What every line the proxy writes for us opens with, startup marker
 *  included. HAProxy's own [NOTICE]/[WARNING] output never does. */
const LINE_PREFIX = "buildcage ";

/** The marker the proxy prints once at startup. See hasProxyStarted. */
const START_MARKER = "buildcage haproxy starting";
/** Same marker, capturing the millisecond epoch it was printed with. */
const START = /^buildcage haproxy starting (\d+)$/;

/**
 * Whether buildcage ended the exchange, rather than an origin answering.
 *
 * The status cannot say: an origin answers 403 or 503 of its own accord too.
 * HAProxy's termination state can: `P` for a deny/reject, `S` for a backend
 * unreachable or unverified, `-` for a relayed response.
 */
function isRefusal(terminationState: string): boolean {
  return terminationState.startsWith("P") || terminationState.startsWith("S");
}

/** Refusal reason, matching the universal engine's kebab-case vocabulary. */
function reasonForStatus(status: number): string {
  if (status === 502) return "dns-failed";
  if (status === 503) return "origin-unreachable";
  return "not-allowed";
}

function actionFor(refused: boolean, isAudit: boolean): TrafficAction {
  if (refused) return "block";
  // audit enforces nothing, so nothing here was allowed by a rule. Calling it
  // "allow" would claim a decision that was never made.
  return isAudit ? "audit" : "allow";
}

const URL_AUTHORITY = /^https?:\/\/([^/?#]+)/;

/** The host half of an absolute URL's authority, without its port. */
function hostOf(url: string): string {
  const match = URL_AUTHORITY.exec(url);
  if (!match) return url;
  const authority = match[1];
  const colon = authority.lastIndexOf(":");
  return colon > 0 ? authority.slice(0, colon) : authority;
}

/** Parse one proxy-log line, or null if it is not one of ours. */
function parseProxyLine(line: string, isAudit: boolean): TrafficEvent | null {
  const trimmed = line.trim();

  const request = REQUEST.exec(trimmed);
  if (request) {
    const refused = isRefusal(request[6]);
    const event: TrafficEvent = {
      time: Number(request[1]) / 1000,
      action: actionFor(refused, isAudit),
      protocol: request[2] as "http" | "https",
      host: hostOf(request[9]),
      port: Number(request[8]),
      method: request[3],
      url: request[9],
      destination: `${request[7]}:${request[8]}`,
    };
    if (refused) event.reason = reasonForStatus(Number(request[4]));
    else {
      event.status = Number(request[4]);
      event.bytes = Number(request[5]);
    }
    return event;
  }

  const pass = PASSTHROUGH.exec(trimmed);
  if (pass) {
    const refused = isRefusal(pass[4]);
    // An ip rule names an address and carries no SNI, so the address is the
    // only identity such a connection has.
    const sni = pass[7];
    const event: TrafficEvent = {
      time: Number(pass[1]) / 1000,
      action: actionFor(refused, isAudit),
      protocol: pass[2] as "tls" | "tcp",
      host: sni === "-" ? pass[5] : sni,
      port: Number(pass[6]),
      destination: `${pass[5]}:${pass[6]}`,
    };
    // Never decrypted, so there is no status to report either way.
    if (refused) event.reason = "not-allowed";
    else event.bytes = Number(pass[3]);
    return event;
  }

  return null;
}

/** What one pass over the resolver log yields. */
export interface InspectDnsLogScan {
  events: TrafficEvent[];
  /** True iff the log's first non-blank line is the startup marker. See
   *  scanInspectDnsLog. */
  headIntact: boolean;
}

/** What one pass over the proxy log yields. */
export interface InspectLogScan {
  events: TrafficEvent[];
  /** Seconds since the epoch the proxy itself started, matching
   *  TrafficEvent.time's unit. Undefined exactly when hasProxyStarted would
   *  be false -- the marker line never showed up at all. */
  startedAt: number | undefined;
  /** True iff the log opens with the startup marker. Stricter than
   *  `startedAt`: a restart writes a second marker, which would otherwise
   *  vouch for a beginning that had already rotated away. */
  headIntact: boolean;
  /** Lines that announce themselves as the proxy's own yet match none of the
   *  formats above. Each one is an event the report cannot account for, so the
   *  caller treats any at all as a log it cannot vouch for. */
  unparsed: number;
}

/**
 * Read the proxy log once, collecting both the events and the startup marker.
 *
 * The report needs both, and the log arrives as a stream that can only be
 * consumed once, so they cannot be two separate passes. `for await` also
 * accepts a plain array, so callers with the lines already in memory pass one.
 */
export async function scanInspectLog(
  lines: AsyncIterable<string> | Iterable<string>,
  isAudit = false,
): Promise<InspectLogScan> {
  const events: TrafficEvent[] = [];
  let startedAt: number | undefined;
  let headIntact: boolean | undefined;
  let unparsed = 0;
  for await (const line of lines) {
    const event = parseProxyLine(line, isAudit);
    if (event) {
      headIntact ??= false;
      events.push(event);
      continue;
    }
    const trimmed = line.trim();
    if (trimmed === "") continue;
    const match = START.exec(trimmed);
    headIntact ??= match !== null;
    if (match && startedAt === undefined) startedAt = Number(match[1]) / 1000;
    // The startup marker is excluded by its own prefix rather than by `match`:
    // its stamp comes from qjs, and a qjs that failed would leave the prefix
    // alone on the line, which is not evidence that traffic went unrecorded.
    if (trimmed.startsWith(LINE_PREFIX) && !trimmed.startsWith(START_MARKER)) unparsed++;
  }
  return { events, startedAt, headIntact: headIntact ?? false, unparsed };
}

/**
 * True when the log carries the marker the proxy prints once at startup.
 *
 * An empty log is ambiguous: the proxy may have started and seen nothing, or it
 * may never have started at all. The caller fails closed rather than reporting
 * "nothing was blocked" for a proxy that never ran.
 */
export function hasProxyStarted(lines: Iterable<string>): boolean {
  for (const line of lines) {
    if (line.includes(START_MARKER)) return true;
  }
  return false;
}

/**
 * Parse the resolver log into one event per name.
 *
 * A name is asked about repeatedly, and for A and AAAA separately, so only the
 * first mention of each is kept: the report is about which names a build
 * reached for, not how many times a resolver was consulted. An allowed answer
 * is decisive, so an AAAA refusal cannot mask an A that resolved.
 *
 * The time comes from s6-log rather than from CoreDNS, whose log plugin has no
 * timestamp replacement of its own. CoreDNS lowercases the name it logs, so a
 * name that carried information in its capitalisation is recorded without it.
 *
 * `headIntact` is false when the log doesn't open with the startup marker,
 * meaning its beginning is gone and the earliest refused names with it. Only
 * the marker counts: CoreDNS's `errors` plugin writes mid-run.
 */
export async function scanInspectDnsLog(
  lines: AsyncIterable<string> | Iterable<string>,
  isAudit = false,
): Promise<InspectDnsLogScan> {
  const seen = new Map<string, { time: number; allowed: boolean }>();
  let headIntact: boolean | undefined;
  for await (const line of lines) {
    const trimmed = line.trim();
    if (trimmed !== "") headIntact ??= trimmed.endsWith(DNS_START_MARKER);
    const match = DNS.exec(trimmed);
    if (!match) continue;
    const parsed = Date.parse(`${match[1].replace(" ", "T")}Z`);
    const time = Number.isNaN(parsed) ? 0 : parsed / 1000;
    const allowed = match[2] === "allowed";
    const existing = seen.get(match[3]);
    if (existing) existing.allowed ||= allowed;
    else seen.set(match[3], { time, allowed });
  }
  const events = [...seen.entries()].map(([host, { time, allowed }]) => {
    const event: TrafficEvent = {
      time,
      action: actionFor(!allowed, isAudit),
      protocol: "dns",
      host,
    };
    if (!allowed) event.reason = "dns-not-allowed";
    return event;
  });
  return { events, headIntact: headIntact ?? false };
}
