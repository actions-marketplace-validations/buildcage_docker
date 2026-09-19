/**
 * The domain model of the `inspect` engine: one thing a build did, produced by
 * the log parser (inspect.ts) and consumed by the report layer.
 */

/**
 * What a rule decided, or would have decided had one been enforced.
 *
 * `discovery` is none of those: no rule decided it and none could. Folding it
 * into `block` would put a row in the report no rule could take away, and fail
 * a build under fail_on_blocked over a lookup that harmed nothing.
 */
export type TrafficAction = "allow" | "block" | "audit" | "discovery";

export type TrafficProtocol = "https" | "http" | "tls" | "tcp" | "dns";

/** One thing the build did. */
export interface TrafficEvent {
  /** When it started, in seconds since the epoch. */
  time: number;
  action: TrafficAction;
  protocol: TrafficProtocol;
  /** The name asked for, or the address when there was no name. */
  host: string;
  /** Absent for dns, which connects to nothing. */
  port?: number;
  /** dns only, and only where the type is the point: a discovery lookup, or a
   *  refused service name. */
  queryType?: string;
  /** http and https only. */
  method?: string;
  /** http and https only. Absolute, query string included. */
  url?: string;
  /** http and https only, and only when the exchange completed. */
  status?: number;
  /** Bytes returned to the build. Absent for dns and for a refusal. */
  bytes?: number;
  /** Why it was refused. Set only when action is "block". */
  reason?: string;
  /** Address it was actually sent to. Absent for dns. */
  destination?: string;
}

/** The hosts a run connected to, for isRedundantDns. CoreDNS lowercases what it
 *  logs while HAProxy repeats the authority verbatim, so both sides are
 *  folded. */
export interface ConnectedHosts {
  any: Set<string>;
  blocked: Set<string>;
}

/** Index a timeline once. The check below runs for every lookup, and rescanning
 *  the whole timeline for each would be quadratic. */
export function connectedHosts(timeline: TrafficEvent[]): ConnectedHosts {
  const connected: ConnectedHosts = { any: new Set(), blocked: new Set() };
  for (const event of timeline) {
    if (event.protocol === "dns") continue;
    const host = event.host.toLowerCase();
    connected.any.add(host);
    if (event.action === "block") connected.blocked.add(host);
  }
  return connected;
}

/**
 * A lookup is the sole trace of a name the build never connected to, and worth
 * keeping for that. Once a connection to the same name also appears, it says
 * nothing that connection does not and only doubles the row.
 *
 * A refused lookup takes a refused connection to cover it. An allowed request
 * for a name the resolver refused would mean the two disagreed about that host,
 * which a reader should see rather than have collapsed away.
 *
 * A discovery lookup is never redundant: it asks about `_service._proto.<host>`,
 * which nothing connects to, and its query type is the point of the row.
 */
export function isRedundantDns(event: TrafficEvent, connected: ConnectedHosts): boolean {
  if (event.protocol !== "dns" || event.action === "discovery") return false;
  const host = event.host.toLowerCase();
  return event.action === "block" ? connected.blocked.has(host) : connected.any.has(host);
}
