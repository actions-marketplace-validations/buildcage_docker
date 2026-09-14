import { connectedHosts, isRedundantDns, type TrafficEvent } from "#core/lib/log/traffic-event.ts";
import { formatElapsedVariable } from "../elapsed-time.ts";

/**
 * Render the communication detail as a collapsed markdown section, or "" if
 * empty. One timeline, allowed and refused interleaved. A name lookup is kept
 * only while it is its own sole trace, and dropped once a connection to the
 * same name shows up too. A discovery lookup is always its own sole trace --
 * nothing connects to `_service._proto.<host>` -- so it always shows.
 *
 * `startedAt` is when the proxy itself started (seconds since the epoch),
 * so every event reads as time elapsed since then rather than an absolute
 * clock reading nobody has a reference point for. Undefined only when the
 * log never showed a startup marker at all; that rare case falls back to
 * absolute-time rendering rather than inventing a start time it does not
 * have.
 */
export function renderInspectDetails(
  timeline: TrafficEvent[],
  startedAt: number | undefined,
): string {
  const body = renderInspectDetailsBody(timeline, startedAt);
  if (!body) return "";
  // A fenced block, so URLs need no markdown escaping and stay copy-pastable.
  return `\n<details>\n<summary>💬 Communication details</summary>\n\n\`\`\`\n${body}\`\`\`\n\n</details>\n`;
}

/**
 * The same content with no `<details>`/`<summary>` wrapper and no fenced
 * code block, or "" if there's nothing to show -- for a plain-text
 * destination like the job log, where both would render as literal text
 * rather than the collapsible, syntax-highlighted section they give the
 * Job Summary.
 */
export function renderInspectDetailsBody(
  timeline: TrafficEvent[],
  startedAt: number | undefined,
): string {
  const connected = connectedHosts(timeline);
  const shown = timeline.filter((e) => !isRedundantDns(e, connected));
  if (shown.length === 0) return "";

  return shown.map((event) => renderEvent(event, startedAt)).join("\n") + "\n";
}

const MARK: Record<string, string> = { block: "🚫", discovery: "ℹ️" };

function renderEvent(event: TrafficEvent, startedAt: number | undefined): string {
  const mark = MARK[event.action] ?? "✅";
  return `${mark} ${formatTime(event.time, startedAt)}: ${subject(event)} -> ${outcome(event)}`;
}

/** What was asked for, in the most specific form available. */
function subject(event: TrafficEvent): string {
  // The type is what tells a fallback nobody notices from an outright failure.
  if (event.queryType !== undefined) return `DNS ${event.queryType} ${event.host}`;
  if (event.protocol === "dns") return `DNS ${event.host}`;
  // A passthrough is never decrypted, so a name and a port is all there is.
  if (event.url === undefined) {
    return `${event.protocol.toUpperCase()} ${event.host}:${event.port}`;
  }
  return `${event.method} ${event.url}`;
}

/** What came of it: a refusal names its reason, anything else its result. */
function outcome(event: TrafficEvent): string {
  if (event.action === "block") return event.reason ?? "blocked";
  if (event.action === "discovery") return `no data (${event.queryType} is never served)`;
  const parts: string[] = [];
  if (event.status !== undefined) parts.push(String(event.status));
  if (event.bytes !== undefined) parts.push(`(${formatBytes(event.bytes)})`);
  // A name that resolved has neither, and saying so is the whole entry.
  return parts.length > 0 ? parts.join(" ") : "resolved";
}

/**
 * Elapsed since the proxy started, to the millisecond -- several requests
 * routinely land in the same second, and only this engine's log carries the
 * resolution to tell them apart. Falls back to absolute UTC only when there
 * is no start time to be relative to.
 */
function formatTime(epochSeconds: number, startedAt: number | undefined): string {
  if (startedAt === undefined) {
    return new Date(epochSeconds * 1000).toISOString().slice(11, 23) + "Z";
  }
  return formatElapsedVariable(epochSeconds - startedAt);
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes}B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)}MB`;
}
