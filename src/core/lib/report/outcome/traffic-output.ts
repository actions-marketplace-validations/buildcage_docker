/**
 * Writes the observed traffic to a file the report action can upload as an
 * artifact, so whoever wants it later can act on what a build reached
 * instead of reading it out of a summary.
 *
 * Only the inspect engine can produce this: it decrypts, so it has the method
 * and full URL of every request, refused ones included. The other engines see
 * host and port only.
 */

import { writeFileSync } from "node:fs";
import { formatElapsedFixed } from "../elapsed-time.ts";
import type { TrafficEvent } from "#core/lib/log/traffic-event.ts";

/**
 * One event, as it appears in the JSON: the same event the report renders,
 * with the time written as text and the elapsed time alongside it. Every other
 * field is documented on TrafficEvent.
 */
export type TrafficRecord = Omit<TrafficEvent, "time"> & {
  /** ISO 8601 UTC, from the proxy's own clock. */
  time: string;
  /** Time since the proxy itself started, always HH:MM:SS.mmm, so the shape
   *  never changes between a short and a long run. Absent when the proxy's
   *  start time could not be determined; never fabricated from something
   *  else. */
  elapsed?: string;
};

/**
 * Build the records for one run, oldest first.
 *
 * Includes every name lookup, the summary's tables only those with no request
 * behind them: the volume is cheap for a machine reader, and which names were
 * asked about is not always derivable from what was then connected to. A field
 * is absent when it does not apply, never zero, so filter on `action`, not
 * `status`.
 */
export function buildTrafficRecords(
  events: TrafficEvent[],
  startedAt: number | undefined,
): TrafficRecord[] {
  return [...events]
    .sort((a, b) => a.time - b.time)
    .map((e) => {
      const record: TrafficRecord = {
        time: new Date(e.time * 1000).toISOString(),
        action: e.action,
        protocol: e.protocol,
        host: e.host,
      };
      if (startedAt !== undefined) record.elapsed = formatElapsedFixed(e.time - startedAt);
      if (e.port !== undefined) record.port = e.port;
      if (e.queryType !== undefined) record.queryType = e.queryType;
      if (e.method !== undefined) record.method = e.method;
      if (e.url !== undefined) record.url = e.url;
      if (e.status !== undefined) record.status = e.status;
      if (e.bytes !== undefined) record.bytes = e.bytes;
      if (e.reason !== undefined) record.reason = e.reason;
      if (e.destination !== undefined) record.destination = e.destination;
      return record;
    });
}

/** Write the same records to a file, indented, for the report action to upload
 *  as an artifact (fetchable after the run, unlike a job output). */
export function writeTrafficFile(path: string, records: TrafficRecord[]): void {
  writeFileSync(path, JSON.stringify(records, null, 2) + "\n");
}
