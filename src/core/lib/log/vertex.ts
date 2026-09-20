import { type AllowedRequest, parseAllowedRequestsFromText } from "./proxy-request-text.ts";

// Matches vertex names for Dockerfile RUN instructions. BuildKit's bracketed
// prefix is the step counter alone ("[2/2] RUN ..."), or a stage identifier
// before it, named ("[stage1 2/2]") or auto-numbered ("[stage-0 2/2]"); the
// counter is left-padded to the build's total width ("[ 2/15]" vs "[10/15]").
// Nothing here picks that apart: only the stage identifier is used (see
// stageKeyOf below), so any bracketed content before "RUN " matches.
const runVertexPattern = /^\[([^\]]+)\]\s+RUN\s/;

// Within the bracketed prefix (see runVertexPattern above) the step counter is
// always the last whitespace-separated token, so whatever precedes it, if
// anything, is the stage identifier. Using `.split(/\s+/)` rather than a
// character-class regex on the stage name means this doesn't need to know
// Docker's `AS <name>` grammar at all, and can't misparse the padded step
// counter itself as a stage name the way a generic `\S+` capture would.
function stageKeyOf(bracketContent: string): string {
  const parts = bracketContent.trim().split(/\s+/);
  return parts.length > 1 ? parts[0] : "";
}

interface Vertex {
  name: string;
  digest: string;
  started?: string;
  completed?: string;
}

interface LogLine {
  vertex: string;
  stream: number;
  timestamp: string;
  data: string;
}

export interface VertexAllowedEntry {
  command: string;
  started: string;
  completed: string;
  entries: AllowedRequest[];
}

/**
 * Parse the output of `buildctl debug logs --progress=rawjson <ref>` into a
 * per-RUN-vertex breakdown, ordered for human debugging: grouped by
 * build stage (each stage's vertices kept together, in `started` order),
 * with stages themselves ordered by their earliest vertex's `started` time.
 * Independent stages can run concurrently, with overlapping `started`
 * timestamps, so vertex.digest (not physical log position) is the only
 * reliable way to attribute a "proxy network requests:" block to the RUN
 * step that produced it.
 */
export function parseVertexAllowedLog(rawJsonText: string): VertexAllowedEntry[] {
  // Usually a single JSON object, but buildctl can flush a large build's
  // rawjson history as several newline-separated JSON documents, which a lone
  // JSON.parse on the whole text would throw on. Not deduplicated by digest:
  // the `!v.started || !v.completed` skip below already drops each vertex's
  // earlier partial occurrences within a document, preserving the array-order
  // semantics the ordering below depends on.
  const vertexes: Vertex[] = [];
  const logs: LogLine[] = [];
  for (const line of rawJsonText.split("\n")) {
    if (!line.trim()) continue;
    let data;
    try {
      data = JSON.parse(line);
    } catch {
      continue;
    }
    vertexes.push(...(data.vertexes || []));
    logs.push(...(data.logs || []));
  }

  const groups = new Map<string, Vertex[]>(); // stageKey -> vertex[]
  for (const v of vertexes) {
    if (!v.started || !v.completed) continue;
    const m = v.name.match(runVertexPattern);
    if (!m) continue;
    const stageKey = stageKeyOf(m[1]);
    if (!groups.has(stageKey)) groups.set(stageKey, []);
    groups.get(stageKey)!.push(v);
  }

  for (const list of groups.values()) {
    list.sort((a, b) => Date.parse(a.started!) - Date.parse(b.started!));
  }
  const orderedGroups = [...groups.values()].sort(
    (a, b) => Date.parse(a[0].started!) - Date.parse(b[0].started!),
  );

  const logsByDigest = new Map<string, LogLine[]>();
  for (const l of logs) {
    if (l.stream !== 2) continue;
    if (!logsByDigest.has(l.vertex)) logsByDigest.set(l.vertex, []);
    logsByDigest.get(l.vertex)!.push(l);
  }

  return orderedGroups.flat().map((v) => {
    const stderrLogs = (logsByDigest.get(v.digest) || []).sort(
      (a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp),
    );
    const text = stderrLogs.map((l) => Buffer.from(l.data, "base64").toString("utf8")).join("");
    return {
      command: v.name,
      started: v.started!,
      completed: v.completed!,
      entries: parseAllowedRequestsFromText(text),
    };
  });
}
