import type { AggregatedEntry } from "#core/lib/log/aggregate.ts";
import { restrictExampleBlock, usesLine } from "./restrict-example.ts";

const ruleTypeToParam: Record<string, string> = {
  HTTPS: "allowed_https_rules",
  HTTP: "allowed_http_rules",
  IP: "allowed_ip_rules",
};

export type AuditedRow = Pick<AggregatedEntry, "host" | "port" | "ruleType">;

/**
 * Build a restrict-mode YAML configuration example from audited rows.
 * Returns a markdown string wrapped in <details> tags, or "" if no rows.
 *
 * actionRef is the ref (tag or commit SHA) this action was invoked with.
 * setup's action.yml lives at the repo root (not a subdirectory), so the
 * example's `uses:` never has an action-name path segment. actionVersion,
 * if known, is appended as a trailing `# 3.1.4` comment.
 */
export function buildRestrictExample(
  auditedRows: AuditedRow[] | null | undefined,
  actionRepo: string,
  actionRef?: string,
  actionVersion?: string,
): string {
  if (!auditedRows || auditedRows.length === 0) return "";

  const groups = new Map<string, string[]>();
  for (const r of auditedRows) {
    const param = ruleTypeToParam[r.ruleType];
    if (!param) continue;
    if (!groups.has(param)) groups.set(param, []);
    groups.get(param)!.push(`${r.host}:${r.port}`);
  }

  if (groups.size === 0) return "";

  let yaml = "";
  yaml += "- name: Start Buildcage\n";
  yaml += usesLine(actionRepo, actionRef, actionVersion);
  yaml += "  with:\n";
  yaml += "    proxy_mode: restrict\n";
  for (const [param, rules] of groups) {
    yaml += `    ${param}: >-\n`;
    for (const rule of rules) {
      yaml += `      ${rule}\n`;
    }
  }

  return restrictExampleBlock(yaml);
}
