/** Logs a labeled ACL rule list, one rule per line, for a `::group::` block. */
export function logRules(label: string, rules: string[]): void {
  console.log(`${label} rules:${rules.length === 0 ? " (none)" : ""}`);
  for (const r of rules) console.log(`  ${r}`);
}

/** Wraps text as a GitHub Actions collapsible group. Returns [] when empty,
 *  so callers don't emit an empty group. */
export function wrapLogGroup(title: string, logText: string): string[] {
  if (!logText) return [];
  return [`::group::${title}`, logText, "::endgroup::"];
}

/**
 * Runs `fn` inside a collapsible group, for output that is printed as it is
 * produced rather than collected first (wrapLogGroup's case).
 *
 * Always closes the group, even if `fn` throws, so a failure mid-group can't
 * leave it open and swallow the rest of the step's output into it.
 */
export function withLogGroup<T>(title: string, fn: () => T): T {
  console.log(`::group::${title}`);
  try {
    return fn();
  } finally {
    console.log("::endgroup::");
  }
}

/**
 * withLogGroup for work that has to be awaited.
 *
 * Kept apart from the synchronous one rather than folded into it: awaiting a
 * synchronous `fn` still yields to the microtask queue, which would let the
 * closing marker land after output printed later in the same tick — leaving
 * the group open around lines it was never meant to contain.
 */
export async function withLogGroupAsync<T>(title: string, fn: () => T | Promise<T>): Promise<T> {
  console.log(`::group::${title}`);
  try {
    return await fn();
  } finally {
    console.log("::endgroup::");
  }
}
