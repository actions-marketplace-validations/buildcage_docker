/**
 * Rule conversion library for buildcage container.
 * Converts wildcard patterns to regex strings for HAProxy ACLs.
 */

import {
  anchorRawRegex,
  endsAnchored,
  splitDomainFromPortPattern,
  splitRawRegexHost,
} from "./partial-wildcard.ts";

/**
 * Split a whitespace-separated rules string into individual rule tokens.
 */
export function splitRuleTokens(rulesInput: string | undefined): string[] {
  return rulesInput?.trim().split(/\s+/).filter(Boolean) ?? [];
}

/**
 * Build regex rules from a space-separated input string.
 */
export function buildRules(rulesInput: string): string[] {
  return splitRuleTokens(rulesInput).map(convertRule);
}

/**
 * Split+validate a space-separated rules string, returning the raw
 * (unconverted) rule tokens, for callers that need the original wildcard or
 * `~`regex syntax preserved, such as known_blocked_rules.
 *
 * @throws {Error} if any rule has invalid wildcard/regex syntax
 */
export function parseAndValidateRules(rulesInput: string | undefined): string[] {
  const rules = splitRuleTokens(rulesInput);
  rules.forEach(convertRule); // validate eagerly; throws on bad syntax
  return rules;
}

/**
 * `known_blocked_rules` only: give a rule that names no port the `:*` the
 * syntax otherwise requires.
 *
 * Every other rule input is matched against a connection, where the port is
 * part of what is being permitted. This one is matched against a row of the
 * report, and a row for a name the resolver refused has no port at all,
 * nothing having been connected to. Requiring one there means writing a port
 * that was never involved, which is every DNS row.
 */
export function completeRulePort(rule: string): string {
  if (!rule.startsWith("~")) return rule.includes(":") ? rule : `${rule}:*`;
  const regex = rule.slice(1);
  if (splitDomainFromPortPattern(regex).portPattern !== null) return rule;
  // Appended after a closing anchor the port would match nothing, so the
  // anchor comes off and convertRule's anchorRawRegex puts it back.
  return `~${endsAnchored(regex) ? regex.slice(0, -1) : regex}:\\d+`;
}

/**
 * Split+validate `known_blocked_rules`, completing a missing port first. The
 * completed text is what is returned, so everything downstream sees one shape.
 *
 * @throws {Error} if any rule has invalid wildcard/regex syntax
 */
export function parseAndValidateKnownBlockedRules(rulesInput: string | undefined): string[] {
  const rules = splitRuleTokens(rulesInput).map(completeRulePort);
  rules.forEach(convertRule);
  return rules;
}

/**
 * Convert a single rule (wildcard or `~`-prefixed regex) to a regex string.
 *
 * The `~` case reuses the `inspect` engine's own validator (a port is always
 * required there too) so both engines reject the same malformed regex the
 * same way, instead of this engine silently accepting a rule that then never
 * matches. anchorRawRegex then makes it cover a whole `host:port`, as a
 * wildcard rule does.
 */
export function convertRule(rule: string): string {
  if (rule.startsWith("~")) {
    splitRawRegexHost(rule);
    return anchorRawRegex(rule.slice(1));
  }
  return `^${wildcardToRegex(rule)}$`;
}

/**
 * Convert a domain wildcard to a regex string (without anchors or port).
 *
 * Supported wildcards:
 *   `**`: one or more characters, dots included
 *   `*` : one or more characters, dots excluded
 *   `?` : a single character, dots excluded
 *
 * A dot-separated part containing `*` must be exactly `*` or `**`.
 */
function domainToRegex(domain: string): string {
  const regexParts = domain.split(".").map((part) => {
    if (part === "**") return ".+";
    if (part === "*") return "[^.]+";
    if (part.includes("*")) {
      throw new Error(
        `Invalid wildcard in "${domain}": part "${part}" mixes "*" with other characters`,
      );
    }
    // Escape regex meta characters, `?` excluded: it is a wildcard, handled below
    return part
      .replace(/[.+^$()[\]{}|\\]/g, "\\$&") // escape regex special chars except `?`
      .replace(/\?/g, "[^.]"); // `?` matches a single character excluding dots
  });

  return regexParts.join("\\.");
}

/**
 * Convert a wildcard pattern (`<domain>:<port|*>`) to a regex string (without anchors).
 */
export function wildcardToRegex(pattern: string): string {
  if (!/^[^:]+:(?:\d+|\*)$/.test(pattern)) {
    throw new Error(`Invalid pattern "${pattern}"`);
  }
  const [domain, port] = pattern.split(":");
  const portRegex = port === "*" ? "\\d+" : port;
  return `${domainToRegex(domain)}:${portRegex}`;
}
