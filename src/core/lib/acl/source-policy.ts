/**
 * Build a BuildKit sourcepolicy.pb.Policy (protobuf-JSON shape) from the same
 * allowed_https_rules/allowed_http_rules/allowed_ip_rules syntax used by
 * the universal engine's HAProxy ACLs.
 *
 * The DENY catch-all is scoped to ^https?:// only, so docker-image://,
 * git://, local://, and oci-layout:// sources (which never match any rule
 * here) fall through to BuildKit's default-allow-when-unmatched behavior:
 * FROM/git sources stay unfiltered, matching the universal engine's documented
 * behavior that only RUN-step network is controlled.
 */
import { convertRule, splitRuleTokens, wildcardToRegex } from "./wildcard-rules.ts";

const DEFAULT_PORT: Record<string, string> = { https: "443", http: "80" };

export interface SourcePolicyInput {
  proxyMode: string;
  httpsRulesInput: string | undefined;
  httpRulesInput: string | undefined;
  ipRulesInput: string | undefined;
}

interface SourcePolicyRule {
  action: "ALLOW" | "DENY";
  selector: { identifier: string; matchType: "REGEX" };
}

interface SourcePolicy {
  version: number;
  rules: SourcePolicyRule[];
}

export function buildSourcePolicy({
  proxyMode,
  httpsRulesInput,
  httpRulesInput,
  ipRulesInput,
}: SourcePolicyInput): SourcePolicy {
  if (proxyMode === "audit") {
    // No rules at all: BuildKit's own "proxy network requests:" build output
    // already provides audit visibility for every request.
    return { version: 1, rules: [] };
  }

  // BuildKit's policy engine applies "last matching rule wins" (see
  // sourcepolicy/engine.go's evaluatePolicy). The DENY catch-all has to come
  // first so it acts as the default, with the specific ALLOW rules after it:
  // an ALLOW rule that also matches the deliberately universal catch-all then
  // overrides it, being evaluated later. Reversing the order would make the
  // catch-all always win, denying everything.
  const rules: SourcePolicyRule[] = [
    {
      action: "DENY",
      selector: { identifier: "^https?://.*", matchType: "REGEX" },
    },
    ...splitRuleTokens(httpsRulesInput).map((rule) => allowRule(rule, "https")),
    ...splitRuleTokens(httpRulesInput).map((rule) => allowRule(rule, "http")),
    ...splitRuleTokens(ipRulesInput).flatMap((rule) => [
      allowRule(rule, "https"),
      allowRule(rule, "http"),
    ]),
  ];
  return { version: 1, rules };
}

function allowRule(rawRule: string, scheme: string): SourcePolicyRule {
  const identifier = rawRule.startsWith("~")
    ? toUrlIdentifierFromRegex(convertRule(rawRule), scheme)
    : toUrlIdentifierFromWildcard(rawRule, scheme);
  return { action: "ALLOW", selector: { identifier, matchType: "REGEX" } };
}

// BuildKit's exec-proxy identifier omits an explicit ":443"/":80" when the
// original request didn't specify a port (verified against a live
// moby/buildkit v0.31.1 container; see docs/security.md); a non-default port
// is always present. So a wildcard or exact port rule that resolves to the
// scheme's default port, or to any port, has to treat the port as optional in
// the generated identifier, or a request using the implicit default port would
// wrongly fall through to the DENY catch-all.
function toUrlIdentifierFromWildcard(rawRule: string, scheme: string): string {
  const combined = wildcardToRegex(rawRule); // e.g. "example\.com:443" or "example\.com:\d+" (no colon inside the domain part)
  const colonIdx = combined.lastIndexOf(":");
  const domainRegex = combined.slice(0, colonIdx);
  const portRegex = combined.slice(colonIdx + 1);
  const isDefaultPort = portRegex === DEFAULT_PORT[scheme];
  const isWildcardPort = portRegex === "\\d+";
  const portPattern = isDefaultPort || isWildcardPort ? `(:${portRegex})?` : `:${portRegex}`;
  return `^${scheme}://${domainRegex}${portPattern}(/.*)?$`;
}

// Replaces every unescaped ".*" with "[^/]*". A bare "." also matches "/", so
// without this, a rule like `~.*\.example\.com` could match past the domain
// and into the always-allowed path, e.g. "https://evil.com/x.example.com".
// Confining it to "[^/]*" keeps the match inside the domain:port segment.
function confineDotStarToDomain(s: string): string {
  return s.replace(/(\\*)\.\*/g, (match, backslashes) =>
    backslashes.length % 2 === 1 ? match : `${backslashes}[^/]*`,
  );
}

// `core` is convertRule's output, which anchorRawRegex has already given a
// leading `^` and a trailing `$`: a `~example` rule arrives here as
// `^example$`, matching the whole domain:port rather than a substring of it.
// The anchors come off so the scheme and the always-allowed path can be added
// around the body.
function toUrlIdentifierFromRegex(core: string, scheme: string): string {
  const body = confineDotStarToDomain(core.slice(1, -1));
  return `^${scheme}://${body}(/.*)?$`;
}
