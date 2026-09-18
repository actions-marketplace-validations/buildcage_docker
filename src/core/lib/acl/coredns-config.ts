/**
 * Corefile generator for the `inspect` engine.
 *
 * Every name a build resolves, allowed or not, is answered locally with the
 * proxy's own address, not NXDOMAIN: the build connects to the proxy and its
 * full URL is recorded before being denied, and a name that is only looked
 * up, never connected to, still shows up in the log. CoreDNS never forwards a
 * query anywhere, so the query itself cannot reach a real nameserver and leak
 * whatever it looked up, with no connection ever needed.
 *
 * Real resolution happens once, in HAProxy, strictly after a request has
 * already passed its full host, path and method check; see
 * haproxy-config.ts. CoreDNS decides nothing a build can reach, only what
 * gets logged as allowed or denied, and that decision still has to match the
 * rules exactly, or a name outside them would be misreported as allowed.
 * That precision is why this engine uses CoreDNS (regex views) over dnsmasq
 * (suffix matching, which could only widen `abc*.amazonaws.com` to
 * `/amazonaws.com/`).
 *
 * Reverse lookups and service-discovery names are the two exceptions to all of
 * the above; see reverseZoneLines and discoveryZoneLines.
 */

import type { CompiledRuleSet } from "./haproxy-rules.ts";

export interface CorednsConfigOptions {
  /** Address every name resolves to, so it lands on the proxy. */
  proxyAddress: string;
  /** TTL for the synthesised answers. */
  ttlSeconds?: number;
  /**
   * `audit` refuses nothing, so every name is logged as allowed. Defaults to
   * `restrict`.
   */
  mode?: "audit" | "restrict";
}

export interface GeneratedCorednsConfig {
  config: string;
  /**
   * Always empty: this module reads an already-compiled rule set, so there is
   * nothing left for it to refuse. Present so a caller can merge it with
   * generateHaproxyConfig's warnings, which IP rules can still fill, and
   * report both the same way.
   */
  warnings: string[];
}

/**
 * Escape a regex for a CEL string literal.
 *
 * CEL rejects `\.` as an invalid character escape, so every backslash has to
 * be doubled to survive into the regex engine. Substituting only the dots
 * would be wrong: the host compiler escapes every one of `.+^$()[]{}|\`, and a
 * `~` rule may contain any of them.
 */
export function escapeForCel(regex: string): string {
  return regex.replace(/\\/g, "\\\\");
}

/**
 * The lines answering a name with the proxy's own address: NOERROR with an
 * empty AAAA (NODATA), not NXDOMAIN. NXDOMAIN claims the name itself does not
 * exist, and musl's getaddrinfo(AF_UNSPEC) takes that literally and discards
 * the valid A answer along with it, so a build under Alpine (BusyBox wget,
 * apk, ...) would fail outright instead of falling back to the A record like
 * every other resolver does. Shared by every block below, so the answer
 * cannot drift between what an allowed name gets and what a denied one does.
 *
 * `IN ANY` matches every type the two above do not, which would otherwise
 * reach no template at all and be answered SERVFAIL. NODATA refuses the same
 * query without telling the resolver the server is broken and worth retrying.
 */
function proxyAnswerLines(proxyAddress: string, ttlSeconds: number): string[] {
  return [
    "    template IN A {",
    `      answer "{{ .Name }} ${ttlSeconds} IN A ${proxyAddress}"`,
    "    }",
    "    template IN AAAA {",
    "    }",
    "    template IN ANY {",
    "    }",
  ];
}

/**
 * A name that is an address read backwards, and nothing else under the reverse
 * zones. Character classes rather than `\\.`, which CEL rejects outright; see
 * escapeForCel. The trailing `[.]` is the dot a query carries, as in the
 * allowlist expression.
 */
const REVERSE_NAME_REGEX =
  "^(([0-9]{1,3}[.]){1,4}in-addr[.]arpa|([0-9a-fA-F][.]){1,32}ip6[.]arpa)[.]$";

/**
 * The reverse zones, where a PTR query is answered NXDOMAIN.
 *
 * Nothing inside the cage has a name to give back, so the only question is how
 * the lookup ends. SERVFAIL, which is what an unhandled query gets, reads to
 * musl as a server that may yet answer: it retries and then waits out its
 * whole resolver timeout, five seconds for every reverse lookup a step makes.
 * NXDOMAIN is final, so the caller stops at once, and it matches what dnsmasq
 * gives the universal engine for the same addresses through bogus-priv.
 *
 * The lookup is still recorded, but under a verb of its own: no rule can name
 * an address read backwards, so reporting one as denied would put a row in the
 * report that no rule could ever take away.
 *
 * The view is what stops that verb from becoming a hiding place. It holds the
 * block to names that really are an address backwards; `SECRET-DATA.in-addr.arpa`
 * and every other label a build might invent misses the view, falls through to
 * the blocks below, and is answered, logged and reported like any other name.
 */
function reverseZoneLines(proxyAddress: string, ttlSeconds: number): string[] {
  const soa = `{{ .Zone }} ${ttlSeconds} IN SOA ns.buildcage.invalid. hostmaster.buildcage.invalid. 1 ${ttlSeconds} ${ttlSeconds} ${ttlSeconds} ${ttlSeconds}`;
  return [
    "# Reverse lookups: answered NXDOMAIN rather than left unhandled, which",
    "# would be SERVFAIL and cost musl a five-second timeout each time. Only a",
    "# name that is an address backwards is treated this way; anything else",
    "# under these zones misses the view and falls through to the blocks below.",
    "in-addr.arpa ip6.arpa {",
    "    view reverse {",
    `      expr name() matches '${REVERSE_NAME_REGEX}'`,
    "    }",
    "    template IN PTR {",
    "      rcode NXDOMAIN",
    `      authority "${soa}"`,
    "    }",
    ...proxyAnswerLines(proxyAddress, ttlSeconds),
    '    log . "buildcage dns reverse name={name}"',
    "    errors",
    "}",
    "",
  ];
}

/**
 * The `_service._proto.` half of a service name, bounded to what RFC 6335 and
 * RFC 2782 allow so the caller chooses as little of the name as possible; see
 * discoveryZoneLines. Character classes rather than `\\.`, which CEL rejects.
 *
 * The only place a service name is recognised: the report reads the verbs the
 * blocks below log under, never the shape.
 */
const SERVICE_PREFIX_REGEX = "_[a-z0-9-]{1,15}[.]_(tcp|udp|sctp)[.]";

/**
 * The types defined at a `_service._proto.` name: SRV (RFC 2782), the TXT
 * DNS-SD pairs with it (RFC 6763), TLSA (RFC 7671) and URI (RFC 7553).
 * Enumerated rather than excluding A and AAAA, so a type this block has never
 * heard of is refused rather than exempted on a guess.
 */
const DISCOVERY_TYPES = ["SRV", "TXT", "TLSA", "URI"];

/**
 * The block answering service-discovery names, under a verb of their own.
 *
 * No rule can permit one, this resolver returning no discovery record to
 * anybody, so reporting the lookup as denied would be a row no rule could take
 * away and would fail a build that worked.
 *
 * Both conditions are what keep that verb from becoming a hiding place; the
 * shape alone is nowhere near enough, `_a._tcp.SECRET.attacker.example` being
 * shaped like a service name too. `parentRegex` holds the block to names under
 * a host the rules already allow, which the build could have looked up
 * directly anyway; it is undefined in audit alone, which refuses nothing and
 * so has no blocked table to leave. The type is checked because the name does
 * not imply it, an underscore name being a convention for the owner name
 * (RFC 8552) rather than a promise about the question: an A query really is
 * answered by this resolver, with the proxy's address, so calling it a lookup
 * that got nothing back would be false.
 */
function discoveryZoneLines(
  proxyAddress: string,
  ttlSeconds: number,
  parentRegex: string | undefined,
): string[] {
  const parent = parentRegex === undefined ? ".+" : `(${escapeForCel(parentRegex)})`;
  return [
    "# Service-discovery names under an allowed host: answered NODATA and logged",
    "# under a verb of their own. No rule can permit one, so a denied row for it",
    "# could never be taken away. A service name under any other host misses the",
    "# view and is denied below, as the host itself would be. Both expressions",
    "# have to hold: a type not defined at a service name is judged below like",
    "# any other lookup rather than exempted on a guess.",
    ". {",
    "    view discovery {",
    `      expr name() matches '^${SERVICE_PREFIX_REGEX}${parent}[.]$'`,
    `      expr type() in [${DISCOVERY_TYPES.map((t) => `'${t}'`).join(", ")}]`,
    "    }",
    ...proxyAnswerLines(proxyAddress, ttlSeconds),
    '    log . "buildcage dns discovery name={name} type={type}"',
    "    errors",
    "}",
    "",
  ];
}

/**
 * The block taking every other service name, under a verb of its own.
 *
 * A refusal like any other, but the remedy is not: the name is an attribute of
 * the host below it (RFC 8552), so a rule naming it silences the row without
 * making the record resolve. Logging it apart is what lets the report point at
 * the host instead.
 *
 * It sits after the allowlist, so a name someone did write a rule for still
 * reads as allowed. The discovery block sits before it instead, so one under
 * an allowed host reads as `discovery` even when a rule names it, which is the
 * more accurate of the two.
 */
function serviceZoneLines(proxyAddress: string, ttlSeconds: number): string[] {
  return [
    "# Every other service name: refused like any other name, but recorded apart",
    "# so the report can say the remedy is the host below it rather than the name",
    "# itself, which no rule can make resolve.",
    ". {",
    "    view service {",
    `      expr name() matches '^${SERVICE_PREFIX_REGEX}.+[.]$'`,
    "    }",
    ...proxyAnswerLines(proxyAddress, ttlSeconds),
    '    log . "buildcage dns service-denied name={name} type={type}"',
    "    errors",
    "}",
    "",
  ];
}

// Loopback-only, so the readiness check reaching it never depends on what
// init-iptables allows. Declared in the catch-all block alone: the plugin
// binds a listener, and a second block asking for the same address fails.
const HEALTH_LINE = "    health 127.0.0.1:8080";

/**
 * Generate a Corefile from the same compiled rules the proxy's own config is
 * generated from, so what this logs as allowed and what HAProxy lets through
 * cannot disagree about a name.
 */
export function generateCorednsConfig(
  rules: CompiledRuleSet,
  options: CorednsConfigOptions,
): GeneratedCorednsConfig {
  const { proxyAddress, ttlSeconds = 60, mode = "restrict" } = options;
  const warnings: string[] = [];
  const hostRegexes = rules.resolverHosts;

  // Audit refuses nothing, so every name is logged as allowed. It is still
  // answered locally, not forwarded: audit records what a build tried, it
  // does not need a real answer to do that, and forwarding would make this
  // resolver a live exfiltration channel for any name a build only looks up.
  if (mode === "audit") {
    const lines = [
      "# Generated by buildcage. Do not edit.",
      "",
      ...reverseZoneLines(proxyAddress, ttlSeconds),
      ...discoveryZoneLines(proxyAddress, ttlSeconds, undefined),
      "# audit enforces nothing, so every name is logged as allowed. It is still",
      "# answered locally with the proxy's own address, so a name that was only",
      "# looked up, never connected to, still shows up here, and the query",
      "# itself never reaches a real nameserver.",
      ". {",
      HEALTH_LINE,
      ...proxyAnswerLines(proxyAddress, ttlSeconds),
      '    log . "buildcage dns allowed name={name}"',
      "    errors",
      "}",
      "",
    ];
    return { config: lines.join("\n"), warnings };
  }

  const lines: string[] = ["# Generated by buildcage. Do not edit.", ""];
  lines.push(...reverseZoneLines(proxyAddress, ttlSeconds));

  if (hostRegexes.length > 0) {
    // A queried name arrives with its trailing dot, hence the `[.]` before the
    // anchor. Alternation is used rather than one block per rule so a name is
    // matched against the whole allowlist in one pass.
    const alternation = hostRegexes.map((r) => `(${r})`).join("|");
    lines.push(...discoveryZoneLines(proxyAddress, ttlSeconds, alternation));
    lines.push(
      "# Allowlisted names are logged as allowed, but answered exactly like a",
      "# denied one, with the proxy's own address: real resolution happens once",
      "# a request has already passed HAProxy's own host+path+method check, not",
      "# here. The expression is the same host pattern the proxy rules are built",
      "# from, so the two cannot drift apart.",
      ". {",
      "    view allowlist {",
      `      expr name() matches '^(${escapeForCel(alternation)})[.]$'`,
      "    }",
      ...proxyAnswerLines(proxyAddress, ttlSeconds),
      '    log . "buildcage dns allowed name={name}"',
      "    errors",
      "}",
      "",
    );
  }

  lines.push(...serviceZoneLines(proxyAddress, ttlSeconds));

  lines.push(
    "# Everything else resolves to the proxy and is answered locally, so the",
    "# query never leaves and the request still arrives somewhere its full URL",
    "# can be recorded before being denied.",
    ". {",
    HEALTH_LINE,
    ...proxyAnswerLines(proxyAddress, ttlSeconds),
    '    log . "buildcage dns denied name={name}"',
    "    errors",
    "}",
    "",
  );

  return { config: lines.join("\n"), warnings };
}
