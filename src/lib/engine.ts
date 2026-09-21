import { SetupError } from "./errors.ts";

/**
 * Resolve and validate the proxy_engine input.
 * Each accepted value maps to a separately published, separately tagged
 * Docker image (see provenance/image-tag.ts's imageTagFromRef).
 *
 * Lives here rather than in the entry point so lib/ modules can import the
 * type without importing back out of it.
 */
const ENGINES = ["universal", "inspect"] as const;
export type ProxyEngine = (typeof ENGINES)[number];

// `transparent` is a permanently supported alias for `universal`, normalized
// here so nothing downstream has to know about it.
const ENGINE_ALIASES: Record<string, ProxyEngine> = { transparent: "universal" };

export function resolveProxyEngine(
  input: string | undefined,
  notice: (message: string) => void,
): ProxyEngine {
  const trimmed = input?.trim() || "universal";
  const alias = ENGINE_ALIASES[trimmed];
  if (alias) {
    notice(
      "proxy_engine: transparent is now called universal; transparent still works, but consider updating to proxy_engine: universal.",
    );
  }
  // The explicit engine (BuildKit's native --proxy-network) was removed; point
  // anyone still on it at a supported engine rather than a bare invalid value.
  if (trimmed === "explicit") {
    throw new SetupError(
      "proxy_engine: explicit has been removed. Use proxy_engine: universal (network-level SNI/Host inspection) or inspect (TLS-terminating URL enforcement).",
      "INVALID_PROXY_ENGINE",
    );
  }
  const engine = alias ?? trimmed;
  if (!(ENGINES as readonly string[]).includes(engine)) {
    throw new SetupError(
      `Invalid proxy_engine: ${JSON.stringify(input)}. Must be one of ${ENGINES.join(", ")}.`,
      "INVALID_PROXY_ENGINE",
    );
  }
  return engine as ProxyEngine;
}
