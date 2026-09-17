import { SetupError } from "./errors.ts";

/**
 * Resolve and validate the proxy_engine input.
 * Each accepted value maps to a separately published, separately tagged
 * Docker image (see provenance/image-tag.ts's imageTagFromRef).
 *
 * Lives here rather than in main.ts because lib/ modules need the type:
 * defining it in the entry point made compose-env.ts and
 * engine-rule-support.ts import back out of it.
 */
const ENGINES = ["universal", "explicit", "inspect"] as const;
export type ProxyEngine = (typeof ENGINES)[number];

// `transparent` was this engine's name before `inspect` existed, when it
// only had to contrast with `explicit` (interception style: network-level
// vs BuildKit's own proxy-network). Both `transparent` and `inspect`
// intercept at the network level, so that name stopped distinguishing
// anything once `inspect` shipped -- `universal` names what actually sets
// this engine apart instead (no CA trust needed, works with any tool).
// Kept working permanently as an alias, normalized here so nothing
// downstream ever has to know it existed.
const ENGINE_ALIASES: Record<string, ProxyEngine> = { transparent: "universal" };

export function resolveProxyEngine(input: string | undefined): ProxyEngine {
  const trimmed = input?.trim() || "universal";
  const alias = ENGINE_ALIASES[trimmed];
  if (alias) {
    console.log(
      `::notice::proxy_engine: transparent is now called universal; transparent still works, but consider updating to proxy_engine: universal.`,
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
