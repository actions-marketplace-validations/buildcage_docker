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
  const engine = alias ?? trimmed;
  if (!(ENGINES as readonly string[]).includes(engine)) {
    throw new SetupError(
      `Invalid proxy_engine: ${JSON.stringify(input)}. Must be one of ${ENGINES.join(", ")}.`,
      "INVALID_PROXY_ENGINE",
    );
  }
  return engine as ProxyEngine;
}
