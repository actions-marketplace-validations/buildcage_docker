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

export function resolveProxyEngine(input: string | undefined): ProxyEngine {
  const trimmed = input?.trim() || "inspect";
  // The explicit engine (BuildKit's native --proxy-network) was removed; point
  // anyone still on it at a supported engine rather than a bare invalid value.
  if (trimmed === "explicit") {
    throw new SetupError(
      "proxy_engine: explicit has been removed. Use proxy_engine: universal (network-level SNI/Host inspection) or inspect (TLS-terminating URL enforcement).",
      "INVALID_PROXY_ENGINE",
    );
  }
  if (trimmed === "transparent") {
    throw new SetupError(
      "proxy_engine: transparent has been renamed. Use proxy_engine: universal.",
      "INVALID_PROXY_ENGINE",
    );
  }
  if (!(ENGINES as readonly string[]).includes(trimmed)) {
    throw new SetupError(
      `Invalid proxy_engine: ${JSON.stringify(input)}. Must be one of ${ENGINES.join(", ")}.`,
      "INVALID_PROXY_ENGINE",
    );
  }
  return trimmed as ProxyEngine;
}
