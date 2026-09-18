import { parseObservedUrl } from "./authority.ts";

export interface ParsedIdentifier {
  scheme: string;
  host: string;
  port: string;
}

/**
 * Parse a proxy-network source identifier ("https://host[:port]/path...")
 * into its scheme/host/port. BuildKit omits an explicit ":443"/":80" from the
 * identifier when the original request didn't specify a port, so a missing
 * port is filled in with the scheme's default. Returns null for non-http(s)
 * identifiers — buildcage's generated policy only ever denies ^https?://
 * sources, but this guards against unexpected input.
 */
export function parseIdentifier(identifier: string): ParsedIdentifier | null {
  const parsed = parseObservedUrl(identifier);
  if (!parsed) return null;
  const { scheme, host, port } = parsed;
  return { scheme, host, port };
}
