/**
 * Splitting an observed `host:port` authority, as it comes from a proxy log
 * line, a BuildKit source identifier or a URL in the traffic.
 *
 * Not for rule syntax: acl/ parses a grammar of its own, where a wildcard can
 * stand in for either half, and it decides where the port begins on its own
 * terms.
 */

/** The port a scheme implies, which an authority is free to leave out. */
export const DEFAULT_PORT: Record<string, string> = { https: "443", http: "80" };

export interface HostPort {
  host: string;
  /**
   * `undefined` when the authority carried no port separator at all. That is
   * not the same as a trailing `host:`, which is separated but empty, and
   * callers that substitute a default only want to do so for the former.
   */
  port: string | undefined;
}

/**
 * Split an authority at its port separator.
 *
 * An IPv6 literal is bracketed and carries colons of its own, so the last
 * colon is a separator only when it falls outside the brackets: `[::1]:443`
 * splits, `[::1]` does not. Reading the last colon unconditionally turns the
 * latter into host `[:` and port `1]`.
 */
export function splitHostPort(authority: string): HostPort {
  const colon = authority.lastIndexOf(":");
  if (colon <= 0 || authority.slice(colon + 1).includes("]")) {
    return { host: authority, port: undefined };
  }
  return { host: authority.slice(0, colon), port: authority.slice(colon + 1) };
}

export interface ObservedUrl {
  scheme: string;
  host: string;
  /** The scheme's default when the authority left it out. */
  port: string;
  /** Path only, `/` where the URL carried none. A query is not part of it. */
  path: string;
}

/**
 * Split an observed absolute URL into its parts, or null if it is not an
 * http(s) URL at all.
 *
 * The authority ends at the first `/`, `?` or `#`: a URL that carries a query
 * but no path still has an authority of its own.
 */
export function parseObservedUrl(url: string): ObservedUrl | null {
  const match = /^(https?):\/\/([^/?#]+)([^?#]*)/.exec(url);
  if (!match) return null;
  const [, scheme, authority, path] = match;
  const { host, port } = splitHostPort(authority);
  return { scheme, host, port: port ?? DEFAULT_PORT[scheme], path: path || "/" };
}
