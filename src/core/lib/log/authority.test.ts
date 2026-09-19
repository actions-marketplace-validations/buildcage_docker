import { describe, it, expect } from "vitest";

import { parseObservedUrl, splitHostPort } from "./authority.ts";

describe("splitHostPort", () => {
  // undefined, not "": the callers that substitute a scheme's default port
  // only want to do so when none was written at all.
  it("reports no port as undefined", () => {
    expect(splitHostPort("example.com")).toStrictEqual({ host: "example.com", port: undefined });
    expect(splitHostPort("")).toStrictEqual({ host: "", port: undefined });
  });

  it("reports a trailing colon as a present but empty port", () => {
    expect(splitHostPort("example.com:")).toStrictEqual({ host: "example.com", port: "" });
  });

  it("splits at the last colon, so a port always wins over anything before it", () => {
    expect(splitHostPort("a:b:443")).toStrictEqual({ host: "a:b", port: "443" });
  });

  describe("IPv6 literals", () => {
    it("splits a bracketed address with a port", () => {
      expect(splitHostPort("[::1]:443")).toStrictEqual({ host: "[::1]", port: "443" });
      expect(splitHostPort("[2001:db8::1]:8443")).toStrictEqual({
        host: "[2001:db8::1]",
        port: "8443",
      });
    });

    // The address's own colons come before the closing bracket, so the last
    // one is not a separator. Reading it as one would give host "[:" and port
    // "1]".
    it("leaves a bracketed address with no port intact", () => {
      expect(splitHostPort("[::1]")).toStrictEqual({ host: "[::1]", port: undefined });
      expect(splitHostPort("[2001:db8::1]")).toStrictEqual({
        host: "[2001:db8::1]",
        port: undefined,
      });
    });
  });

  // A leading colon is not a separator either: there is no host before it, so
  // the whole thing is treated as the host rather than as a bare port.
  it("does not split on a leading colon", () => {
    expect(splitHostPort(":443")).toStrictEqual({ host: ":443", port: undefined });
  });
});

describe("parseObservedUrl", () => {
  it("splits scheme, host, port and path", () => {
    expect(parseObservedUrl("https://example.com:8443/pkg/a")).toStrictEqual({
      scheme: "https",
      host: "example.com",
      port: "8443",
      path: "/pkg/a",
    });
  });

  it("fills in the port the scheme implies", () => {
    expect(parseObservedUrl("http://example.com/x")?.port).toBe("80");
    expect(parseObservedUrl("https://example.com/x")?.port).toBe("443");
  });

  it("reads a URL with no path as one on /", () => {
    expect(parseObservedUrl("https://example.com")?.path).toBe("/");
  });

  it("ends the authority at a query, which a URL may carry without a path", () => {
    expect(parseObservedUrl("https://example.com?q=1")).toStrictEqual({
      scheme: "https",
      host: "example.com",
      port: "443",
      path: "/",
    });
  });

  it("drops the query from the path", () => {
    expect(parseObservedUrl("https://example.com/pkg?q=1#frag")?.path).toBe("/pkg");
  });

  it("keeps an IPv6 literal whole", () => {
    expect(parseObservedUrl("https://[::1]:8443/x")).toStrictEqual({
      scheme: "https",
      host: "[::1]",
      port: "8443",
      path: "/x",
    });
  });

  it("returns null for anything that is not an http(s) URL", () => {
    expect(parseObservedUrl("docker-image://docker.io/library/alpine:latest")).toBe(null);
    expect(parseObservedUrl("example.com/x")).toBe(null);
  });
});
