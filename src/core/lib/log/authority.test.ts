import { describe, it, expect } from "vitest";

import { DEFAULT_PORT, splitHostPort } from "./authority.ts";

describe("splitHostPort", () => {
  it("splits a plain host:port", () => {
    expect(splitHostPort("example.com:443")).toStrictEqual({ host: "example.com", port: "443" });
  });

  // undefined, not "": the callers that substitute a scheme's default port
  // only want to do so when none was written at all.
  it("reports no port as undefined", () => {
    expect(splitHostPort("example.com")).toStrictEqual({ host: "example.com", port: undefined });
  });

  it("reports a trailing colon as a present but empty port", () => {
    expect(splitHostPort("example.com:")).toStrictEqual({ host: "example.com", port: "" });
  });

  it("splits at the last colon, so a port always wins over anything before it", () => {
    expect(splitHostPort("a:b:443")).toStrictEqual({ host: "a:b", port: "443" });
  });

  it("splits an IPv4 address the same way", () => {
    expect(splitHostPort("10.0.0.5:5432")).toStrictEqual({ host: "10.0.0.5", port: "5432" });
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
    // one is not a separator. Reading it as one would give host "[:" and
    // port "1]", which is what each of these call sites used to do.
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

  it("handles an empty authority", () => {
    expect(splitHostPort("")).toStrictEqual({ host: "", port: undefined });
  });
});

describe("DEFAULT_PORT", () => {
  it("knows the two schemes buildcage proxies", () => {
    expect(DEFAULT_PORT.https).toBe("443");
    expect(DEFAULT_PORT.http).toBe("80");
  });
});
