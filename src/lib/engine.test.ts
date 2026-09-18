import { describe, it, expect, vi } from "vitest";

import { resolveProxyEngine } from "./engine.ts";

const silent = () => {};

describe("resolveProxyEngine", () => {
  it("defaults to universal for undefined", () => {
    expect(resolveProxyEngine(undefined, silent)).toBe("universal");
  });

  it("defaults to universal for empty string", () => {
    expect(resolveProxyEngine("", silent)).toBe("universal");
  });

  it("accepts universal explicitly", () => {
    expect(resolveProxyEngine("universal", silent)).toBe("universal");
  });

  it("accepts explicit", () => {
    expect(resolveProxyEngine("explicit", silent)).toBe("explicit");
  });

  it("accepts inspect", () => {
    expect(resolveProxyEngine("inspect", silent)).toBe("inspect");
  });

  it("throws SetupError for an invalid value", () => {
    expect(() => resolveProxyEngine("restrict", silent)).toThrow();
  });

  it("throws SetupError for a value with different casing (case-sensitive)", () => {
    expect(() => resolveProxyEngine("Explicit", silent)).toThrow();
  });

  // `transparent` is universal's old name, kept working permanently as an
  // alias — see ENGINE_ALIASES.
  describe("the transparent alias", () => {
    it("resolves transparent to universal", () => {
      expect(resolveProxyEngine("transparent", silent)).toBe("universal");
    });

    it("points at the new name", () => {
      const notice = vi.fn();

      resolveProxyEngine("transparent", notice);

      expect(notice).toHaveBeenCalledWith(
        expect.stringContaining("proxy_engine: transparent is now called universal"),
      );
      expect(notice).toHaveBeenCalledWith(
        expect.stringContaining("updating to proxy_engine: universal"),
      );
    });

    it("says nothing for any other value", () => {
      const notice = vi.fn();

      resolveProxyEngine("universal", notice);
      resolveProxyEngine("explicit", notice);
      resolveProxyEngine("inspect", notice);

      expect(notice).not.toHaveBeenCalled();
    });

    it("no longer appears in the invalid-value error's accepted list", () => {
      expect(() => resolveProxyEngine("restrict", silent)).toThrowError(
        /universal, explicit, inspect/,
      );
    });
  });
});
