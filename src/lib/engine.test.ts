import { describe, it, expect, vi } from "vitest";

import { resolveProxyEngine } from "./engine.ts";

const silent = () => {};

describe("resolveProxyEngine", () => {
  it("defaults to universal for undefined or an empty string", () => {
    expect(resolveProxyEngine(undefined, silent)).toBe("universal");
    expect(resolveProxyEngine("", silent)).toBe("universal");
  });

  it("accepts each engine that has an image of its own", () => {
    expect(resolveProxyEngine("universal", silent)).toBe("universal");
    expect(resolveProxyEngine("explicit", silent)).toBe("explicit");
    expect(resolveProxyEngine("inspect", silent)).toBe("inspect");
  });

  it("throws SetupError for a value that is not an engine, casing included", () => {
    expect(() => resolveProxyEngine("restrict", silent)).toThrow();
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
