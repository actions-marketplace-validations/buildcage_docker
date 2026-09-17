import { describe, it, expect, vi } from "vitest";

import { resolveProxyEngine } from "./engine.ts";

describe("resolveProxyEngine", () => {
  it("defaults to universal for undefined", () => {
    expect(resolveProxyEngine(undefined)).toBe("universal");
  });

  it("defaults to universal for empty string", () => {
    expect(resolveProxyEngine("")).toBe("universal");
  });

  it("accepts universal explicitly", () => {
    expect(resolveProxyEngine("universal")).toBe("universal");
  });

  it("accepts explicit", () => {
    expect(resolveProxyEngine("explicit")).toBe("explicit");
  });

  it("accepts inspect", () => {
    expect(resolveProxyEngine("inspect")).toBe("inspect");
  });

  it("throws SetupError for an invalid value", () => {
    expect(() => resolveProxyEngine("restrict")).toThrow();
  });

  it("throws SetupError for a value with different casing (case-sensitive)", () => {
    expect(() => resolveProxyEngine("Explicit")).toThrow();
  });

  // `transparent` is universal's old name, kept working permanently as an
  // alias — see ENGINE_ALIASES.
  describe("the transparent alias", () => {
    it("resolves transparent to universal", () => {
      const log = vi.spyOn(console, "log").mockImplementation(() => {});
      try {
        expect(resolveProxyEngine("transparent")).toBe("universal");
      } finally {
        log.mockRestore();
      }
    });

    it("prints a ::notice:: pointing at the new name", () => {
      const log = vi.spyOn(console, "log").mockImplementation(() => {});
      try {
        resolveProxyEngine("transparent");
        expect(log).toHaveBeenCalledWith(expect.stringContaining("::notice::"));
        expect(log).toHaveBeenCalledWith(expect.stringContaining("proxy_engine: transparent"));
        expect(log).toHaveBeenCalledWith(expect.stringContaining("proxy_engine: universal"));
      } finally {
        log.mockRestore();
      }
    });

    it("does not print a notice for any other value", () => {
      const log = vi.spyOn(console, "log").mockImplementation(() => {});
      try {
        resolveProxyEngine("universal");
        resolveProxyEngine("explicit");
        resolveProxyEngine("inspect");
        expect(log).not.toHaveBeenCalled();
      } finally {
        log.mockRestore();
      }
    });

    it("no longer appears in the invalid-value error's accepted list", () => {
      expect(() => resolveProxyEngine("restrict")).toThrowError(/universal, explicit, inspect/);
    });
  });
});
