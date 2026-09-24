import { describe, it, expect } from "vitest";

import { resolveProxyEngine } from "./engine.ts";

describe("resolveProxyEngine", () => {
  it("defaults to inspect for undefined or an empty string", () => {
    expect(resolveProxyEngine(undefined)).toBe("inspect");
    expect(resolveProxyEngine("")).toBe("inspect");
  });

  it("accepts each engine that has an image of its own", () => {
    expect(resolveProxyEngine("universal")).toBe("universal");
    expect(resolveProxyEngine("inspect")).toBe("inspect");
  });

  it("throws SetupError for a value that is not an engine, casing included", () => {
    expect(() => resolveProxyEngine("restrict")).toThrow();
    expect(() => resolveProxyEngine("Explicit")).toThrow();
  });

  it("rejects the removed explicit engine, naming the supported replacements", () => {
    expect(() => resolveProxyEngine("explicit")).toThrowError(
      /explicit has been removed.*universal.*inspect/s,
    );
  });

  it("rejects the removed transparent alias, naming its new name", () => {
    expect(() => resolveProxyEngine("transparent")).toThrowError(
      /transparent has been renamed.*proxy_engine: universal/,
    );
  });
});
