/**
 * Property-based tests for proxy_engine resolution.
 *
 * Run with: vp test run src/lib/engine.property.test.ts
 */
import { describe, it, expect } from "vitest";
import fc from "fast-check";

import { resolveProxyEngine } from "./engine.ts";

const silent = () => {};

describe("resolveProxyEngine: properties", () => {
  it("always returns one of the three canonical engine names, or throws", () => {
    fc.assert(
      fc.property(fc.string({ minLength: 0, maxLength: 20 }), (input) => {
        let result;
        try {
          result = resolveProxyEngine(input, silent);
        } catch {
          return; // throwing is an acceptable outcome for invalid input
        }
        expect(["universal", "explicit", "inspect"]).toContain(result);
      }),
    );
  });

  it("is idempotent for its own valid outputs", () => {
    fc.assert(
      fc.property(fc.constantFrom("universal", "explicit", "inspect"), (engine) => {
        expect(resolveProxyEngine(resolveProxyEngine(engine, silent), silent)).toBe(engine);
      }),
    );
  });
});
