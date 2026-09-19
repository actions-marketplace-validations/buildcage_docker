import { describe, it, expect } from "vitest";
import fc from "fast-check";

import { imageTagFromRef } from "./image-tag.ts";

// `universal` (the default) publishes the plain tag; every other engine
// appends `-<engine>`. These properties exercise `explicit`.
const suffixFor = (engine: string) => (engine === "explicit" ? "-explicit" : "");

describe("imageTagFromRef: properties", () => {
  it("40-char hex SHA always produces sha-<lowercase sha>, suffixed only for explicit", () => {
    fc.assert(
      fc.property(
        fc.stringMatching(/^[0-9a-fA-F]{40}$/),
        fc.constantFrom("universal", "explicit"),
        (sha, engine) => {
          expect(imageTagFromRef(sha, engine)).toBe(`sha-${sha.toLowerCase()}${suffixFor(engine)}`);
        },
      ),
    );
  });

  it("v-prefixed ref always strips the leading v, suffixed only for explicit", () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1 }).map((s) => `v${s}`),
        fc.constantFrom("universal", "explicit"),
        (ref, engine) => {
          expect(imageTagFromRef(ref, engine)).toBe(`${ref.slice(1)}${suffixFor(engine)}`);
        },
      ),
    );
  });

  // Leading 'g' is not a hex char and not 'v', so this always hits the passthrough branch.
  it("non-SHA non-v-prefixed ref always passes through unchanged, suffixed only for explicit", () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 0, maxLength: 50 }).map((s) => `g${s}`),
        fc.constantFrom("universal", "explicit"),
        (ref, engine) => {
          expect(imageTagFromRef(ref, engine)).toBe(`${ref}${suffixFor(engine)}`);
        },
      ),
    );
  });

  it("defaults to no suffix (universal) when no engine is given", () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 0, maxLength: 50 }).map((s) => `g${s}`),
        (ref) => {
          expect(imageTagFromRef(ref)).toBe(ref);
        },
      ),
    );
  });
});
