import { describe, it, expect } from "vitest";

import { imageTagFromRef } from "./image-tag.ts";

describe("imageTagFromRef", () => {
  it("converts a 40-char hex SHA to sha-<sha>, lowercased", () => {
    expect(imageTagFromRef("a".repeat(40))).toBe(`sha-${"a".repeat(40)}`);
    const mixed = "ABCDEF1234".padEnd(40, "0");
    expect(imageTagFromRef(mixed)).toBe(`sha-${mixed.toLowerCase()}`);
  });

  it("strips a leading 'v' from a version, prerelease or major-only tag", () => {
    expect(imageTagFromRef("v2.1.0")).toBe("2.1.0");
    expect(imageTagFromRef("v3.1.6-rc1")).toBe("3.1.6-rc1");
    expect(imageTagFromRef("v2")).toBe("2");
  });

  it("returns a branch name as-is", () => {
    expect(imageTagFromRef("main")).toBe("main");
  });

  // With no ref there is no version to tag, so there is nothing for a suffix
  // to attach to: "-inspect" alone is not a tag any image is published under,
  // and asking the registry for it would be a lookup that cannot succeed.
  it("returns empty string with no ref, whether or not an engine is named", () => {
    expect(imageTagFromRef("")).toBe("");
    expect(imageTagFromRef(undefined)).toBe("");
    expect(imageTagFromRef("", "inspect")).toBe("");
    expect(imageTagFromRef(undefined, "inspect")).toBe("");
  });

  it("appends no suffix for the default (universal) engine, or when omitted", () => {
    expect(imageTagFromRef("v2.1.0", "universal")).toBe("2.1.0");
    expect(imageTagFromRef("v2.1.0")).toBe("2.1.0");
  });

  it("appends the inspect engine suffix when requested", () => {
    expect(imageTagFromRef("v2.1.0", "inspect")).toBe("2.1.0-inspect");
    expect(imageTagFromRef("a".repeat(40), "inspect")).toBe(`sha-${"a".repeat(40)}-inspect`);
  });

  it("gives every non-default engine its own suffix", () => {
    // A new engine is a separately published image, so forgetting the suffix
    // would silently pull the universal one.
    expect(imageTagFromRef("v2.1.0", "proxy")).toBe("2.1.0-proxy");
  });
});
