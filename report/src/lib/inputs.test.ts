import { describe, it, expect } from "vitest";

import { readBuilderName } from "./inputs.ts";
import { DEFAULT_BUILDER_NAME } from "#core/lib/docker/report-source.ts";

/** Stands in for core.getInput, which returns "" for anything unset. */
function inputs(values: Record<string, string> = {}): (name: string) => string {
  return (name) => values[name] ?? "";
}

describe("readBuilderName", () => {
  it("returns the input when set", () => {
    expect(readBuilderName(inputs({ builder_name: "mine" }))).toBe("mine");
  });

  // Report finds setup's container by the project name this derives to, so the
  // fallback has to be the same one setup used.
  it("falls back to the shared default when unset", () => {
    expect(readBuilderName(inputs())).toBe(DEFAULT_BUILDER_NAME);
  });

  it("treats an empty input as unset rather than as a builder named ''", () => {
    expect(readBuilderName(inputs({ builder_name: "" }))).toBe(DEFAULT_BUILDER_NAME);
  });
});
