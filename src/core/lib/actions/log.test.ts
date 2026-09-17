import { describe, it, expect, vi } from "vitest";
import { logRules, wrapLogGroup } from "./log.ts";

describe("logRules", () => {
  it("marks an empty rule list on the label line, so the block isn't silently blank", () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    logRules("Allowed HTTPS", []);
    expect(log.mock.calls.length).toBe(1);
    expect(log.mock.calls[0][0]).toBe("Allowed HTTPS rules: (none)");
  });

  it("logs one indented line per rule, in order, under a plain label line", () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    logRules("Allowed HTTPS", ["example.com:443", "*.example.org:443"]);
    expect(log.mock.calls.map((c) => c[0])).toStrictEqual([
      "Allowed HTTPS rules:",
      "  example.com:443",
      "  *.example.org:443",
    ]);
  });
});

describe("wrapLogGroup", () => {
  it("wraps non-empty log text in a group-open/content/group-close triple", () => {
    expect(wrapLogGroup("Title", "line1\nline2\n")).toStrictEqual([
      "::group::Title",
      "line1\nline2\n",
      "::endgroup::",
    ]);
  });

  it("returns an empty array for empty log text", () => {
    expect(wrapLogGroup("Title", "")).toStrictEqual([]);
  });
});
