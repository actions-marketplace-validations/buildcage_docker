import { describe, it, expect, reportResults } from "../test/test-shim.ts";
import { escapeForHaproxy, hostMatcher, pathMatcher } from "./haproxy-matchers.ts";

describe("host matching", () => {
  it("matches a literal name as a string, lowercased", () => {
    expect(hostMatcher("^Example\\.com$")).toStrictEqual({ op: "-m str", pattern: "example.com" });
  });

  it("keeps a wildcard on the regex engine", () => {
    expect(hostMatcher("^.*\\.example\\.com$")).toStrictEqual({
      op: "-m reg -i",
      pattern: "^.*\\.example\\.com$",
    });
  });

  it("keeps a pattern with no end anchor on the regex engine", () => {
    // A ~ rule carries the author's own regex, which need not be anchored.
    expect(hostMatcher("^example\\.com")).toStrictEqual({
      op: "-m reg -i",
      pattern: "^example\\.com",
    });
  });
});

describe("path matching", () => {
  it("matches an exact path as a string", () => {
    expect(pathMatcher("^/a/b$")).toStrictEqual({ op: "-m str", pattern: "/a/b" });
  });

  it("matches an explicit prefix by its beginning", () => {
    expect(pathMatcher("^/a/.*$")).toStrictEqual({ op: "-m beg", pattern: "/a/" });
  });

  it("matches an unanchored prefix by its beginning", () => {
    expect(pathMatcher("^/")).toStrictEqual({ op: "-m beg", pattern: "/" });
  });

  it("undoes the one escape a compiled pattern carries", () => {
    expect(pathMatcher("^/a\\.txt$")).toStrictEqual({ op: "-m str", pattern: "/a.txt" });
  });

  it("keeps a metacharacter on the regex engine", () => {
    expect(pathMatcher("^/a+$")).toStrictEqual({ op: "-m reg", pattern: "^/a+$" });
  });

  it("keeps a pattern not starting at a slash on the regex engine", () => {
    expect(pathMatcher("^$")).toStrictEqual({ op: "-m reg", pattern: "^$" });
  });
});

describe("config escaping", () => {
  it("escapes only what the word parser folds", () => {
    expect(escapeForHaproxy("^/pkg#frag$")).toBe("^/pkg\\#frag$");
    expect(escapeForHaproxy(`a b'c"d`)).toBe(`a\\ b\\'c\\"d`);
  });

  it("doubles a backslash rather than escaping what follows it", () => {
    expect(escapeForHaproxy("^a\\.com$")).toBe("^a\\\\.com$");
  });
});

reportResults();
