import { describe, it, expect, reportResults } from "../test/test-shim.ts";
import { escapeForHaproxy, hostMatcher, pathMatcher } from "./haproxy-matchers.ts";

describe("host matching", () => {
  it("matches a literal name as a string, lowercased", () => {
    // txn.host is lowercased once per request, so -m str has to agree with
    // what -m reg -i would have accepted.
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
    // What a rule permitting any path compiles to.
    expect(pathMatcher("^/")).toStrictEqual({ op: "-m beg", pattern: "/" });
  });

  it("undoes the one escape a compiled pattern carries", () => {
    expect(pathMatcher("^/a\\.txt$")).toStrictEqual({ op: "-m str", pattern: "/a.txt" });
  });

  it("keeps a metacharacter on the regex engine", () => {
    // `+` means one or more to the regex engine and itself to -m str, so a ~
    // rule using it must not be narrowed.
    expect(pathMatcher("^/a+$")).toStrictEqual({ op: "-m reg", pattern: "^/a+$" });
  });

  it("keeps a pattern not starting at a slash on the regex engine", () => {
    // Narrowing would leave an empty pattern, which the config parser cannot
    // read.
    expect(pathMatcher("^$")).toStrictEqual({ op: "-m reg", pattern: "^$" });
  });
});

describe("config escaping", () => {
  it("escapes only what the word parser folds", () => {
    // A `#` would otherwise comment out the rest of the acl line, silently
    // shortening the pattern rather than failing.
    expect(escapeForHaproxy("^/pkg#frag$")).toBe("^/pkg\\#frag$");
    expect(escapeForHaproxy(`a b'c"d`)).toBe(`a\\ b\\'c\\"d`);
  });

  it("doubles a backslash rather than escaping what follows it", () => {
    expect(escapeForHaproxy("^a\\.com$")).toBe("^a\\\\.com$");
  });
});

reportResults();
