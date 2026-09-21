import { describe, it, expect, reportResults } from "../test/test-shim.ts";
import { inspectStage } from "./haproxy-inspect-stage.ts";
import { compileRuleSet, INTERNAL_RANGES, type RuleInputs } from "./haproxy-rules.ts";

/** The plaintext stage for these rules, as the generated config carries it. */
function plainStage(inputs: RuleInputs): string {
  return inspectStage(
    {
      name: "http_in",
      port: 10026,
      bindExtra: "",
      scheme: "http",
      rules: compileRuleSet(inputs).http,
      backend: "origin_plain",
    },
    { mode: "restrict", hasResolver: true, internalAddrs: INTERNAL_RANGES },
  ).join("\n");
}

describe("inspect stage", () => {
  it("refuses a request with no Host before it judges the path", () => {
    // Both are refusals, so only the reason turns on the order, and one of the
    // two names a host the report can act on where the other leaves the `-`
    // the log prints for a Host that never came. No rule is needed to see it:
    // both checks sit above the rule block whatever is written there.
    const plain = plainStage({});
    expect(plain.indexOf("missing-host-header") < plain.indexOf("path -m sub")).toBe(true);
  });

  it("writes nothing below a deny that carries no condition and so is final", () => {
    // HAProxy skips every http-request rule after an unconditional deny and
    // warns that they are NOOP. The resolver block is what would follow here.
    const plain = plainStage({ httpsRules: ["a.example.com:443"] });
    expect(plain.includes("# No rules for this scheme, so nothing is permitted.")).toBe(true);
    expect(plain.includes("do-resolve")).toBe(false);
    expect(plain.includes("acl dst_internal")).toBe(false);
  });
});

reportResults();
