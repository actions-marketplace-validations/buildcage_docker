/**
 * Unit tests for core/lib/report/render/restrict-example.ts
 *
 * The `uses:` line and the <details> block every engine's "Switch to restrict
 * mode" snippet is built around. Each renderer's own tests assert the YAML it
 * puts inside; these assert the frame, so no renderer's tests have to.
 */
import { describe, it, expect } from "vitest";
import { restrictExampleBlock, usesLine } from "./restrict-example.ts";

const REPO = "owner/repo";

describe("usesLine", () => {
  it("writes the ref as given, tag or commit sha alike", () => {
    const sha = "a".repeat(40);
    expect(usesLine(REPO, "v2")).toBe(`  uses: ${REPO}@v2\n`);
    expect(usesLine(REPO, "v2.1.0")).toBe(`  uses: ${REPO}@v2.1.0\n`);
    expect(usesLine(REPO, sha)).toBe(`  uses: ${REPO}@${sha}\n`);
  });

  it("appends the resolved version as a trailing comment, and nothing when it is unknown", () => {
    expect(usesLine(REPO, "v2", "3.1.4")).toBe(`  uses: ${REPO}@v2 # 3.1.4\n`);
    expect(usesLine(REPO, "v2", undefined)).toBe(`  uses: ${REPO}@v2\n`);
    expect(usesLine(REPO, "v2", "")).toBe(`  uses: ${REPO}@v2\n`);
  });
});

describe("restrictExampleBlock", () => {
  it("wraps the yaml in the collapsed section, at the step indent Actions expects", () => {
    // A blank line stays blank: trailing spaces on it would show in the fence.
    expect(restrictExampleBlock("- name: Start\n  with:\n\n    x: 1\n")).toBe(
      "\n<details>\n" +
        "<summary>🛡️ Switch to restrict mode</summary>\n\n" +
        "```yaml\n" +
        "      - name: Start\n" +
        "        with:\n" +
        "\n" +
        "          x: 1\n" +
        "```\n\n" +
        "</details>\n",
    );
  });

  it("renders a footnote as small print under the fence when one is given", () => {
    expect(restrictExampleBlock("x\n", { footnote: "only the host is checked" })).toContain(
      "```\n\n<sub>*only the host is checked*</sub>\n\n</details>\n",
    );
  });
});
