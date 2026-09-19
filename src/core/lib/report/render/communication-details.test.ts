import { describe, it, expect } from "vitest";
import {
  renderCommunicationDetails,
  renderCommunicationDetailsBody,
} from "./communication-details.ts";
import { wrapCommunicationDetails as wrap } from "./communication-section.ts";

// No brackets in these two fixtures on purpose, so the non-escaping tests
// below don't need to reason about escaped output — bracket/asterisk/etc.
// escaping is covered separately in the "markdown escaping" tests.
const VERTEX_A = {
  command: "RUN echo no-network-here && mkdir -p /tmp/work",
  started: "2026-07-05T22:08:41.527Z",
  completed: "2026-07-05T22:08:41.670Z",
  entries: [],
};

const VERTEX_B = {
  command:
    "RUN echo step-A && wget -q -O /dev/null --timeout=5 https://allowed.example.com/ && echo A-done",
  started: "2026-07-05T22:08:41.670Z",
  completed: "2026-07-05T22:08:41.751Z",
  entries: [{ method: "GET", url: "https://allowed.example.com/", status: 200 }],
};

const ALLOWED_HEADER = "* **✅ Allowed Urls**\n\n";

/** A vertex item at the indent a lone build renders it at. */
const ITEM_A =
  "   * RUN echo no-network-here && mkdir -p /tmp/work\n\n" +
  "      (22:08:41Z · duration 0.143s)\n\n" +
  "      ```\n" +
  "      (no communication)\n" +
  "      ```\n\n";

const ITEM_B =
  "   * RUN echo step-A && wget -q -O /dev/null --timeout=5 https://allowed.example.com/ && echo A-done\n\n" +
  "      (22:08:41Z · duration 0.081s)\n\n" +
  "      ```\n" +
  "      - GET https://allowed.example.com/ -> 200\n" +
  "      ```\n\n";

const ALLOWED_A = ALLOWED_HEADER + ITEM_A;
const ALLOWED_B = ALLOWED_HEADER + ITEM_B;

const DENIED_ONE = [{ url: "https://blocked.example.com/", timestamp: "2026-07-05T22:08:41Z" }];
const BLOCKED_ONE = "* **🚫 Blocked Urls**\n\n   - (22:08:41Z) https://blocked.example.com/\n\n";

describe("renderCommunicationDetails", () => {
  it("renders nothing when neither side has anything to show", () => {
    expect(renderCommunicationDetails([], [])).toBe("");
    expect(renderCommunicationDetails(null, null)).toBe("");
    expect(renderCommunicationDetails(undefined, undefined)).toBe("");
    // A build whose vertex list is empty counts as no build at all.
    expect(renderCommunicationDetails([[]], [])).toBe("");
  });

  it("a vertex with no entries renders '(no communication)'", () => {
    expect(renderCommunicationDetails([[VERTEX_A]], [])).toBe(wrap(ALLOWED_A));
  });

  it("a vertex with an allowed entry renders the request line in a code block", () => {
    expect(renderCommunicationDetails([[VERTEX_B]], [])).toBe(wrap(ALLOWED_B));
  });

  it("an entry with no status omits the arrow", () => {
    const vertex = {
      ...VERTEX_B,
      entries: [{ method: "GET", url: "https://allowed.example.com/" }],
    };
    expect(renderCommunicationDetails([[vertex]], [])).toMatch(
      /- GET https:\/\/allowed\.example\.com\/\n/,
    );
  });

  it("renders multiple vertices within one build under one 'Allowed Urls' item, no build item", () => {
    const md = renderCommunicationDetails([[VERTEX_A, VERTEX_B]], []);
    expect(md.includes("Build")).toBe(false);
    expect(md).toBe(wrap(ALLOWED_HEADER + ITEM_A + ITEM_B));
  });

  it("adds a 'Build N' item per build, one level deeper, only when there is more than one build", () => {
    const md = renderCommunicationDetails([[VERTEX_A], [VERTEX_B]], []);
    expect(md.includes("   * Build 1\n\n      * RUN echo no-network-here")).toBe(true);
    expect(md.includes("   * Build 2\n\n      * RUN echo step-A")).toBe(true);
  });

  it("skips empty builds when deciding whether to show build items (only 1 non-empty build)", () => {
    const md = renderCommunicationDetails([[], [VERTEX_A], []], []);
    expect(md.includes("Build")).toBe(false);
  });

  it("renders the Blocked Urls section with whole-second timestamps, no vertex attribution", () => {
    expect(renderCommunicationDetails([], DENIED_ONE)).toBe(wrap(BLOCKED_ONE));
  });

  it("renders multiple Blocked Urls entries in the order given", () => {
    const deniedTimeline = [
      { url: "https://blocked.example.com/a", timestamp: "2026-07-05T22:08:41Z" },
      { url: "https://blocked.example.com/b", timestamp: "2026-07-05T22:08:42Z" },
    ];
    expect(renderCommunicationDetails([], deniedTimeline)).toBe(
      wrap(
        "* **🚫 Blocked Urls**\n\n   - (22:08:41Z) https://blocked.example.com/a\n   - (22:08:42Z) https://blocked.example.com/b\n\n",
      ),
    );
  });

  it("renders Allowed Urls before Blocked Urls", () => {
    expect(renderCommunicationDetails([[VERTEX_B]], DENIED_ONE)).toBe(
      wrap(ALLOWED_B + BLOCKED_ONE),
    );
  });

  describe("markdown escaping", () => {
    it("escapes every character that could alter rendering, in a command", () => {
      // One of each: the '[N/M]' step-counter prefix and a bracketed label
      // (link syntax), emphasis, a code span, raw HTML, and a backslash.
      const vertex = { ...VERTEX_A, command: "[2/2] RUN *a* _b_ `c` <d> \\e", entries: [] };
      const md = renderCommunicationDetails([[vertex]], []);
      expect(md).toContain("   * \\[2/2\\] RUN \\*a\\* \\_b\\_ \\`c\\` \\<d\\> \\\\e\n\n");
    });

    it("escapes special characters in an allowed request's URL inside the code block", () => {
      const vertex = {
        ...VERTEX_A,
        entries: [{ method: "GET", url: "https://allowed.example.com/[id]", status: 200 }],
      };
      const md = renderCommunicationDetails([[vertex]], []);
      expect(md).toMatch(/- GET https:\/\/allowed\.example\.com\/\\\[id\\\] -> 200/);
    });

    it("escapes special characters in a denied URL", () => {
      const deniedTimeline = [
        { url: "https://blocked.example.com/[id]", timestamp: "2026-07-05T22:08:41Z" },
      ];
      const md = renderCommunicationDetails([], deniedTimeline);
      expect(md).toMatch(/- \(22:08:41Z\) https:\/\/blocked\.example\.com\/\\\[id\\\]/);
    });

    it("does not escape '.' or '-', which are common and harmless in URLs/commands", () => {
      const vertex = { ...VERTEX_A, command: "RUN echo hello-world.txt", entries: [] };
      const md = renderCommunicationDetails([[vertex]], []);
      expect(md).toMatch(/\* RUN echo hello-world\.txt\n/);
    });
  });
});

describe("renderCommunicationDetailsBody", () => {
  // The job log renders <details>/<summary> as literal text, so this variant
  // exists to leave them off; report-action.node.ts hands its result to
  // wrapLogGroup, which emits no ::group:: at all when handed "".
  it("renders nothing at all when there is nothing to show", () => {
    expect(renderCommunicationDetailsBody([], [])).toBe("");
    expect(renderCommunicationDetailsBody(null, null)).toBe("");
  });

  it("is the same content with no <details> wrapper around it", () => {
    const body = renderCommunicationDetailsBody([[VERTEX_B]], DENIED_ONE);
    expect(body).toBe(ALLOWED_B + BLOCKED_ONE);
    expect(renderCommunicationDetails([[VERTEX_B]], DENIED_ONE)).toBe(wrap(body));
  });
});
