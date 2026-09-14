// haproxy.cfg.template isn't generated from INTERNAL_RANGES, so nothing
// keeps the two lists in sync automatically -- this catches drift.
import { describe, it, expect, reportResults } from "../test/test-shim.ts";
import { INTERNAL_RANGES } from "./haproxy-rules.ts";

const isNode = typeof (globalThis as { process?: unknown }).process !== "undefined";

/** The proxy's own address in the universal engine's CNI network (172.20.0.0/24). */
const PROXY_GATEWAY = "172.20.0.1";

async function readUniversalTemplate(): Promise<string> {
  if (isNode) {
    // Non-literal specifiers, same trick as test-shim.ts, so the qjs
    // tsconfig never tries to resolve Node's types for this branch.
    const fsSpecifier = "node:fs";
    const urlSpecifier = "node:url";
    const pathSpecifier = "node:path";
    const { readFileSync } = await import(fsSpecifier);
    const { fileURLToPath } = await import(urlSpecifier);
    const { dirname, join } = await import(pathSpecifier);
    const here = dirname(fileURLToPath(import.meta.url));
    return readFileSync(
      join(here, "../../../../docker/universal/files/haproxy.cfg.template"),
      "utf8",
    );
  }
  // Under qjs, tests run inside the actual universal engine image, which
  // has this same file at this same path.
  const stdSpecifier = "qjs:std";
  const std = await import(stdSpecifier);
  const f = std.open("/etc/haproxy/haproxy.cfg.template", "r");
  if (f === null) throw new Error("cannot open /etc/haproxy/haproxy.cfg.template");
  const content = f.readAsString();
  f.close();
  return content;
}

/** Every `acl <name> ...` line in the template, in order. */
function aclLines(template: string, aclName: string): string[] {
  return template.split("\n").filter((l) => l.trim().startsWith(`acl ${aclName} `));
}

/** The address list of one `acl dst_internal... var(...) -m ip <addrs>` line. */
function extractGuardAddresses(template: string, aclName: string): string[] {
  const line = aclLines(template, aclName)[0];
  if (line === undefined) {
    throw new Error(`template has no "acl ${aclName}" line`);
  }
  const marker = "-m ip ";
  const idx = line.indexOf(marker);
  if (idx === -1) {
    throw new Error(`"acl ${aclName}" line has no "-m ip" address list: ${line}`);
  }
  return line
    .slice(idx + marker.length)
    .trim()
    .split(/\s+/);
}

const TEMPLATE = await readUniversalTemplate();

describe("universal engine's internal-address guard stays in sync with INTERNAL_RANGES", () => {
  for (const aclName of ["dst_internal", "dst_internal_http"]) {
    it(`${aclName}'s address list is exactly INTERNAL_RANGES plus the proxy gateway`, () => {
      const addrs = extractGuardAddresses(TEMPLATE, aclName);
      const expected = [...INTERNAL_RANGES, PROXY_GATEWAY].slice().sort();
      expect(addrs.slice().sort()).toStrictEqual(expected);
    });

    it(`${aclName} is declared a second time against the runner's own addresses`, () => {
      // Declaring the name twice ORs the two, so the runner's addresses extend
      // the guard without lengthening the line above. Losing this line would
      // leave the whole of RFC1918 reachable again, silently.
      const lines = aclLines(TEMPLATE, aclName);
      expect(lines.length).toBe(2);
      expect(lines[1].includes("-m ip -f /etc/haproxy/rules/host_addrs.lst")).toBe(true);
      // Both declarations must judge the same thing to OR meaningfully.
      const fetchOf = (line: string) => line.trim().split(/\s+/)[2];
      expect(fetchOf(lines[1])).toBe(fetchOf(lines[0]));
    });
  }
});

describe("universal engine's log line is sized like the inspect engine's", () => {
  it("raises the line length haproxy would otherwise cut at 1024", () => {
    // The template is not generated, so haproxy-config.ts's own `len` says
    // nothing about this file. A cut line matches nothing the report knows.
    expect(TEMPLATE.includes("log stdout len 16384 format raw local0")).toBe(true);
  });
});

reportResults();
