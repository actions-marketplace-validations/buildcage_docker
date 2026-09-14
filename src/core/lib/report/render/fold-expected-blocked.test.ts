import { describe, it, expect, reportResults } from "#core/lib/test/test-shim.ts";
import { foldExpectedBlockedRows } from "./fold-expected-blocked.ts";
import type { HostTableRow } from "./host-table.ts";

describe("foldExpectedBlockedRows", () => {
  const row = (overrides: Partial<HostTableRow> = {}): HostTableRow => ({
    host: "a.sury.org",
    port: "-",
    ruleType: "DNS",
    reason: "dns-not-allowed",
    count: 1,
    expected: true,
    expectedBy: "*.sury.org:*",
    ...overrides,
  });

  it("folds the rows one rule matched into a single row", () => {
    const folded = foldExpectedBlockedRows([
      row({ host: "a.sury.org", count: 2 }),
      row({ host: "b.sury.org", count: 3 }),
    ]);
    expect(folded.length).toBe(1);
    expect(folded[0].display).toBe("*.sury.org:* (2 hosts)");
    expect(folded[0].count).toBe(5);
    expect(folded[0].expected).toBe(true);
  });

  it("keeps the rule type and reason of the rows it folded", () => {
    const folded = foldExpectedBlockedRows([row(), row({ host: "b.sury.org" })]);
    expect(folded[0].ruleType).toBe("DNS");
    expect(folded[0].reason).toBe("dns-not-allowed");
  });

  it("says host, not hosts, when the rule matched only one", () => {
    expect(foldExpectedBlockedRows([row()])[0].display).toBe("*.sury.org:* (1 host)");
  });

  it("counts one host blocked on two ports once", () => {
    const folded = foldExpectedBlockedRows([
      row({ port: "443", ruleType: "HTTPS", reason: "https-not-allowed" }),
      row({ port: "8443", ruleType: "HTTPS", reason: "https-not-allowed" }),
    ]);
    expect(folded[0].display).toBe("*.sury.org:* (1 host)");
    expect(folded[0].count).toBe(2);
  });

  it("splits one rule's rows by rule type and reason", () => {
    const folded = foldExpectedBlockedRows([
      row(),
      row({ host: "b.sury.org", port: "443", ruleType: "HTTPS", reason: "https-not-allowed" }),
    ]);
    expect(folded.length).toBe(2);
    expect(folded.map((r) => r.ruleType).sort()).toStrictEqual(["DNS", "HTTPS"]);
  });

  it("keeps a row no rule matched as it is, ahead of the folded ones", () => {
    const unmatched = row({ host: "evil.example.com", expected: false, expectedBy: undefined });
    const folded = foldExpectedBlockedRows([row(), unmatched]);
    expect(folded[0]).toStrictEqual(unmatched);
    expect(folded[1].display).toBe("*.sury.org:* (1 host)");
  });

  it("preserves the order of the rows no rule matched", () => {
    const first = row({
      host: "first.example.com",
      count: 9,
      expected: false,
      expectedBy: undefined,
    });
    const second = row({
      host: "second.example.com",
      count: 4,
      expected: false,
      expectedBy: undefined,
    });
    const folded = foldExpectedBlockedRows([first, second]);
    expect(folded.map((r) => r.host)).toStrictEqual(["first.example.com", "second.example.com"]);
  });

  it("orders folded rows by total count, then by rule", () => {
    const folded = foldExpectedBlockedRows([
      row({ expectedBy: "*.quiet.example:*", count: 1 }),
      row({ expectedBy: "*.sury.org:*", count: 4 }),
      row({ expectedBy: "*.noisy.example:*", count: 1 }),
    ]);
    expect(folded.map((r) => r.expectedBy)).toStrictEqual([
      "*.sury.org:*",
      "*.noisy.example:*",
      "*.quiet.example:*",
    ]);
  });

  it("returns nothing for no rows", () => {
    expect(foldExpectedBlockedRows([])).toStrictEqual([]);
  });
});

reportResults();
