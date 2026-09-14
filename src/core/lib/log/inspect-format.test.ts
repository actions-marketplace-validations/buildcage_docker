// The proxy writes these lines and this parser reads them, but nothing else
// holds the two together: a field moved on one side and not the other leaves a
// report that says a build reached nothing at all. This renders the log-format
// the generator actually emits and reads it back with the parser the report
// actually uses, so the two can only drift by failing here first.
import { describe, it, expect, reportResults } from "../test/test-shim.ts";
import { generateHaproxyConfig } from "../acl/haproxy-config.ts";
import { scanInspectLog } from "./inspect.ts";

const OPTIONS = {
  httpsRules: ["registry.npmjs.org:443"],
  httpRules: ["b.example.com:80"],
  ipRules: ["10.0.0.5:5432"],
  tlsRules: ["db.example.com:443"],
  resolverAddress: ["1.1.1.1"],
  proxyAddress: "172.20.0.1",
};

/** Long enough that the rendered line passes haproxy's own 1024-byte default,
 *  which is the length that used to lose the event entirely. */
const PATH = `/pkg.tgz?token=${"a".repeat(1200)}`;

/** One representative value per log-format token. A token with no value here
 *  throws rather than rendering blank: a new field has to be given a sample,
 *  or this test would quietly stop covering the line it appears on. */
const SAMPLES: Record<string, string> = {
  "%[date(0,ms)]": "1787471975123",
  "%HM": "GET",
  "%ST": "200",
  "%B": "708",
  "%ts": "--",
  "%[dst]": "10.200.0.100",
  "%[dst_port]": "9443",
  "%[capture.req.hdr(0)]": "registry.npmjs.org",
  "%[var(txn.pathq)]": PATH,
  "%[var(txn.proto)]": "tls",
  "%[var(txn.sni)]": "db.example.com",
};

const TOKEN = /%(?:\[[^\]]*\]|[A-Za-z]+)/g;

/** The log-format strings the generator emits, unquoted, in config order. */
function logFormats(config: string): string[] {
  return config
    .split("\n")
    .filter((line) => line.includes('log-format "buildcage'))
    .map((line) => line.slice(line.indexOf('"') + 1, line.lastIndexOf('"')));
}

function render(format: string, overrides: Record<string, string> = {}): string {
  return format.replace(TOKEN, (token) => {
    const sample = overrides[token] ?? SAMPLES[token];
    if (sample === undefined) throw new Error(`log-format token with no sample: ${token}`);
    return sample;
  });
}

const FORMATS = logFormats(generateHaproxyConfig(OPTIONS).config);
const [PASSTHROUGH, HTTPS, HTTP] = [
  FORMATS.find((f) => f.includes(" pass ")) ?? "",
  FORMATS.find((f) => f.includes(" https ")) ?? "",
  FORMATS.find((f) => f.includes(" http ")) ?? "",
];

describe("the generated log-format and this parser describe the same line", () => {
  it("emits one format per frontend that logs", () => {
    expect(FORMATS.length).toBe(3);
    expect(PASSTHROUGH === "").toBe(false);
    expect(HTTPS === "").toBe(false);
    expect(HTTP === "").toBe(false);
  });

  it("reads every field of a request line back out of where it was written", async () => {
    const line = render(HTTPS);
    // Guards the sample itself: a shorter path would not reach the length that
    // broke this in the first place.
    expect(line.length > 1024).toBe(true);

    const { events, unparsed } = await scanInspectLog([line]);
    expect(unparsed).toBe(0);
    expect(events.length).toBe(1);
    const [e] = events;
    expect(e.time).toBe(1787471975.123);
    expect(e.action).toBe("allow");
    expect(e.protocol).toBe("https");
    expect(e.method).toBe("GET");
    expect(e.host).toBe("registry.npmjs.org");
    expect(e.port).toBe(9443);
    expect(e.status).toBe(200);
    expect(e.bytes).toBe(708);
    expect(e.destination).toBe("10.200.0.100:9443");
    expect(e.url).toBe(`https://registry.npmjs.org${PATH}`);
  });

  it("reads a plain request line the same way", async () => {
    const [e] = (await scanInspectLog([render(HTTP)])).events;
    expect(e.protocol).toBe("http");
    expect(e.url).toBe(`http://registry.npmjs.org${PATH}`);
    expect(e.status).toBe(200);
  });

  it("reads our own refusal out of the termination state, not the status", async () => {
    const line = render(HTTPS, { "%ts": "PR", "%ST": "403", "%B": "0" });
    const [e] = (await scanInspectLog([line])).events;
    expect(e.action).toBe("block");
    expect(e.reason).toBe("not-allowed");
    expect(e.status === undefined).toBe(true);
  });

  it("reads every field of a passthrough line, which has no request in it", async () => {
    const { events, unparsed } = await scanInspectLog([render(PASSTHROUGH)]);
    expect(unparsed).toBe(0);
    const [e] = events;
    expect(e.protocol).toBe("tls");
    expect(e.host).toBe("db.example.com");
    expect(e.port).toBe(9443);
    expect(e.bytes).toBe(708);
    expect(e.destination).toBe("10.200.0.100:9443");
    expect(e.url === undefined).toBe(true);
  });

  it("refuses to render a field it has never been shown", () => {
    expect(() => render("buildcage %[var(txn.unknown)]")).toThrow("no sample");
  });
});

reportResults();
