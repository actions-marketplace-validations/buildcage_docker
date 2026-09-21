// The proxy writes these lines and this parser reads them, with nothing else
// holding the two together: a field moved on one side and not the other leaves
// a report that says the build reached nothing at all.
import { describe, it, expect } from "vitest";
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

/** Long enough that the rendered line runs past haproxy's own 1024-byte default. */
const PATH = `/pkg.tgz?token=${"a".repeat(1200)}`;

/** One representative value per log-format token. A token with no value here
 *  throws, so a new field cannot quietly go uncovered. */
const SAMPLES: Record<string, string> = {
  "%[date(0,ms)]": "1787471975123",
  "%HM": "GET",
  "%ST": "200",
  "%B": "708",
  "%ts": "--",
  "%[var(txn.reason)]": "-",
  "%[dst]": "10.200.0.100",
  "%[dst_port]": "9443",
  "%[capture.req.hdr(0)]": "registry.npmjs.org",
  "%[var(txn.pathq)]": PATH,
  "%[var(txn.proto)]": "tls",
  "%[var(txn.sni)]": "db.example.com",
  "%[ssl_fc_sni,regsub([^A-Za-z0-9._-],_,g)]": "registry.npmjs.org",
};

// The inner alternative is the character class a regsub argument carries, so
// the `]` closing it does not end the token.
const TOKEN = /%(?:\[(?:[^[\]]|\[[^[\]]*\])*\]|[A-Za-z]+)/g;

/** The log-format strings the generator emits, unquoted, in config order. */
function logFormats(config: string): string[] {
  return config
    .split("\n")
    .filter((line) => line.includes('log-format "buildcage'))
    .map((line) => line.slice(line.indexOf('"') + 1, line.lastIndexOf('"')));
}

function render(
  format: string,
  overrides: Record<string, string> = {},
  named: { reason?: string } = {},
): string {
  const all =
    named.reason === undefined ? overrides : { ...overrides, "%[var(txn.reason)]": named.reason };
  return format.replace(TOKEN, (token) => {
    const sample = all[token] ?? SAMPLES[token];
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
    // Guards the sample itself, which has to reach past the default line length.
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

  it("reads a refusal the config named out of the reason field", async () => {
    const line = render(
      HTTPS,
      { "%ts": "PR--", "%ST": "403", "%B": "0" },
      { reason: "internal-address" },
    );
    const [e] = (await scanInspectLog([line])).events;
    expect(e.action).toBe("block");
    expect(e.reason).toBe("internal-address");
    expect(e.status === undefined).toBe(true);
  });

  it("reads an upstream resolution failure as failed, not as a refusal", async () => {
    const line = render(
      HTTPS,
      { "%ts": "PR--", "%ST": "502", "%B": "0" },
      { reason: "dns-failed" },
    );
    const [e] = (await scanInspectLog([line])).events;
    expect(e.action).toBe("failed");
    expect(e.reason).toBe("dns-failed");
    expect(e.status === undefined).toBe(true);
  });

  it("names a failure the config left unnamed from the termination phase", async () => {
    const line = render(HTTPS, { "%ts": "SH--", "%ST": "502", "%B": "0" });
    const [e] = (await scanInspectLog([line])).events;
    expect(e.action).toBe("failed");
    expect(e.reason).toBe("origin-no-response");
  });

  // What a client that finished the handshake and then left produces, and what
  // bytes haproxy could not read as a request produce too: with no request to
  // log, every field one would have comes out empty.
  const NO_REQUEST = {
    "%HM": "<BADREQ>",
    "%ST": "400",
    "%B": "0",
    "%[capture.req.hdr(0)]": "-",
    "%[var(txn.pathq)]": "-",
  };

  it("takes the host of a connection closed before its request from the SNI", async () => {
    const line = render(HTTPS, { ...NO_REQUEST, "%ts": "CR" });
    const [e] = (await scanInspectLog([line])).events;
    expect(e.action).toBe("incomplete");
    expect(e.host).toBe("registry.npmjs.org");
    expect(e.port).toBe(9443);
    expect(e.reason).toBe("client-aborted");
    expect(e.destination).toBe("10.200.0.100:9443");
    expect(e.method === undefined).toBe(true);
    expect(e.url === undefined).toBe(true);
    expect(e.status === undefined).toBe(true);
  });

  it("tells a client that closed from one that waited out its own timeout", async () => {
    const line = render(HTTPS, { ...NO_REQUEST, "%ts": "cR", "%ST": "408" });
    const [e] = (await scanInspectLog([line])).events;
    expect(e.action).toBe("incomplete");
    expect(e.reason).toBe("client-timeout");
  });

  it("reads haproxy's own 400 as a request it could not act on", async () => {
    const line = render(HTTPS, { ...NO_REQUEST, "%ts": "PR" });
    const [e] = (await scanInspectLog([line])).events;
    expect(e.action).toBe("incomplete");
    expect(e.host).toBe("registry.npmjs.org");
    expect(e.reason).toBe("bad-request");
    expect(e.url === undefined).toBe(true);
  });

  it("reads a request that carried no Host the same way, path and all", async () => {
    const line = render(HTTPS, {
      "%ST": "403",
      "%B": "0",
      "%ts": "PR",
      "%[capture.req.hdr(0)]": "-",
    });
    const [e] = (await scanInspectLog([line])).events;
    expect(e.action).toBe("incomplete");
    expect(e.reason).toBe("bad-request");
    expect(e.method === undefined).toBe(true);
  });

  it("leaves a refusal whose sender chose a hyphen-leading Host a block", async () => {
    // The capture rewrites only whitespace, quotes and control characters, so
    // a Host of the build's own choosing reaches the log as sent. Reading the
    // leading `-` alone would let it move its own refusals out of both tables
    // and out of fail_on_blocked.
    const line = render(HTTPS, {
      "%ST": "403",
      "%B": "0",
      "%ts": "PR",
      "%[capture.req.hdr(0)]": "-evil.example.com",
    });
    const [e] = (await scanInspectLog([line])).events;
    expect(e.action).toBe("block");
    expect(e.host).toBe("-evil.example.com");
  });

  it("overrides the reason the config named, audit resolving that host to nothing", async () => {
    // audit enforces nothing, so a missing Host reaches do-resolve, which has
    // no name to look up and lands on dns-failed. Reporting that would blame
    // the SNI's own name for failing to resolve.
    const line = render(
      HTTPS,
      { "%ST": "502", "%B": "0", "%ts": "PR", "%[capture.req.hdr(0)]": "-" },
      { reason: "dns-failed" },
    );
    const [e] = (await scanInspectLog([line], true)).events;
    expect(e.action).toBe("incomplete");
    expect(e.reason).toBe("bad-request");
  });

  it("leaves a phase R neither the client nor this proxy ended an ordinary exchange", async () => {
    // `RR` is haproxy running out of a resource while reading the request:
    // its own doing, but not a decision, so it names no reason of the three.
    const line = render(HTTPS, { ...NO_REQUEST, "%ts": "RR" });
    const [e] = (await scanInspectLog([line])).events;
    expect(e.action === "incomplete").toBe(false);
  });

  it("falls back to the address when the handshake carried no SNI", async () => {
    // A name-based client always sends one, so a handshake without it was
    // aimed at an address the build wrote out itself.
    const line = render(HTTPS, {
      ...NO_REQUEST,
      "%ts": "CR",
      "%[ssl_fc_sni,regsub([^A-Za-z0-9._-],_,g)]": "-",
    });
    const [e] = (await scanInspectLog([line])).events;
    expect(e.host).toBe("10.200.0.100");
  });

  it("names no host at all on the plain stage, which logs no SNI to fall back on", async () => {
    const line = render(HTTP, { ...NO_REQUEST, "%ts": "CR" });
    const { events, unparsed } = await scanInspectLog([line]);
    expect(unparsed).toBe(0);
    const [e] = events;
    expect(e.action).toBe("incomplete");
    expect(e.protocol).toBe("http");
    expect(e.host).toBe("(unknown)");
    // The address is still recorded; it is just not a host the build asked for.
    expect(e.destination).toBe("10.200.0.100:9443");
  });

  it("leaves a client that abandoned an allowed request an ordinary exchange", async () => {
    const line = render(HTTPS, { "%ts": "CD--" });
    const [e] = (await scanInspectLog([line])).events;
    expect(e.action).toBe("allow");
    expect(e.url).toBe(`https://registry.npmjs.org${PATH}`);
  });

  it("names a passthrough refusal the same way, though it has no status at all", async () => {
    const line = render(PASSTHROUGH, { "%ts": "PR", "%B": "0" }, { reason: "internal-address" });
    const [e] = (await scanInspectLog([line])).events;
    expect(e.action).toBe("block");
    expect(e.reason).toBe("internal-address");
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
