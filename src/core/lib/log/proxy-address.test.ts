import { readFileSync } from "node:fs";
import { describe, it, expect } from "vitest";
import { PROXY_ADDRESS } from "./proxy-address.ts";

/** A file that declares the inspect engine's gateway and cannot import
 *  PROXY_ADDRESS. Changing one without this would make the parser name every
 *  name-based connection by an address that is not the one it lands on. */
const read = (relative: string) => readFileSync(new URL(relative, import.meta.url), "utf8");

describe("PROXY_ADDRESS", () => {
  it("is the gateway a name-based connection's destination is set to", () => {
    // The CNI gateway itself, the address the build actually dials.
    expect(read("../../../../docker/inspect/files/cni.conflist")).toContain(
      `"gateway": "${PROXY_ADDRESS}"`,
    );
    // Echoed into the haproxy config generator, which the guard uses too.
    expect(read("../../../../docker/inspect/files/s6-scripts/init-inspect-cfg")).toContain(
      `\nGATEWAY=${PROXY_ADDRESS}\n`,
    );
  });
});
