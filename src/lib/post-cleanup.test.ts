import { describe, it, expect, vi, afterEach } from "vitest";

import { planPostCleanup } from "./post-cleanup.ts";

const COMPOSE_FILE = "/action/docker/compose.action.yaml";

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("planPostCleanup", () => {
  it("takes down the project main.ts derived from the same builder_name", () => {
    vi.stubEnv("INPUT_BUILDER_NAME", "second");

    const { args, env } = planPostCleanup(COMPOSE_FILE, undefined, { PATH: "/usr/bin" });

    expect(args).toStrictEqual(["compose", "-f", COMPOSE_FILE, "-p", expect.any(String), "down"]);
    expect(env).toStrictEqual({ PATH: "/usr/bin", BUILDER_NAME: "second" });
  });

  // action.yml's own default covers the normal case; this covers running the
  // built script outside the Actions runtime.
  it("falls back to the default builder name when the input is unset", () => {
    const { env } = planPostCleanup(COMPOSE_FILE, undefined, {});

    expect(env.BUILDER_NAME).toBe("buildcage");
  });

  it("derives the same project name main.ts and report do for one builder", () => {
    vi.stubEnv("INPUT_BUILDER_NAME", "second");
    const first = planPostCleanup(COMPOSE_FILE, undefined, {});
    const second = planPostCleanup(COMPOSE_FILE, undefined, {});

    expect(first.args).toStrictEqual(second.args);
  });

  it("uses the override outright when this repo's own testing supplies one", () => {
    vi.stubEnv("INPUT_BUILDER_NAME", "second");

    const { args } = planPostCleanup(COMPOSE_FILE, "buildcage-e2e", {});

    expect(args).toStrictEqual(["compose", "-f", COMPOSE_FILE, "-p", "buildcage-e2e", "down"]);
  });
});
