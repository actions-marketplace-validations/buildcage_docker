import { defineConfig } from "vite-plus";

// Committed build artifacts (verified against source by the "Check dist is
// up to date" CI step) — never lint/format generated output.
const generatedOutputs = ["dist/**", "report/dist/**"];

// Recorded/golden fixtures: some (e.g. core/lib/log/__fixtures__/*.json) are
// parsed line-by-line to mimic buildctl's real NDJSON-ish log output, so
// pretty-printing them breaks that line structure and fails the tests that
// read them. Fixtures are captured data, not authored code — never reformat
// any of them, even ones that happen to be safe today.
const fixtures = ["**/__fixtures__/**"];

// Vendored from moby/profiles by `make seccomp_profile`. Reformatting it would
// destroy the diff against upstream, which is how this file gets reviewed.
const vendored = ["docker/seccomp/builder.json"];

export default defineConfig({
  lint: {
    ignorePatterns: generatedOutputs,
    options: {
      // typescript already at v7 (typescript-go), so tsgolint's type-aware
      // rules apply directly. `pnpm typecheck` (tsc) stays the authoritative
      // full type check; typeCheck (still experimental) is left off here.
      typeAware: true,
    },
  },
  fmt: {
    ignorePatterns: [...generatedOutputs, ...fixtures, ...vendored, "MAINTAINERS.md"],
  },
  staged: {
    "*.{ts,tsx,js,jsx,json,jsonc,yaml,yml,md}": "vp check --fix",
    "docker/explicit/buildkit-proxy/**/*.go": "gofmt -w",
  },
  test: {
    include: ["src/**/*.test.ts", "report/src/**/*.test.ts"],
    restoreMocks: true,
    // No thresholds: this only makes the numbers visible. @vitest/coverage-v8
    // is pinned to the exact vitest version vite-plus bundles, which vite-plus
    // asserts at startup; bump both together.
    coverage: {
      provider: "v8",
      // Without an explicit include, v8 reports only files some test imported,
      // which hides the files that have no test at all.
      include: ["src/**/*.ts", "report/src/**/*.ts"],
      exclude: [
        "**/*.test.ts",
        ...fixtures,
        "**/*.d.ts",
        // Test scaffolding: the QuickJS shims and the QuickJS test runner.
        "src/core/lib/test/**",
        "src/core/scripts/test/**",
      ],
      // text goes to the CI log; the file copy is what the workflow pastes
      // into the job summary.
      reporter: [
        ["text", {}],
        ["text-summary", { file: "summary.txt" }],
      ],
    },
  },
});
