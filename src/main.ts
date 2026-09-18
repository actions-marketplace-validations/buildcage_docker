import { execFileSync } from "node:child_process";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { SetupError } from "./lib/errors.ts";
import { annotate } from "#core/lib/actions/annotation.ts";
import { exitOnFatalError } from "#core/lib/actions/fatal.ts";
import { readBuilderName, readEngineInputs, readRuleInputs } from "./lib/inputs.ts";
import { checkUrlAndTlsRuleSupport } from "./lib/engine-rule-support.ts";
import { buildComposeEnv } from "./lib/compose-env.ts";
import {
  verifyImageDigestOrThrow,
  type VerifyImageDigestOptions,
  type ResolvedImage,
} from "#core/lib/provenance/verify-image.ts";
import { resolveBuildcageImageRef } from "#core/lib/provenance/image-ref.ts";
import { describeDockerFailure } from "#core/lib/actions/docker-error.ts";
import { logRules, withLogGroup } from "#core/lib/actions/log.ts";
import { deriveProjectName } from "#core/lib/docker/compose-project-name.ts";
import { buildComposeUpArgs, buildComposeDownArgs } from "#core/lib/docker/args.ts";
import { builderStartError } from "./lib/builder-diagnostics.ts";

// Untested by design, down to the end of the file: what is left here is the
// entry point's own wiring -- the compose file path, the local-image gate, the
// docker invocations main() sequences, and the self-invocation guard a test
// can never be inside. Every unit main() calls is tested directly, in lib/.
/* v8 ignore start */
const __dirname = dirname(fileURLToPath(import.meta.url));
const composeFile = join(__dirname, "../docker/compose.action.yaml");

// Gates a local-image override used only by this repo's own CI/dev testing
// (test_action in .github/workflows/test-e2e.yml, and verify-image in
// docker-publish.yml, where the image is not signed yet), never by a consumer
// of a published action. A normal build physically excludes
// src/core/lib/provenance/local-image-override.ts (rolldown tree-shakes the dead import); the
// unit_test CI job also greps the built output as a backstop.
const LOCAL_IMAGE_OVERRIDE_ENABLED = process.env.BUILDCAGE_BUILD_TEST_HOOKS === "1";

/**
 * Verifies image provenance and resolves the digest-pinned image ref.
 * Throws ProvenanceError("UNVERIFIABLE_REF") if verification can't be
 * performed (branch ref / local ./) — printed by the top-level catch.
 */
async function resolveVerifiedImage({
  actionRef,
  actionRepo,
  proxyEngine,
}: VerifyImageDigestOptions): Promise<ResolvedImage> {
  const digest = await verifyImageDigestOrThrow({ actionRef, actionRepo, proxyEngine });
  console.log(
    `Image provenance verified for ref: ${JSON.stringify(actionRef)} (digest ${digest}).`,
  );
  return {
    imageRef: resolveBuildcageImageRef({ imageDigest: digest, actionRepository: actionRepo }),
    pullPolicy: "always",
  };
}

async function main(): Promise<void> {
  const env = process.env;
  const actionRef = env.GITHUB_ACTION_REF ?? "";
  const actionRepo = env.GITHUB_ACTION_REPOSITORY ?? "";

  const { proxyEngine } = readEngineInputs(annotate.notice);
  console.log(`Proxy engine: ${proxyEngine}`);

  const localOverride = LOCAL_IMAGE_OVERRIDE_ENABLED
    ? (await import("./core/lib/provenance/local-image-override.ts")).readLocalImageOverride(env)
    : null;
  if (localOverride) {
    console.log(
      `BUILDCAGE_LOCAL_IMAGE_REF is set (${JSON.stringify(localOverride.imageRef)}) — ` +
        `skipping image provenance verification and registry tag resolution entirely. ` +
        `This bypass exists only for buildcage's own CI self-tests and local development and is ` +
        `dead-code-eliminated from every published release build.`,
    );
  }
  const { imageRef, pullPolicy } =
    localOverride ?? (await resolveVerifiedImage({ actionRef, actionRepo, proxyEngine }));
  console.log(`buildcage: image: ${imageRef}`);

  const { proxyMode, httpsRules, httpRules, ipRules, urlRules, tlsRules, knownBlockedRules } =
    readRuleInputs();
  checkUrlAndTlsRuleSupport({ proxyEngine, proxyMode, urlRules, tlsRules }, annotate.warning);

  withLogGroup("buildcage: Configured ACL Rules", () => {
    logRules("HTTPS", httpsRules);
    logRules("HTTP", httpRules);
    logRules("IP", ipRules);
    logRules("URL", urlRules);
    logRules("TLS", tlsRules);
    logRules("Known blocked", knownBlockedRules);
  });

  const builderName = readBuilderName();
  // So report can independently derive the same project name from its own
  // builder_name input and find this container via `docker ps --filter`.
  const projectName = deriveProjectName(builderName);

  const composeEnv = buildComposeEnv(
    {
      builderName,
      proxyMode,
      proxyEngine,
      imageRef,
      httpsRules,
      httpRules,
      ipRules,
      urlRules,
      tlsRules,
      knownBlockedRules,
    },
    env,
  );

  try {
    execFileSync("docker", buildComposeDownArgs({ composeFile, projectName }), {
      stdio: "inherit",
      env: composeEnv,
    });
  } catch (e) {
    throw new SetupError(
      describeDockerFailure(e, { operation: "docker compose down" }),
      "DOCKER_UNAVAILABLE",
    );
  }

  try {
    execFileSync("docker", buildComposeUpArgs({ composeFile, projectName, pullPolicy }), {
      stdio: "inherit",
      env: composeEnv,
    });
  } catch (e) {
    throw builderStartError(e, { composeFile, projectName, builderName, composeEnv });
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch(exitOnFatalError("setup"));
}
/* v8 ignore stop */
