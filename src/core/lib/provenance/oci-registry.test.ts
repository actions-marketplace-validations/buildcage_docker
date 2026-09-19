/**
 * Unit tests for oci-registry.ts: the pull token, the manifest digest and an
 * image's config labels. The registry client underneath them is exercised
 * through those three rather than on its own.
 *
 * Tests use an injectable _fetch to avoid real network access.
 */
import { describe, it, expect } from "vitest";

import {
  fetchManifestDigest,
  fetchRegistryToken,
  fetchImageConfigLabels,
  type FetchLike,
  type FetchLikeResponse,
} from "./oci-registry.ts";
import {
  expectVerifyError,
  failsWith,
  networkFailure,
  okJson,
  stubRegistry,
} from "#core/lib/test/registry-stub.ts";

const DIGEST = "sha256:" + "a".repeat(64);

/** The HEAD response fetchManifestDigest reads its digest out of. */
function manifestHead(status: number, digestValue: string | null): FetchLikeResponse {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (name: string) => (name === "Docker-Content-Digest" ? digestValue : null) },
  };
}

// ── fetchManifestDigest ───────────────────────────────────────────────────

describe("fetchManifestDigest", () => {
  const call = (_fetch: FetchLike) =>
    fetchManifestDigest("ghcr.io", "owner/repo", "2.1.0", "token", _fetch);

  it("returns digest from Docker-Content-Digest header on success", async () => {
    let capturedOpts: { method?: string } | undefined;
    const result = await call(async (_url, opts) => {
      capturedOpts = opts;
      return manifestHead(200, DIGEST);
    });
    expect(result).toBe(DIGEST);
    expect(capturedOpts?.method).toBe("HEAD");
  });

  it("throws NOT_FOUND on 404", async () => {
    await expectVerifyError(
      call(async () => manifestHead(404, null)),
      "NOT_FOUND",
    );
  });

  it("throws TRANSIENT on 5xx", async () => {
    await expectVerifyError(
      call(async () => manifestHead(500, null)),
      "TRANSIENT",
    );
  });

  it("throws TRANSIENT with an auth hint on 401", async () => {
    await expectVerifyError(
      call(async () => manifestHead(401, null)),
      "TRANSIENT",
      /authenticated/,
    );
  });

  it("throws TRANSIENT with an auth hint on 403", async () => {
    await expectVerifyError(
      call(async () => manifestHead(403, null)),
      "TRANSIENT",
      /authenticated/,
    );
  });

  it("throws TRANSIENT when Docker-Content-Digest header is absent", async () => {
    await expectVerifyError(
      call(async () => manifestHead(200, null)),
      "TRANSIENT",
    );
  });

  it("throws TRANSIENT on network error", async () => {
    await expectVerifyError(call(networkFailure), "TRANSIENT");
  });

  it("throws TRANSIENT for a non-ok status that is not 404, 401/403 or 5xx", async () => {
    await expectVerifyError(
      call(async () => manifestHead(418, null)),
      "TRANSIENT",
    );
  });
});

// ── fetchRegistryToken ────────────────────────────────────────────────────

describe("fetchRegistryToken", () => {
  const call = (basicAuth: string | null, _fetch: FetchLike) =>
    fetchRegistryToken("ghcr.io", "buildcage/docker", basicAuth, _fetch);

  // ── basicAuth=null (not logged in) ─────────────────────────────────────

  it("returns an anonymous token when there are no Docker credentials and the registry responds 200", async () => {
    let callCount = 0;
    const token = await call(null, async (_url, opts) => {
      callCount++;
      expect(opts, "should send no auth header").toBe(undefined);
      return okJson({ token: "anon-token" });
    });
    expect(token).toBe("anon-token");
    expect(callCount, "should make exactly one request").toBe(1);
  });

  it("throws TOKEN_ERROR on 401/403 when no Docker credentials (private, not logged in)", async () => {
    await expectVerifyError(
      call(null, async () => failsWith(401)),
      "TOKEN_ERROR",
      /docker login/,
    );
    await expectVerifyError(
      call(null, async () => failsWith(403)),
      "TOKEN_ERROR",
    );
  });

  it("throws TRANSIENT on 5xx when no Docker credentials", async () => {
    await expectVerifyError(
      call(null, async () => failsWith(503)),
      "TRANSIENT",
    );
  });

  it("throws TRANSIENT on network error when no Docker credentials", async () => {
    await expectVerifyError(call(null, networkFailure), "TRANSIENT");
  });

  // ── basicAuth set (after docker login) ─────────────────────────────────

  it("uses Basic auth directly (no anonymous attempt) when Docker credentials are available", async () => {
    const basicAuth = Buffer.from("actor:ghp_token").toString("base64");
    let callCount = 0;
    let capturedAuth: string | undefined;
    const token = await call(basicAuth, async (_url, opts) => {
      callCount++;
      capturedAuth = opts?.headers?.Authorization;
      return okJson({ token: "jwt-token" });
    });
    expect(token).toBe("jwt-token");
    expect(callCount, "should make exactly one request (no anonymous attempt)").toBe(1);
    expect(capturedAuth, "should send the Docker config auth directly").toBe(`Basic ${basicAuth}`);
  });

  it("throws TOKEN_ERROR immediately on 401 when Docker credentials are present (no fallback)", async () => {
    let callCount = 0;
    await expectVerifyError(
      call(Buffer.from("actor:expired_token").toString("base64"), async () => {
        callCount++;
        return failsWith(401);
      }),
      "TOKEN_ERROR",
      /docker login/,
    );
    expect(callCount, "should not retry with anonymous").toBe(1);
  });

  it("throws TRANSIENT on 5xx when Docker credentials are present", async () => {
    await expectVerifyError(
      call(Buffer.from("actor:token").toString("base64"), async () => failsWith(500)),
      "TRANSIENT",
    );
  });

  it("wraps a network failure under Basic auth as TRANSIENT", async () => {
    await expectVerifyError(call("dXNlcjpwYXNz", networkFailure), "TRANSIENT");
  });
});

// ── fetchImageConfigLabels ────────────────────────────────────────────────

describe("fetchImageConfigLabels", () => {
  const amd64Dig = "sha256:" + "b".repeat(64);
  const configDig = "sha256:" + "c".repeat(64);
  const labels = { "org.opencontainers.image.version": "3.1.0-inspect" };
  const call = (_fetch: FetchLike) =>
    fetchImageConfigLabels("ghcr.io", "buildcage/docker", DIGEST, "token", _fetch);

  it("follows index → platform manifest → config blob and returns the labels", async () => {
    const registry = stubRegistry({
      [`/manifests/${DIGEST}`]: okJson({
        manifests: [
          { digest: amd64Dig, platform: { architecture: "amd64", os: "linux" } },
          { digest: "sha256:" + "e".repeat(64), platform: { architecture: "arm64", os: "linux" } },
        ],
      }),
      [`/manifests/${amd64Dig}`]: okJson({ config: { digest: configDig } }),
      [`/blobs/${configDig}`]: okJson({ config: { Labels: labels } }),
    });
    expect(await call(registry)).toStrictEqual(labels);
    expect(registry.urls[1], "the first real platform, not the index again").toContain(amd64Dig);
  });

  it("skips the unknown/unknown attestation manifests buildx attaches", async () => {
    const registry = stubRegistry({
      [`/manifests/${DIGEST}`]: okJson({
        manifests: [
          {
            digest: "sha256:" + "f".repeat(64),
            platform: { architecture: "unknown", os: "unknown" },
          },
          { digest: amd64Dig, platform: { architecture: "amd64", os: "linux" } },
        ],
      }),
      [`/manifests/${amd64Dig}`]: okJson({ config: { digest: configDig } }),
      [`/blobs/${configDig}`]: okJson({ config: { Labels: labels } }),
    });
    await call(registry);
    expect(registry.urls[1]).toContain(amd64Dig);
  });

  it("reads a single-platform image whose digest is the manifest itself", async () => {
    const registry = stubRegistry({
      [`/manifests/${DIGEST}`]: okJson({ config: { digest: configDig } }),
      [`/blobs/${configDig}`]: okJson({ config: { Labels: labels } }),
    });
    expect(await call(registry)).toStrictEqual(labels);
  });

  it("returns an empty object for an image with no labels", async () => {
    const registry = stubRegistry({
      [`/manifests/${DIGEST}`]: okJson({ config: { digest: configDig } }),
      [`/blobs/${configDig}`]: okJson({ config: {} }),
    });
    expect(await call(registry)).toStrictEqual({});
  });

  it("throws TRANSIENT on 5xx", async () => {
    await expectVerifyError(
      call(stubRegistry({ [`/manifests/${DIGEST}`]: failsWith(503) })),
      "TRANSIENT",
    );
  });

  it("throws NOT_FOUND, naming the image, on 404", async () => {
    await expectVerifyError(
      call(stubRegistry({ [`/manifests/${DIGEST}`]: failsWith(404) })),
      "NOT_FOUND",
      `ghcr.io/buildcage/docker@${DIGEST}`,
    );
  });

  it("throws TRANSIENT with an auth hint on 403", async () => {
    await expectVerifyError(
      call(stubRegistry({ [`/manifests/${DIGEST}`]: failsWith(403) })),
      "TRANSIENT",
      /authenticated/,
    );
  });

  it("throws NOT_FOUND when an index carries no real platform", async () => {
    await expectVerifyError(
      call(
        stubRegistry({
          [`/manifests/${DIGEST}`]: okJson({
            manifests: [{ digest: amd64Dig, platform: { architecture: "unknown", os: "unknown" } }],
          }),
        }),
      ),
      "NOT_FOUND",
    );
  });

  it("throws NOT_FOUND when the manifest names no config blob", async () => {
    await expectVerifyError(
      call(stubRegistry({ [`/manifests/${DIGEST}`]: okJson({}) })),
      "NOT_FOUND",
    );
  });

  it("throws TRANSIENT for a non-ok status the registry JSON reader does not name", async () => {
    await expectVerifyError(
      call(stubRegistry({ [`/manifests/${DIGEST}`]: failsWith(418) })),
      "TRANSIENT",
    );
  });

  it("wraps a network failure as TRANSIENT rather than letting it escape untyped", async () => {
    await expectVerifyError(call(networkFailure), "TRANSIENT");
  });
});
