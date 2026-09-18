/**
 * Unit tests for the registry reads: oci-registry.ts, the bundle lookup in
 * oci-bundle.ts and the credential read in docker-credentials.ts. They share
 * one file because they share the stub below.
 *
 * Tests use injectable _fetch / readFileSync arguments to avoid real network
 * and filesystem access.
 *
 * Run with: vp test run core/lib/provenance/oci-registry.test.ts
 */
import { describe, it, expect, assert } from "vitest";

import {
  fetchManifestDigest,
  fetchRegistryToken,
  fetchImageConfigLabels,
  type FetchLike,
  type FetchLikeResponse,
} from "./oci-registry.ts";
import { fetchBundle } from "./oci-bundle.ts";
import { readGhcrBasicAuth } from "./docker-credentials.ts";
import { VerifyImageError } from "./errors.ts";

const BUNDLE_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json";
const IMAGE_MANIFEST = "application/vnd.oci.image.manifest.v1+json";
const EMPTY_CONFIG = "application/vnd.oci.empty.v1+json";

const DIGEST = "sha256:" + "a".repeat(64);
const MANIFEST_DIGEST = "sha256:" + "b".repeat(64);
const BLOB_DIGEST = "sha256:" + "c".repeat(64);

const REFERRERS_PATH = `/referrers/${DIGEST}`;
/** The `sha256-<hex>` tag the fallback path looks the bundle up under. */
const TAG_PATH = `/manifests/${DIGEST.replace(":", "-")}`;

/** Says the stub was asked for a path it has no answer for; see expectVerifyError. */
const UNSTUBBED = "unstubbed registry request";

type Route = FetchLikeResponse | ((url: string) => FetchLikeResponse);
type RegistryStub = FetchLike & { urls: string[] };

/**
 * A fetch stub answering by URL path, so a test states what each endpoint holds
 * rather than the order the calls come in. A path no key matches fails the test
 * instead of being answered by whatever response came last.
 */
function stubRegistry(routes: Record<string, Route>): RegistryStub {
  const urls: string[] = [];
  return Object.assign(
    async (url: string) => {
      urls.push(url);
      const key = Object.keys(routes).find((k) => url.includes(k));
      if (key === undefined) throw new Error(`${UNSTUBBED}: ${url}`);
      const route = routes[key]!;
      return typeof route === "function" ? route(url) : route;
    },
    { urls },
  );
}

function okJson(body: unknown): FetchLikeResponse {
  return { ok: true, status: 200, json: async () => body };
}

/** A refusal with an empty JSON body, which some paths read before classifying it. */
function failsWith(status: number): FetchLikeResponse {
  return { ok: false, status, json: async () => ({}) };
}

/** Usable as a whole stub or as one route: the request never completes. */
function networkFailure(): never {
  throw new TypeError("fetch failed");
}

/** The HEAD response fetchManifestDigest reads its digest out of. */
function manifestHead(status: number, digestValue: string | null): FetchLikeResponse {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (name: string) => (name === "Docker-Content-Digest" ? digestValue : null) },
  };
}

/**
 * Assert a registry call refuses with a VerifyImageError carrying `code`.
 *
 * An error raised by an unstubbed request is rejected too: it arrives wrapped as
 * a perfectly plausible TRANSIENT, which would let a stale stub pass.
 */
async function expectVerifyError(
  call: Promise<unknown>,
  code: string,
  message?: string | RegExp,
): Promise<void> {
  try {
    await call;
  } catch (err) {
    expect(err).toBeInstanceOf(VerifyImageError);
    const failure = err as VerifyImageError;
    expect(failure.message).not.toContain(UNSTUBBED);
    expect(failure.code).toBe(code);
    if (message !== undefined) expect(failure.message).toMatch(message);
    return;
  }
  assert.fail("should have thrown");
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

  it("throws TRANSIENT with auth hint on 401", async () => {
    await expectVerifyError(
      call(async () => manifestHead(401, null)),
      "TRANSIENT",
      /authenticated/,
    );
  });

  it("throws TRANSIENT with auth hint on 403", async () => {
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

  // ── basicAuth=null (未ログイン) ─────────────────────────────────────────

  it("returns anonymous token when no Docker credentials and registry responds 200", async () => {
    let callCount = 0;
    const token = await call(null, async (_url, opts) => {
      callCount++;
      expect(opts, "should send no auth header").toBe(undefined);
      return okJson({ token: "anon-token" });
    });
    expect(token).toBe("anon-token");
    expect(callCount, "should make exactly one request").toBe(1);
  });

  it("throws TOKEN_ERROR on 401 when no Docker credentials (private, not logged in)", async () => {
    await expectVerifyError(
      call(null, async () => failsWith(401)),
      "TOKEN_ERROR",
      /docker login/,
    );
  });

  it("throws TOKEN_ERROR on 403 when no Docker credentials (private, not logged in)", async () => {
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

  // ── basicAuth あり (docker login 済み) ────────────────────────────────

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

  it("throws TOKEN_ERROR immediately on 403 when Docker credentials are present (no fallback)", async () => {
    await expectVerifyError(
      call(Buffer.from("actor:token").toString("base64"), async () => failsWith(403)),
      "TOKEN_ERROR",
    );
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

// ── readGhcrBasicAuth ─────────────────────────────────────────────────────

describe("readGhcrBasicAuth", () => {
  const mockReadFileSync = (content: string) => (_path: string, _enc: string) => content;

  it("returns auth when auths['ghcr.io'].auth is present", () => {
    const config = JSON.stringify({ auths: { "ghcr.io": { auth: "dGVzdDp0b2tlbg==" } } });
    const result = readGhcrBasicAuth({}, mockReadFileSync(config));
    expect(result).toBe("dGVzdDp0b2tlbg==");
  });

  it("normalizes https:// prefix and trailing slash in key", () => {
    const config = JSON.stringify({ auths: { "https://ghcr.io/": { auth: "dGVzdA==" } } });
    const result = readGhcrBasicAuth({}, mockReadFileSync(config));
    expect(result).toBe("dGVzdA==");
  });

  it("returns null when ghcr.io entry is absent", () => {
    const config = JSON.stringify({ auths: { "docker.io": { auth: "dGVzdA==" } } });
    expect(readGhcrBasicAuth({}, mockReadFileSync(config))).toBe(null);
  });

  it("returns null when auth field is empty string (credsStore environment)", () => {
    const config = JSON.stringify({ auths: { "ghcr.io": {} } });
    expect(readGhcrBasicAuth({}, mockReadFileSync(config))).toBe(null);
  });

  it("returns null when auths is absent", () => {
    const config = JSON.stringify({ credsStore: "desktop" });
    expect(readGhcrBasicAuth({}, mockReadFileSync(config))).toBe(null);
  });

  it("returns null on file read error (not logged in at all)", () => {
    const throwingRead = () => {
      throw new Error("ENOENT");
    };
    expect(readGhcrBasicAuth({}, throwingRead)).toBe(null);
  });

  it("returns null on invalid JSON", () => {
    expect(readGhcrBasicAuth({}, mockReadFileSync("not json"))).toBe(null);
  });

  it("uses DOCKER_CONFIG env var to resolve config path", () => {
    let capturedPath: string | undefined;
    const readSpy = (p: string) => {
      capturedPath = p;
      return JSON.stringify({ auths: {} });
    };
    readGhcrBasicAuth({ DOCKER_CONFIG: "/custom/docker" }, readSpy);
    expect(
      capturedPath?.startsWith("/custom/docker"),
      `expected path under DOCKER_CONFIG, got: ${capturedPath}`,
    ).toBeTruthy();
  });
});

// ── fetchBundle ───────────────────────────────────────────────────────────

const bundle = (_fetch: FetchLike) =>
  fetchBundle("ghcr.io", "buildcage/docker", DIGEST, "token", _fetch);

/** What the Referrers API answers when it does hold the bundle manifest. */
const REFERRERS_HIT = okJson({
  manifests: [{ artifactType: BUNDLE_TYPE, mediaType: IMAGE_MANIFEST, digest: MANIFEST_DIGEST }],
});
/** A registry with no Referrers API at all. */
const REFERRERS_MISS = failsWith(404);

describe("fetchBundle — Referrers API path", () => {
  const bundleObj = { mediaType: BUNDLE_TYPE, verificationMaterial: {} };

  it("returns bundle when found via Referrers API (3-request flow: referrers → manifest → blob)", async () => {
    const registry = stubRegistry({
      [REFERRERS_PATH]: REFERRERS_HIT,
      [`/manifests/${MANIFEST_DIGEST}`]: okJson({
        artifactType: BUNDLE_TYPE,
        layers: [{ mediaType: BUNDLE_TYPE, digest: BLOB_DIGEST }],
      }),
      [`/blobs/${BLOB_DIGEST}`]: okJson(bundleObj),
    });
    expect(await bundle(registry)).toStrictEqual(bundleObj);
    expect(registry.urls.length, "referrers, bundle manifest, blob").toBe(3);
  });

  it("throws NOT_FOUND when Referrers returns no matching artifactType", async () => {
    await expectVerifyError(
      bundle(
        stubRegistry({
          [REFERRERS_PATH]: okJson({
            manifests: [{ artifactType: "application/other", digest: "sha256:c" }],
          }),
          [TAG_PATH]: failsWith(404),
        }),
      ),
      "NOT_FOUND",
    );
  });
});

describe("fetchBundle — fallback tag path", () => {
  const bundleObj = { mediaType: BUNDLE_TYPE };
  const bundleBlob = { [`/blobs/${BLOB_DIGEST}`]: okJson(bundleObj) };

  it("falls back to sha256-<hex> tag (legacy direct-layers format) and returns bundle", async () => {
    const registry = stubRegistry({
      [REFERRERS_PATH]: REFERRERS_MISS,
      [TAG_PATH]: okJson({ layers: [{ mediaType: BUNDLE_TYPE, digest: BLOB_DIGEST }] }),
      ...bundleBlob,
    });
    expect(await bundle(registry)).toStrictEqual(bundleObj);
  });

  it("falls back to sha256-<hex> tag as OCI image index (standard artifactType match)", async () => {
    const registry = stubRegistry({
      [REFERRERS_PATH]: REFERRERS_MISS,
      [TAG_PATH]: okJson({
        manifests: [
          { mediaType: IMAGE_MANIFEST, artifactType: BUNDLE_TYPE, digest: MANIFEST_DIGEST },
        ],
      }),
      [`/manifests/${MANIFEST_DIGEST}`]: okJson({
        artifactType: BUNDLE_TYPE,
        layers: [{ mediaType: BUNDLE_TYPE, digest: BLOB_DIGEST }],
      }),
      ...bundleBlob,
    });
    expect(await bundle(registry)).toStrictEqual(bundleObj);
  });

  it("falls back to sha256-<hex> tag as OCI image index (GHCR: config.mediaType used as artifactType)", async () => {
    // GHCR stores config.mediaType ("application/vnd.oci.empty.v1+json") as artifactType
    // in the Referrers Tag Schema index instead of the manifest's own artifactType field,
    // so the same index satisfies neither the referrers lookup nor a direct type match.
    const index = okJson({
      manifests: [
        { mediaType: IMAGE_MANIFEST, artifactType: EMPTY_CONFIG, digest: MANIFEST_DIGEST },
      ],
    });
    const registry = stubRegistry({
      [REFERRERS_PATH]: index,
      [TAG_PATH]: index,
      [`/manifests/${MANIFEST_DIGEST}`]: okJson({
        artifactType: BUNDLE_TYPE,
        layers: [{ mediaType: BUNDLE_TYPE, digest: BLOB_DIGEST }],
      }),
      ...bundleBlob,
    });
    expect(await bundle(registry)).toStrictEqual(bundleObj);
  });

  it("throws TRANSIENT on 5xx from Referrers API", async () => {
    await expectVerifyError(
      bundle(stubRegistry({ [REFERRERS_PATH]: failsWith(503) })),
      "TRANSIENT",
    );
  });

  it("throws TRANSIENT on network error from Referrers API", async () => {
    await expectVerifyError(bundle(networkFailure), "TRANSIENT");
  });

  it("throws TRANSIENT (not NOT_FOUND) on 403 from blob fetch", async () => {
    await expectVerifyError(
      bundle(
        stubRegistry({
          [REFERRERS_PATH]: REFERRERS_MISS,
          [TAG_PATH]: okJson({ layers: [{ mediaType: BUNDLE_TYPE, digest: BLOB_DIGEST }] }),
          [`/blobs/${BLOB_DIGEST}`]: failsWith(403),
        }),
      ),
      "TRANSIENT",
      /authenticated/,
    );
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

// ── fail-closed paths ─────────────────────────────────────────────────────
//
// Every branch below refuses rather than returns. They are what stands between
// a registry that answers oddly and an unverified image being pulled anyway, so
// each case pins the code that comes back, not just that something threw.

describe("fetchBundle — fallback tag refusals", () => {
  const tagIs = (response: Route) =>
    stubRegistry({ [REFERRERS_PATH]: REFERRERS_MISS, [TAG_PATH]: response });

  it("throws TRANSIENT on 5xx", async () => {
    await expectVerifyError(bundle(tagIs(failsWith(503))), "TRANSIENT");
  });

  it("throws TRANSIENT on 401/403, an auth problem rather than a missing bundle", async () => {
    await expectVerifyError(bundle(tagIs(failsWith(403))), "TRANSIENT");
  });

  it("throws NOT_FOUND for any other non-ok status", async () => {
    await expectVerifyError(bundle(tagIs(failsWith(418))), "NOT_FOUND");
  });

  it("wraps a network failure on the fallback tag as TRANSIENT", async () => {
    await expectVerifyError(bundle(tagIs(networkFailure)), "TRANSIENT");
  });

  it("throws NOT_FOUND when the legacy direct-layers manifest carries no bundle layer", async () => {
    const tag = okJson({ layers: [{ mediaType: "application/octet-stream" }] });
    await expectVerifyError(bundle(tagIs(tag)), "NOT_FOUND");
  });

  it("throws NOT_FOUND when the legacy manifest omits layers entirely", async () => {
    await expectVerifyError(bundle(tagIs(okJson({}))), "NOT_FOUND");
  });

  it("falls through to the tag when the referrers API answers without a manifests list", async () => {
    await expectVerifyError(
      bundle(stubRegistry({ [REFERRERS_PATH]: okJson({}), [TAG_PATH]: failsWith(404) })),
      "NOT_FOUND",
    );
  });
});

describe("fetchBundle — descriptors the referrers tag index offers but cannot satisfy", () => {
  /** Referrers miss, then a tag index holding exactly these descriptors. */
  const indexOf = (manifests: unknown[], subManifest?: Route) =>
    stubRegistry({
      [REFERRERS_PATH]: REFERRERS_MISS,
      [TAG_PATH]: okJson({ manifests }),
      ...(subManifest ? { [`/manifests/${MANIFEST_DIGEST}`]: subManifest } : {}),
    });
  const emptyConfigDescriptor = [
    { mediaType: IMAGE_MANIFEST, artifactType: EMPTY_CONFIG, digest: MANIFEST_DIGEST },
  ];

  it("skips a descriptor that is not an image manifest at all", async () => {
    const index = indexOf([
      { mediaType: "application/vnd.oci.image.index.v1+json", digest: MANIFEST_DIGEST },
    ]);
    await expectVerifyError(bundle(index), "NOT_FOUND");
  });

  it("skips a descriptor whose sub-manifest cannot be fetched", async () => {
    await expectVerifyError(bundle(indexOf(emptyConfigDescriptor, failsWith(404))), "NOT_FOUND");
  });

  it("skips a descriptor whose sub-manifest turns out to be some other artifact", async () => {
    const sub = okJson({ artifactType: "application/other" });
    await expectVerifyError(bundle(indexOf(emptyConfigDescriptor, sub)), "NOT_FOUND");
  });

  it("skips a bundle sub-manifest that carries no bundle layer", async () => {
    const sub = okJson({ artifactType: BUNDLE_TYPE, layers: [{ mediaType: "text/plain" }] });
    await expectVerifyError(bundle(indexOf(emptyConfigDescriptor, sub)), "NOT_FOUND");
  });

  it("skips a bundle sub-manifest that omits layers entirely", async () => {
    const sub = okJson({ artifactType: BUNDLE_TYPE });
    await expectVerifyError(bundle(indexOf(emptyConfigDescriptor, sub)), "NOT_FOUND");
  });
});

describe("fetchBundle — bundle manifest refusals", () => {
  const manifestIs = (response: Route) =>
    stubRegistry({
      [REFERRERS_PATH]: REFERRERS_HIT,
      [`/manifests/${MANIFEST_DIGEST}`]: response,
    });

  it("throws TRANSIENT on 5xx", async () => {
    await expectVerifyError(bundle(manifestIs(failsWith(502))), "TRANSIENT");
  });

  it("throws TRANSIENT on 401/403", async () => {
    await expectVerifyError(bundle(manifestIs(failsWith(401))), "TRANSIENT");
  });

  it("throws TRANSIENT for any other non-ok status", async () => {
    await expectVerifyError(bundle(manifestIs(failsWith(418))), "TRANSIENT");
  });

  it("throws NOT_FOUND when the bundle manifest holds no bundle layer", async () => {
    const manifest = okJson({ layers: [{ mediaType: "text/plain" }] });
    await expectVerifyError(bundle(manifestIs(manifest)), "NOT_FOUND");
  });

  it("throws NOT_FOUND when the bundle manifest omits layers entirely", async () => {
    await expectVerifyError(bundle(manifestIs(okJson({}))), "NOT_FOUND");
  });

  it("wraps a network failure as TRANSIENT", async () => {
    await expectVerifyError(bundle(manifestIs(networkFailure)), "TRANSIENT");
  });
});

describe("fetchBundle — bundle blob refusals", () => {
  /** Referrers hit, bundle manifest hit, then the blob response under test. */
  const blobIs = (response: Route) =>
    stubRegistry({
      [REFERRERS_PATH]: REFERRERS_HIT,
      [`/manifests/${MANIFEST_DIGEST}`]: okJson({
        layers: [{ mediaType: BUNDLE_TYPE, digest: BLOB_DIGEST }],
      }),
      [`/blobs/${BLOB_DIGEST}`]: response,
    });

  it("throws TRANSIENT on 5xx", async () => {
    await expectVerifyError(bundle(blobIs(failsWith(500))), "TRANSIENT");
  });

  it("throws NOT_FOUND for any other non-ok status", async () => {
    await expectVerifyError(bundle(blobIs(failsWith(404))), "NOT_FOUND");
  });

  it("wraps a network failure as TRANSIENT", async () => {
    await expectVerifyError(bundle(blobIs(networkFailure)), "TRANSIENT");
  });
});
