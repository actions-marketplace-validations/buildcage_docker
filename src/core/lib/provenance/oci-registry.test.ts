/**
 * Unit tests for core/lib/oci-registry.ts
 *
 * Tests use injectable _exec / _fetch arguments to avoid real network/docker calls.
 *
 * Run with: vp test run core/lib/provenance/oci-registry.test.ts
 */
import { describe, it, expect, assert } from "vitest";

import {
  fetchManifestDigest,
  fetchRegistryToken,
  fetchBundle,
  fetchImageConfigLabels,
  readGhcrBasicAuth,
} from "./oci-registry.ts";
import { VerifyImageError } from "./errors.ts";

// ── fetchManifestDigest ───────────────────────────────────────────────────

describe("fetchManifestDigest", () => {
  const digest = "sha256:" + "a".repeat(64);

  function makeResp(status: number, digestValue: string | null) {
    return {
      ok: status >= 200 && status < 300,
      status,
      headers: { get: (name: string) => (name === "Docker-Content-Digest" ? digestValue : null) },
    };
  }

  it("returns digest from Docker-Content-Digest header on success", async () => {
    let capturedOpts: { method?: string } | undefined;
    const mockFetch = async (url: string, opts?: { method?: string }) => {
      capturedOpts = opts;
      return makeResp(200, digest);
    };
    const result = await fetchManifestDigest("ghcr.io", "owner/repo", "2.1.0", "token", mockFetch);
    expect(result).toBe(digest);
    expect(capturedOpts?.method).toBe("HEAD");
  });

  it("throws NOT_FOUND on 404", async () => {
    const mockFetch = async () => makeResp(404, null);
    try {
      await fetchManifestDigest("ghcr.io", "owner/repo", "2.1.0", "token", mockFetch);
      assert.fail("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(VerifyImageError);
      expect((err as VerifyImageError).code).toBe("NOT_FOUND");
    }
  });

  it("throws TRANSIENT on 5xx", async () => {
    const mockFetch = async () => makeResp(500, null);
    try {
      await fetchManifestDigest("ghcr.io", "owner/repo", "2.1.0", "token", mockFetch);
      assert.fail("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(VerifyImageError);
      expect((err as VerifyImageError).code).toBe("TRANSIENT");
    }
  });

  it("throws TRANSIENT with auth hint on 401", async () => {
    const mockFetch = async () => makeResp(401, null);
    try {
      await fetchManifestDigest("ghcr.io", "owner/repo", "2.1.0", "token", mockFetch);
      assert.fail("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(VerifyImageError);
      expect((err as VerifyImageError).code).toBe("TRANSIENT");
      expect(
        (err as VerifyImageError).message.includes("authenticated"),
        "error message should hint at authentication",
      ).toBeTruthy();
    }
  });

  it("throws TRANSIENT with auth hint on 403", async () => {
    const mockFetch = async () => makeResp(403, null);
    try {
      await fetchManifestDigest("ghcr.io", "owner/repo", "2.1.0", "token", mockFetch);
      assert.fail("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(VerifyImageError);
      expect((err as VerifyImageError).code).toBe("TRANSIENT");
      expect(
        (err as VerifyImageError).message.includes("authenticated"),
        "error message should hint at authentication",
      ).toBeTruthy();
    }
  });

  it("throws TRANSIENT when Docker-Content-Digest header is absent", async () => {
    const mockFetch = async () => makeResp(200, null);
    try {
      await fetchManifestDigest("ghcr.io", "owner/repo", "2.1.0", "token", mockFetch);
      assert.fail("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(VerifyImageError);
      expect((err as VerifyImageError).code).toBe("TRANSIENT");
    }
  });

  it("throws TRANSIENT on network error", async () => {
    const mockFetch = async () => {
      throw new Error("ECONNREFUSED");
    };
    try {
      await fetchManifestDigest("ghcr.io", "owner/repo", "2.1.0", "token", mockFetch);
      assert.fail("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(VerifyImageError);
      expect((err as VerifyImageError).code).toBe("TRANSIENT");
    }
  });
});

// ── fetchRegistryToken ────────────────────────────────────────────────────

describe("fetchRegistryToken", () => {
  // ── basicAuth=null (未ログイン) ─────────────────────────────────────────

  it("returns anonymous token when no Docker credentials and registry responds 200", async () => {
    let callCount = 0;
    const mockFetch = async (url: string, opts?: { headers?: Record<string, string> }) => {
      callCount++;
      expect(opts, "should send no auth header").toBe(undefined);
      return { ok: true, status: 200, json: async () => ({ token: "anon-token" }) };
    };
    const token = await fetchRegistryToken("ghcr.io", "buildcage/docker", null, mockFetch);
    expect(token).toBe("anon-token");
    expect(callCount, "should make exactly one request").toBe(1);
  });

  it("throws TOKEN_ERROR on 401 when no Docker credentials (private, not logged in)", async () => {
    const mockFetch = async () => ({ ok: false, status: 401 });
    try {
      await fetchRegistryToken("ghcr.io", "buildcage/docker", null, mockFetch);
      assert.fail("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(VerifyImageError);
      expect((err as VerifyImageError).code).toBe("TOKEN_ERROR");
      expect(
        (err as VerifyImageError).message.includes("docker login"),
        "error message should mention docker login",
      ).toBeTruthy();
    }
  });

  it("throws TOKEN_ERROR on 403 when no Docker credentials (private, not logged in)", async () => {
    const mockFetch = async () => ({ ok: false, status: 403 });
    try {
      await fetchRegistryToken("ghcr.io", "buildcage/docker", null, mockFetch);
      assert.fail("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(VerifyImageError);
      expect((err as VerifyImageError).code).toBe("TOKEN_ERROR");
    }
  });

  it("throws TRANSIENT on 5xx when no Docker credentials", async () => {
    const mockFetch = async () => ({ ok: false, status: 503 });
    try {
      await fetchRegistryToken("ghcr.io", "buildcage/docker", null, mockFetch);
      assert.fail("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(VerifyImageError);
      expect((err as VerifyImageError).code).toBe("TRANSIENT");
    }
  });

  it("throws TRANSIENT on network error when no Docker credentials", async () => {
    const mockFetch = async () => {
      throw new Error("ECONNREFUSED");
    };
    try {
      await fetchRegistryToken("ghcr.io", "buildcage/docker", null, mockFetch);
      assert.fail("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(VerifyImageError);
      expect((err as VerifyImageError).code).toBe("TRANSIENT");
    }
  });

  // ── basicAuth あり (docker login 済み) ────────────────────────────────

  it("uses Basic auth directly (no anonymous attempt) when Docker credentials are available", async () => {
    const basicAuth = Buffer.from("actor:ghp_token").toString("base64");
    let callCount = 0;
    let capturedAuth: string | undefined;
    const mockFetch = async (url: string, opts?: { headers?: Record<string, string> }) => {
      callCount++;
      capturedAuth = opts?.headers?.Authorization;
      return { ok: true, status: 200, json: async () => ({ token: "jwt-token" }) };
    };
    const token = await fetchRegistryToken("ghcr.io", "buildcage/docker", basicAuth, mockFetch);
    expect(token).toBe("jwt-token");
    expect(callCount, "should make exactly one request (no anonymous attempt)").toBe(1);
    expect(capturedAuth, "should send the Docker config auth directly").toBe(`Basic ${basicAuth}`);
  });

  it("throws TOKEN_ERROR immediately on 401 when Docker credentials are present (no fallback)", async () => {
    const basicAuth = Buffer.from("actor:expired_token").toString("base64");
    let callCount = 0;
    const mockFetch = async () => {
      callCount++;
      return { ok: false, status: 401 };
    };
    try {
      await fetchRegistryToken("ghcr.io", "buildcage/docker", basicAuth, mockFetch);
      assert.fail("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(VerifyImageError);
      expect((err as VerifyImageError).code).toBe("TOKEN_ERROR");
      expect(
        (err as VerifyImageError).message.includes("docker login"),
        "error message should mention docker login",
      ).toBeTruthy();
      expect(callCount, "should not retry with anonymous").toBe(1);
    }
  });

  it("throws TOKEN_ERROR immediately on 403 when Docker credentials are present (no fallback)", async () => {
    const basicAuth = Buffer.from("actor:token").toString("base64");
    const mockFetch = async () => ({ ok: false, status: 403 });
    try {
      await fetchRegistryToken("ghcr.io", "buildcage/docker", basicAuth, mockFetch);
      assert.fail("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(VerifyImageError);
      expect((err as VerifyImageError).code).toBe("TOKEN_ERROR");
    }
  });

  it("throws TRANSIENT on 5xx when Docker credentials are present", async () => {
    const basicAuth = Buffer.from("actor:token").toString("base64");
    const mockFetch = async () => ({ ok: false, status: 500 });
    try {
      await fetchRegistryToken("ghcr.io", "buildcage/docker", basicAuth, mockFetch);
      assert.fail("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(VerifyImageError);
      expect((err as VerifyImageError).code).toBe("TRANSIENT");
    }
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

const BUNDLE_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json";

function makeFetchReturning(responses: any[]) {
  let i = 0;
  return async (url: string) => {
    const resp = responses[i++] ?? responses[responses.length - 1];
    return typeof resp === "function" ? resp(url) : resp;
  };
}

describe("fetchBundle — Referrers API path", () => {
  const digest = "sha256:" + "a".repeat(64);
  const manifestDig = "sha256:" + "b".repeat(64);
  const blobDig = "sha256:" + "d".repeat(64);
  const bundleObj = { mediaType: BUNDLE_TYPE, verificationMaterial: {} };

  it("returns bundle when found via Referrers API (3-request flow: referrers → manifest → blob)", async () => {
    const mockFetch = makeFetchReturning([
      // GET /referrers/<digest>
      {
        ok: true,
        status: 200,
        json: async () => ({
          manifests: [
            {
              artifactType: BUNDLE_TYPE,
              mediaType: "application/vnd.oci.image.manifest.v1+json",
              digest: manifestDig,
            },
          ],
        }),
      },
      // GET /manifests/<manifestDig>
      {
        ok: true,
        status: 200,
        json: async () => ({
          artifactType: BUNDLE_TYPE,
          layers: [{ mediaType: BUNDLE_TYPE, digest: blobDig }],
        }),
      },
      // GET /blobs/<blobDig>
      { ok: true, status: 200, json: async () => bundleObj },
    ]);
    const result = await fetchBundle("ghcr.io", "buildcage/docker", digest, "token", mockFetch);
    expect(result).toStrictEqual(bundleObj);
  });

  it("throws NOT_FOUND when Referrers returns no matching artifactType", async () => {
    const mockFetch = makeFetchReturning([
      // Referrers API → no bundle
      {
        ok: true,
        status: 200,
        json: async () => ({
          manifests: [{ artifactType: "application/other", digest: "sha256:c" }],
        }),
      },
      // Fallback tag → 404
      { ok: false, status: 404, json: async () => ({}) },
    ]);
    try {
      await fetchBundle("ghcr.io", "buildcage/docker", digest, "token", mockFetch);
      assert.fail("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(VerifyImageError);
      expect((err as VerifyImageError).code).toBe("NOT_FOUND");
    }
  });
});

describe("fetchBundle — fallback tag path", () => {
  const digest = "sha256:" + "a".repeat(64);
  const manifestDig = "sha256:" + "b".repeat(64);
  const blobDig = "sha256:" + "c".repeat(64);
  const bundleObj = { mediaType: BUNDLE_TYPE };

  it("falls back to sha256-<hex> tag (legacy direct-layers format) and returns bundle", async () => {
    const mockFetch = makeFetchReturning([
      // Referrers API → 404 (old registry, no Referrers support)
      { ok: false, status: 404, json: async () => ({}) },
      // Fallback tag: direct manifest with layers
      {
        ok: true,
        status: 200,
        json: async () => ({
          layers: [{ mediaType: BUNDLE_TYPE, digest: blobDig }],
        }),
      },
      // Blob
      { ok: true, status: 200, json: async () => bundleObj },
    ]);
    const result = await fetchBundle("ghcr.io", "buildcage/docker", digest, "token", mockFetch);
    expect(result).toStrictEqual(bundleObj);
  });

  it("falls back to sha256-<hex> tag as OCI image index (standard artifactType match)", async () => {
    const mockFetch = makeFetchReturning([
      // Referrers API → 404
      { ok: false, status: 404, json: async () => ({}) },
      // Fallback tag: image index with correct artifactType
      {
        ok: true,
        status: 200,
        json: async () => ({
          manifests: [
            {
              mediaType: "application/vnd.oci.image.manifest.v1+json",
              artifactType: BUNDLE_TYPE,
              digest: manifestDig,
            },
          ],
        }),
      },
      // Sub-manifest
      {
        ok: true,
        status: 200,
        json: async () => ({
          artifactType: BUNDLE_TYPE,
          layers: [{ mediaType: BUNDLE_TYPE, digest: blobDig }],
        }),
      },
      // Blob
      { ok: true, status: 200, json: async () => bundleObj },
    ]);
    const result = await fetchBundle("ghcr.io", "buildcage/docker", digest, "token", mockFetch);
    expect(result).toStrictEqual(bundleObj);
  });

  it("falls back to sha256-<hex> tag as OCI image index (GHCR: config.mediaType used as artifactType)", async () => {
    // GHCR stores config.mediaType ("application/vnd.oci.empty.v1+json") as artifactType
    // in the Referrers Tag Schema index instead of the manifest's own artifactType field.
    const mockFetch = makeFetchReturning([
      // Referrers API → 303 redirect → image index (GHCR behaviour)
      {
        ok: true,
        status: 200,
        json: async () => ({
          manifests: [
            {
              mediaType: "application/vnd.oci.image.manifest.v1+json",
              artifactType: "application/vnd.oci.empty.v1+json", // ← GHCR: config.mediaType
              digest: manifestDig,
            },
          ],
        }),
      },
      // Fallback tag: same image index (fetched again)
      {
        ok: true,
        status: 200,
        json: async () => ({
          manifests: [
            {
              mediaType: "application/vnd.oci.image.manifest.v1+json",
              artifactType: "application/vnd.oci.empty.v1+json", // ← GHCR: config.mediaType
              digest: manifestDig,
            },
          ],
        }),
      },
      // Sub-manifest inspection: real artifactType is correct
      {
        ok: true,
        status: 200,
        json: async () => ({
          artifactType: BUNDLE_TYPE,
          layers: [{ mediaType: BUNDLE_TYPE, digest: blobDig }],
        }),
      },
      // Blob
      { ok: true, status: 200, json: async () => bundleObj },
    ]);
    const result = await fetchBundle("ghcr.io", "buildcage/docker", digest, "token", mockFetch);
    expect(result).toStrictEqual(bundleObj);
  });

  it("throws TRANSIENT on 5xx from Referrers API", async () => {
    const mockFetch = makeFetchReturning([{ ok: false, status: 503 }]);
    try {
      await fetchBundle("ghcr.io", "buildcage/docker", digest, "token", mockFetch);
      assert.fail("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(VerifyImageError);
      expect((err as VerifyImageError).code).toBe("TRANSIENT");
    }
  });

  it("throws TRANSIENT on network error from Referrers API", async () => {
    const mockFetch = async () => {
      throw new Error("ECONNRESET");
    };
    try {
      await fetchBundle("ghcr.io", "buildcage/docker", digest, "token", mockFetch);
      assert.fail("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(VerifyImageError);
      expect((err as VerifyImageError).code).toBe("TRANSIENT");
    }
  });

  it("throws TRANSIENT (not NOT_FOUND) on 403 from blob fetch", async () => {
    const mockFetch = makeFetchReturning([
      // Referrers API → 404 (no Referrers support)
      { ok: false, status: 404, json: async () => ({}) },
      // Fallback tag manifest found (legacy format)
      {
        ok: true,
        status: 200,
        json: async () => ({
          layers: [{ mediaType: BUNDLE_TYPE, digest: blobDig }],
        }),
      },
      // Blob fetch → 403 (auth error, e.g. private repo not authenticated)
      { ok: false, status: 403 },
    ]);
    try {
      await fetchBundle("ghcr.io", "buildcage/docker", digest, "token", mockFetch);
      assert.fail("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(VerifyImageError);
      expect(
        (err as VerifyImageError).code,
        "auth error must not be reported as NOT_FOUND (unsigned image)",
      ).toBe("TRANSIENT");
    }
  });
});

// ── fetchImageConfigLabels ────────────────────────────────────────────────

describe("fetchImageConfigLabels", () => {
  const digest = "sha256:" + "a".repeat(64);
  const amd64Dig = "sha256:" + "b".repeat(64);
  const configDig = "sha256:" + "c".repeat(64);
  const labels = { "org.opencontainers.image.version": "3.1.0-inspect" };

  function okJson(body: unknown) {
    return { ok: true, status: 200, json: async () => body };
  }

  it("follows index → platform manifest → config blob and returns the labels", async () => {
    const urls: string[] = [];
    const responses = [
      okJson({
        manifests: [
          { digest: amd64Dig, platform: { architecture: "amd64", os: "linux" } },
          { digest: "sha256:" + "e".repeat(64), platform: { architecture: "arm64", os: "linux" } },
        ],
      }),
      okJson({ config: { digest: configDig } }),
      okJson({ config: { Labels: labels } }),
    ];
    let i = 0;
    const mockFetch = async (url: string) => {
      urls.push(url);
      return responses[i++]!;
    };
    const result = await fetchImageConfigLabels(
      "ghcr.io",
      "buildcage/docker",
      digest,
      "token",
      mockFetch,
    );
    expect(result).toStrictEqual(labels);
    expect(urls[1]).toContain(amd64Dig);
    expect(urls[2]).toContain(`/blobs/${configDig}`);
  });

  it("skips the unknown/unknown attestation manifests buildx attaches", async () => {
    const urls: string[] = [];
    const responses = [
      okJson({
        manifests: [
          {
            digest: "sha256:" + "f".repeat(64),
            platform: { architecture: "unknown", os: "unknown" },
          },
          { digest: amd64Dig, platform: { architecture: "amd64", os: "linux" } },
        ],
      }),
      okJson({ config: { digest: configDig } }),
      okJson({ config: { Labels: labels } }),
    ];
    let i = 0;
    const mockFetch = async (url: string) => {
      urls.push(url);
      return responses[i++]!;
    };
    await fetchImageConfigLabels("ghcr.io", "buildcage/docker", digest, "token", mockFetch);
    expect(urls[1]).toContain(amd64Dig);
  });

  it("reads a single-platform image whose digest is the manifest itself", async () => {
    const mockFetch = makeFetchReturning([
      okJson({ config: { digest: configDig } }),
      okJson({ config: { Labels: labels } }),
    ]);
    const result = await fetchImageConfigLabels(
      "ghcr.io",
      "buildcage/docker",
      digest,
      "token",
      mockFetch,
    );
    expect(result).toStrictEqual(labels);
  });

  it("returns an empty object for an image with no labels", async () => {
    const mockFetch = makeFetchReturning([
      okJson({ config: { digest: configDig } }),
      okJson({ config: {} }),
    ]);
    expect(
      await fetchImageConfigLabels("ghcr.io", "buildcage/docker", digest, "token", mockFetch),
    ).toStrictEqual({});
  });

  it("throws TRANSIENT on 5xx", async () => {
    const mockFetch = makeFetchReturning([{ ok: false, status: 503 }]);
    try {
      await fetchImageConfigLabels("ghcr.io", "buildcage/docker", digest, "token", mockFetch);
      assert.fail("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(VerifyImageError);
      expect((err as VerifyImageError).code).toBe("TRANSIENT");
    }
  });

  it("throws NOT_FOUND, naming the image, on 404", async () => {
    const mockFetch = makeFetchReturning([{ ok: false, status: 404 }]);
    try {
      await fetchImageConfigLabels("ghcr.io", "buildcage/docker", digest, "token", mockFetch);
      assert.fail("should have thrown");
    } catch (err) {
      expect((err as VerifyImageError).code).toBe("NOT_FOUND");
      expect((err as VerifyImageError).message).toContain(`ghcr.io/buildcage/docker@${digest}`);
    }
  });

  it("throws TRANSIENT with an auth hint on 403", async () => {
    const mockFetch = makeFetchReturning([{ ok: false, status: 403 }]);
    try {
      await fetchImageConfigLabels("ghcr.io", "buildcage/docker", digest, "token", mockFetch);
      assert.fail("should have thrown");
    } catch (err) {
      expect((err as VerifyImageError).code).toBe("TRANSIENT");
      expect((err as VerifyImageError).message).toContain("authenticated");
    }
  });

  it("throws NOT_FOUND when an index carries no real platform", async () => {
    const mockFetch = makeFetchReturning([
      okJson({
        manifests: [{ digest: amd64Dig, platform: { architecture: "unknown", os: "unknown" } }],
      }),
    ]);
    try {
      await fetchImageConfigLabels("ghcr.io", "buildcage/docker", digest, "token", mockFetch);
      assert.fail("should have thrown");
    } catch (err) {
      expect((err as VerifyImageError).code).toBe("NOT_FOUND");
    }
  });
});

// ── fail-closed paths ─────────────────────────────────────────────────────
//
// Every branch below refuses rather than returns, and coverage showed that
// none of them had ever run. They are what stands between a registry that
// answers oddly and an unverified image being pulled anyway, so each case
// pins the code that comes back, not just that something threw.

/** Drives a call and returns the VerifyImageError code, failing if it resolves. */
async function codeOfRejection(run: () => Promise<unknown>): Promise<string> {
  try {
    await run();
  } catch (err) {
    expect(err).toBeInstanceOf(VerifyImageError);
    return (err as VerifyImageError).code;
  }
  assert.fail("should have thrown");
}

const REJECTING_FETCH = async () => {
  throw new TypeError("fetch failed");
};

describe("fetchManifestDigest — unhandled status", () => {
  it("throws TRANSIENT for a non-ok status that is not 404, 401/403 or 5xx", async () => {
    const mockFetch = async () => ({ ok: false, status: 418, headers: { get: () => null } });
    expect(
      await codeOfRejection(() =>
        fetchManifestDigest("ghcr.io", "owner/repo", "2.1.0", "token", mockFetch),
      ),
    ).toBe("TRANSIENT");
  });
});

describe("fetchRegistryToken — network failure under Basic auth", () => {
  it("wraps a non-VerifyImageError as TRANSIENT", async () => {
    expect(
      await codeOfRejection(() =>
        fetchRegistryToken("ghcr.io", "owner/repo", "dXNlcjpwYXNz", REJECTING_FETCH),
      ),
    ).toBe("TRANSIENT");
  });
});

describe("fetchImageConfigLabels — refusals", () => {
  const digest = "sha256:" + "a".repeat(64);
  const call = (mockFetch: any) =>
    fetchImageConfigLabels("ghcr.io", "buildcage/docker", digest, "token", mockFetch);

  it("throws NOT_FOUND when the manifest names no config blob", async () => {
    const mockFetch = makeFetchReturning([{ ok: true, status: 200, json: async () => ({}) }]);
    expect(await codeOfRejection(() => call(mockFetch))).toBe("NOT_FOUND");
  });

  it("throws TRANSIENT for a non-ok status the registry JSON reader does not name", async () => {
    const mockFetch = makeFetchReturning([{ ok: false, status: 418, json: async () => ({}) }]);
    expect(await codeOfRejection(() => call(mockFetch))).toBe("TRANSIENT");
  });

  it("wraps a network failure as TRANSIENT rather than letting it escape untyped", async () => {
    expect(await codeOfRejection(() => call(REJECTING_FETCH))).toBe("TRANSIENT");
  });
});

describe("fetchBundle — fallback tag refusals", () => {
  const digest = "sha256:" + "a".repeat(64);
  const referrersMiss = { ok: false, status: 404, json: async () => ({}) };
  const call = (mockFetch: any) =>
    fetchBundle("ghcr.io", "buildcage/docker", digest, "token", mockFetch);

  it("throws TRANSIENT on 5xx", async () => {
    const mockFetch = makeFetchReturning([
      referrersMiss,
      { ok: false, status: 503, json: async () => ({}) },
    ]);
    expect(await codeOfRejection(() => call(mockFetch))).toBe("TRANSIENT");
  });

  it("throws TRANSIENT on 401/403, an auth problem rather than a missing bundle", async () => {
    const mockFetch = makeFetchReturning([
      referrersMiss,
      { ok: false, status: 403, json: async () => ({}) },
    ]);
    expect(await codeOfRejection(() => call(mockFetch))).toBe("TRANSIENT");
  });

  it("throws NOT_FOUND for any other non-ok status", async () => {
    const mockFetch = makeFetchReturning([
      referrersMiss,
      { ok: false, status: 418, json: async () => ({}) },
    ]);
    expect(await codeOfRejection(() => call(mockFetch))).toBe("NOT_FOUND");
  });

  it("wraps a network failure on the fallback tag as TRANSIENT", async () => {
    let i = 0;
    const mockFetch = async () => {
      if (i++ === 0) return referrersMiss;
      throw new TypeError("fetch failed");
    };
    expect(await codeOfRejection(() => call(mockFetch))).toBe("TRANSIENT");
  });

  it("throws NOT_FOUND when the legacy direct-layers manifest carries no bundle layer", async () => {
    const mockFetch = makeFetchReturning([
      referrersMiss,
      {
        ok: true,
        status: 200,
        json: async () => ({ layers: [{ mediaType: "application/octet-stream" }] }),
      },
    ]);
    expect(await codeOfRejection(() => call(mockFetch))).toBe("NOT_FOUND");
  });

  it("throws NOT_FOUND when the legacy manifest omits layers entirely", async () => {
    const mockFetch = makeFetchReturning([
      referrersMiss,
      { ok: true, status: 200, json: async () => ({}) },
    ]);
    expect(await codeOfRejection(() => call(mockFetch))).toBe("NOT_FOUND");
  });

  it("falls through to the tag when the referrers API answers without a manifests list", async () => {
    const mockFetch = makeFetchReturning([
      { ok: true, status: 200, json: async () => ({}) },
      { ok: false, status: 404, json: async () => ({}) },
    ]);
    expect(await codeOfRejection(() => call(mockFetch))).toBe("NOT_FOUND");
  });
});

describe("fetchBundle — descriptors the referrers tag index offers but cannot satisfy", () => {
  const digest = "sha256:" + "a".repeat(64);
  const subDig = "sha256:" + "b".repeat(64);
  const referrersMiss = { ok: false, status: 404, json: async () => ({}) };
  const IMAGE_MANIFEST = "application/vnd.oci.image.manifest.v1+json";
  const EMPTY_CONFIG = "application/vnd.oci.empty.v1+json";

  /** Referrers miss, then a tag index holding exactly these descriptors. */
  function indexOf(manifests: unknown[], ...rest: any[]) {
    return makeFetchReturning([
      referrersMiss,
      { ok: true, status: 200, json: async () => ({ manifests }) },
      ...rest,
    ]);
  }

  const call = (mockFetch: any) =>
    fetchBundle("ghcr.io", "buildcage/docker", digest, "token", mockFetch);

  it("skips a descriptor that is not an image manifest at all", async () => {
    const mockFetch = indexOf([
      { mediaType: "application/vnd.oci.image.index.v1+json", digest: subDig },
    ]);
    expect(await codeOfRejection(() => call(mockFetch))).toBe("NOT_FOUND");
  });

  it("skips a descriptor whose sub-manifest cannot be fetched", async () => {
    const mockFetch = indexOf(
      [{ mediaType: IMAGE_MANIFEST, artifactType: EMPTY_CONFIG, digest: subDig }],
      { ok: false, status: 404, json: async () => ({}) },
    );
    expect(await codeOfRejection(() => call(mockFetch))).toBe("NOT_FOUND");
  });

  it("skips a descriptor whose sub-manifest turns out to be some other artifact", async () => {
    const mockFetch = indexOf(
      [{ mediaType: IMAGE_MANIFEST, artifactType: EMPTY_CONFIG, digest: subDig }],
      { ok: true, status: 200, json: async () => ({ artifactType: "application/other" }) },
    );
    expect(await codeOfRejection(() => call(mockFetch))).toBe("NOT_FOUND");
  });

  it("skips a bundle sub-manifest that carries no bundle layer", async () => {
    const mockFetch = indexOf(
      [{ mediaType: IMAGE_MANIFEST, artifactType: EMPTY_CONFIG, digest: subDig }],
      {
        ok: true,
        status: 200,
        json: async () => ({ artifactType: BUNDLE_TYPE, layers: [{ mediaType: "text/plain" }] }),
      },
    );
    expect(await codeOfRejection(() => call(mockFetch))).toBe("NOT_FOUND");
  });

  it("skips a bundle sub-manifest that omits layers entirely", async () => {
    const mockFetch = indexOf(
      [{ mediaType: IMAGE_MANIFEST, artifactType: EMPTY_CONFIG, digest: subDig }],
      { ok: true, status: 200, json: async () => ({ artifactType: BUNDLE_TYPE }) },
    );
    expect(await codeOfRejection(() => call(mockFetch))).toBe("NOT_FOUND");
  });
});

describe("fetchBundle — bundle manifest refusals", () => {
  const digest = "sha256:" + "a".repeat(64);
  const manifestDig = "sha256:" + "b".repeat(64);
  const referrersHit = {
    ok: true,
    status: 200,
    json: async () => ({
      manifests: [
        {
          artifactType: BUNDLE_TYPE,
          mediaType: "application/vnd.oci.image.manifest.v1+json",
          digest: manifestDig,
        },
      ],
    }),
  };
  const call = (mockFetch: any) =>
    fetchBundle("ghcr.io", "buildcage/docker", digest, "token", mockFetch);

  it("throws TRANSIENT on 5xx", async () => {
    const mockFetch = makeFetchReturning([
      referrersHit,
      { ok: false, status: 502, json: async () => ({}) },
    ]);
    expect(await codeOfRejection(() => call(mockFetch))).toBe("TRANSIENT");
  });

  it("throws TRANSIENT on 401/403", async () => {
    const mockFetch = makeFetchReturning([
      referrersHit,
      { ok: false, status: 401, json: async () => ({}) },
    ]);
    expect(await codeOfRejection(() => call(mockFetch))).toBe("TRANSIENT");
  });

  it("throws TRANSIENT for any other non-ok status", async () => {
    const mockFetch = makeFetchReturning([
      referrersHit,
      { ok: false, status: 418, json: async () => ({}) },
    ]);
    expect(await codeOfRejection(() => call(mockFetch))).toBe("TRANSIENT");
  });

  it("throws NOT_FOUND when the bundle manifest holds no bundle layer", async () => {
    const mockFetch = makeFetchReturning([
      referrersHit,
      { ok: true, status: 200, json: async () => ({ layers: [{ mediaType: "text/plain" }] }) },
    ]);
    expect(await codeOfRejection(() => call(mockFetch))).toBe("NOT_FOUND");
  });

  it("throws NOT_FOUND when the bundle manifest omits layers entirely", async () => {
    const mockFetch = makeFetchReturning([
      referrersHit,
      { ok: true, status: 200, json: async () => ({}) },
    ]);
    expect(await codeOfRejection(() => call(mockFetch))).toBe("NOT_FOUND");
  });

  it("wraps a network failure as TRANSIENT", async () => {
    let i = 0;
    const mockFetch = async () => {
      if (i++ === 0) return referrersHit;
      throw new TypeError("fetch failed");
    };
    expect(await codeOfRejection(() => call(mockFetch))).toBe("TRANSIENT");
  });
});

describe("fetchBundle — bundle blob refusals", () => {
  const digest = "sha256:" + "a".repeat(64);
  const manifestDig = "sha256:" + "b".repeat(64);
  const blobDig = "sha256:" + "c".repeat(64);
  const call = (mockFetch: any) =>
    fetchBundle("ghcr.io", "buildcage/docker", digest, "token", mockFetch);

  /** Referrers hit, bundle manifest hit, then the blob response under test. */
  function upToBlob(blob: any) {
    return [
      {
        ok: true,
        status: 200,
        json: async () => ({
          manifests: [
            {
              artifactType: BUNDLE_TYPE,
              mediaType: "application/vnd.oci.image.manifest.v1+json",
              digest: manifestDig,
            },
          ],
        }),
      },
      {
        ok: true,
        status: 200,
        json: async () => ({ layers: [{ mediaType: BUNDLE_TYPE, digest: blobDig }] }),
      },
      blob,
    ];
  }

  it("throws TRANSIENT on 5xx", async () => {
    const mockFetch = makeFetchReturning(
      upToBlob({ ok: false, status: 500, json: async () => ({}) }),
    );
    expect(await codeOfRejection(() => call(mockFetch))).toBe("TRANSIENT");
  });

  it("throws NOT_FOUND for any other non-ok status", async () => {
    const mockFetch = makeFetchReturning(
      upToBlob({ ok: false, status: 404, json: async () => ({}) }),
    );
    expect(await codeOfRejection(() => call(mockFetch))).toBe("NOT_FOUND");
  });

  it("wraps a network failure as TRANSIENT", async () => {
    const responses = upToBlob(() => {
      throw new TypeError("fetch failed");
    });
    expect(await codeOfRejection(() => call(makeFetchReturning(responses)))).toBe("TRANSIENT");
  });
});
