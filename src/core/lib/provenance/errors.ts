import { ActionError } from "../errors.ts";

/** TRANSIENT is a network or 5xx error, never "resource absent". */
export type VerifyImageErrorCode = "NOT_FOUND" | "TRANSIENT" | "TOKEN_ERROR" | "VERIFY_FAILED";

/**
 * Intentional error in the image provenance verification flow: Sigstore
 * bundle fetch and verify, OCI registry lookups, image ref resolution.
 */
export class VerifyImageError extends ActionError<VerifyImageErrorCode> {}

/** UNVERIFIABLE_REF: the action ref is a branch or local path, so nothing can verify it. */
export type ProvenanceErrorCode = VerifyImageErrorCode | "UNVERIFIABLE_REF";

/**
 * Thrown by verifyImageDigestOrThrow (see verify-image.ts) when image
 * provenance can't be established. This is the one a caller's own top-level
 * catch sees: every VerifyImageError is translated on the way out, by
 * toProvenanceError.
 */
export class ProvenanceError extends ActionError<ProvenanceErrorCode> {}
