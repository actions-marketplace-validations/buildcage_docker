import { ActionError } from "../errors.ts";

/**
 * Codes both error classes below carry:
 *   NOT_FOUND:      resource does not exist (missing tag or bundle)
 *   TRANSIENT:      network or 5xx error; do not treat as "resource absent"
 *   TOKEN_ERROR:    registry token endpoint returned a client error
 *   VERIFY_FAILED:  Sigstore bundle verification failed
 */
export type VerifyImageErrorCode = "NOT_FOUND" | "TRANSIENT" | "TOKEN_ERROR" | "VERIFY_FAILED";

/**
 * Intentional error in the image provenance verification flow: Sigstore
 * bundle fetch and verify, OCI registry lookups, image ref resolution.
 */
export class VerifyImageError extends ActionError<VerifyImageErrorCode> {}

/** The codes above, plus the one only the caller-facing error can carry:
 *   UNVERIFIABLE_REF: action ref cannot be verified (branch / local path) */
export type ProvenanceErrorCode = VerifyImageErrorCode | "UNVERIFIABLE_REF";

/**
 * Thrown by verifyImageDigestOrThrow (see verify-image.ts) when image
 * provenance can't be established. This is the one a caller's own top-level
 * catch sees: every VerifyImageError is translated on the way out, by
 * toProvenanceError.
 */
export class ProvenanceError extends ActionError<ProvenanceErrorCode> {}
