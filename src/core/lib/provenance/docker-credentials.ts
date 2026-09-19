/** The registry credential `docker login` leaves behind. */

import { readFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

// Narrowed to the one overload of node:fs's readFileSync this module actually
// calls, so tests can pass a simple stub instead of the fully overloaded type.
export type ReadFileSyncLike = (path: string, encoding: string) => string;

/**
 * Read the base64 Basic-auth credential for ghcr.io from Docker's config.json.
 * Returns the raw `auth` string (base64) if found, or null if not logged in.
 * Credential helpers (credsStore/credHelpers) are not supported: only direct
 * base64 auth written by `docker login` / `docker/login-action` is detected.
 */
export function readGhcrBasicAuth(
  _env: NodeJS.ProcessEnv = process.env,
  _readFileSync: ReadFileSyncLike = readFileSync as ReadFileSyncLike,
): string | null {
  try {
    const configDir = _env.DOCKER_CONFIG ?? path.join(os.homedir(), ".docker");
    const config: { auths?: Record<string, { auth?: string }> } = JSON.parse(
      _readFileSync(path.join(configDir, "config.json"), "utf8"),
    );
    for (const [key, value] of Object.entries(config.auths ?? {})) {
      const normalized = key.replace(/^https?:\/\//, "").replace(/\/$/, "");
      if (normalized === "ghcr.io" && typeof value.auth === "string" && value.auth) {
        return value.auth;
      }
    }
    return null;
  } catch {
    return null;
  }
}
