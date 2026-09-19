export interface LocalImageOverride {
  imageRef: string;
  pullPolicy: "never";
}

/**
 * Reads BUILDCAGE_LOCAL_IMAGE_REF from the given env. Kept in its own module
 * so a normal build can exclude it entirely; see readLocalImageOverride in
 * lib/local-image.ts.
 */
export function readLocalImageOverride(env: NodeJS.ProcessEnv): LocalImageOverride | null {
  const ref = env.BUILDCAGE_LOCAL_IMAGE_REF;
  if (!ref) return null;
  return { imageRef: ref, pullPolicy: "never" };
}
