/** Declared as properties, not methods, so a caller can pass one on its own:
 *  nothing here reads `this`. */
export interface Annotation {
  notice: (message: string) => void;
  warning: (message: string) => void;
  error: (message: string) => void;
}

/**
 * Build a GitHub Actions annotation emitter. When `enabled` is false, every
 * method is a no-op — used to suppress annotations when this script isn't
 * running as the real action.
 */
export function createAnnotation(enabled: boolean): Annotation {
  if (!enabled) {
    return { notice() {}, warning() {}, error() {} };
  }
  return {
    notice(message: string) {
      console.log(`::notice::${message}`);
    },
    warning(message: string) {
      console.log(`::warning::${message}`);
    },
    error(message: string) {
      console.log(`::error::${message}`);
    },
  };
}

/**
 * The always-on emitter, for the messages that are printed whether or not
 * this is a real action run: a deprecated input's migration notice, a
 * library-layer warning, a fatal error on the way out. Anything a caller can
 * choose to suppress takes an Annotation as an argument instead.
 *
 * Exists so the `::notice::`/`::warning::`/`::error::` spelling lives in this
 * file alone, rather than being written out at each call site.
 */
export const annotate: Annotation = createAnnotation(true);
