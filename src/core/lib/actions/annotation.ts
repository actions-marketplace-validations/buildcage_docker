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
 *
 * This is what a step hands down for everything that belongs to the run it is
 * setting up; a message that has to be printed even when this isn't the real
 * action takes one of `annotate`'s methods instead.
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
 * The always-on emitter, for the messages that are printed whether or not this
 * is a real action run: a deprecated input's migration notice, a fatal error on
 * the way out.
 *
 * Only the module that assembles an action's steps — its entry point, or
 * wherever that body was extracted to — and `fatal.ts` may name it. The modules
 * they call don't choose where a message goes: they take the sink as an
 * argument, an `Annotation` for what the caller can suppress and one of
 * `annotate`'s methods for what it can't.
 *
 * Exists so the `::notice::`/`::warning::`/`::error::` spelling lives in this
 * file alone, rather than being written out at each call site.
 */
export const annotate: Annotation = createAnnotation(true);
