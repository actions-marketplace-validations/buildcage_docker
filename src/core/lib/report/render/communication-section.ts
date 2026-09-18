/**
 * The `💬 Communication details` section's own markup.
 *
 * A renderer opens the section with this exact text, and
 * truncate-communication-details.ts finds it again by searching the finished
 * report for it, so the two sides have to agree byte for byte.
 */

export const COMMUNICATION_DETAILS_OPEN =
  "<details>\n<summary>\u{1F4AC} Communication details</summary>\n\n";
export const COMMUNICATION_DETAILS_CLOSE = "</details>\n";

/** Wrap a rendered body in the section, blank line before it included. */
export function wrapCommunicationDetails(body: string): string {
  return `\n${COMMUNICATION_DETAILS_OPEN}${body}${COMMUNICATION_DETAILS_CLOSE}`;
}
