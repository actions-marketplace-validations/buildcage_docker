/**
 * Every `core.getInput` the report action makes, in one place, so that what
 * this action reads is answerable from one file rather than by grepping the
 * entry point.
 *
 * Separate from src/lib/inputs.ts because this is a separate action with a
 * separate bundle: importing the setup action's would pull rule parsing into
 * report's dist for one string. The default they must agree on is shared as a
 * constant instead.
 */
import * as core from "@actions/core";

import { annotate } from "#core/lib/actions/annotation.ts";
import { DEFAULT_BUILDER_NAME } from "#core/lib/docker/report-source.ts";

/** Narrowed to what this module needs, so a test can pass a plain lookup. */
export type GetInput = (name: string) => string;

/** The spellings @actions/core's own getBooleanInput accepts. */
const TRUE_INPUTS = ["true", "True", "TRUE"];
const FALSE_INPUTS = ["false", "False", "FALSE"];

export function readBuilderName(getInput: GetInput = core.getInput): string {
  return getInput("builder_name") || DEFAULT_BUILDER_NAME;
}

export interface TrafficArtifactInputs {
  wanted: boolean;
  /** Undefined leaves the retention to the repository's own default. */
  retentionDays?: number;
}

export function readTrafficArtifactInputs(
  getInput: GetInput = core.getInput,
): TrafficArtifactInputs {
  return {
    wanted: readBoolean("upload_traffic_artifact", getInput),
    retentionDays: readRetentionDays(getInput),
  };
}

/**
 * An unset input is a no: the dev and test invocations run this from source
 * rather than through action.yml's own defaults. Anything else unreadable is
 * a typo, and saying so beats an artifact that never appears.
 */
function readBoolean(name: string, getInput: GetInput): boolean {
  const value = getInput(name);
  if (TRUE_INPUTS.includes(value)) {
    return true;
  }
  if (value !== "" && !FALSE_INPUTS.includes(value)) {
    annotate.warning(
      `${name} must be true or false, not ${JSON.stringify(value)}. Reading it as false.`,
    );
  }
  return false;
}

function readRetentionDays(getInput: GetInput): number | undefined {
  const value = getInput("traffic_artifact_retention_days");
  if (value === "") {
    return undefined;
  }
  const days = Number(value);
  if (!Number.isInteger(days) || days <= 0) {
    annotate.warning(
      `traffic_artifact_retention_days must be a whole number of days above zero, not ` +
        `${JSON.stringify(value)}. Leaving the retention to the repository's own default.`,
    );
    return undefined;
  }
  return days;
}
