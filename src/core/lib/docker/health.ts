/**
 * Turns `docker inspect`'s .State into the reason a container isn't usable:
 * `compose up --wait` fails identically whether Docker is missing, the image
 * won't start or the healthcheck never passed.
 */
export interface ContainerState {
  /** .Status: "running", "exited", … */
  status: string;
  exitCode: number | null;
  /** .Health.Status, null on an image with no healthcheck. */
  health: string | null;
  lastHealthOutput: string | null;
}

export function buildDockerInspectStateArgs(containerName: string): string[] {
  return ["inspect", "--format", "{{json .State}}", containerName];
}

interface RawHealthLog {
  Output?: unknown;
}

interface RawState {
  Status?: unknown;
  ExitCode?: unknown;
  Health?: { Status?: unknown; Log?: RawHealthLog[] };
}

/** Null for anything that isn't a state object: a missing container prints
 *  nothing to stdout. */
export function parseContainerState(inspectOutput: string): ContainerState | null {
  let raw: RawState;
  try {
    raw = JSON.parse(inspectOutput) as RawState;
  } catch {
    return null;
  }
  if (!raw || typeof raw !== "object" || typeof raw.Status !== "string") return null;

  const log = Array.isArray(raw.Health?.Log) ? raw.Health.Log : [];
  const lastOutput = log.length > 0 ? log[log.length - 1]?.Output : undefined;
  return {
    status: raw.Status,
    exitCode: typeof raw.ExitCode === "number" ? raw.ExitCode : null,
    health: typeof raw.Health?.Status === "string" ? raw.Health.Status : null,
    lastHealthOutput: typeof lastOutput === "string" ? lastOutput.trim() || null : null,
  };
}

export function isContainerReady(state: ContainerState): boolean {
  return state.status === "running" && state.health !== "unhealthy" && state.health !== "starting";
}

export interface DescribeContainerStartFailureOptions {
  /** How the message names the container, e.g. "builder". */
  role: string;
  containerName: string;
}

export function describeContainerStartFailure(
  state: ContainerState,
  { role, containerName }: DescribeContainerStartFailureOptions,
): string {
  const subject = `Buildcage's ${role} container (${containerName})`;
  const probe = state.lastHealthOutput
    ? ` Last health check output: ${JSON.stringify(state.lastHealthOutput)}.`
    : "";
  const evidence = " Its log is printed above.";

  if (state.status !== "running") {
    const code = state.exitCode === null ? "" : ` with code ${state.exitCode}`;
    return `${subject} stopped${code} instead of starting up.${probe}${evidence}`;
  }
  if (!isContainerReady(state)) {
    return `${subject} started but never became ready.${probe}${evidence}`;
  }
  // Running and not unhealthy, so the failure was something else Docker
  // already reported: a name collision with a container outside this project,
  // for one.
  return `${subject} is running, but \`docker compose up\` failed. See the Docker output above.${probe}`;
}
