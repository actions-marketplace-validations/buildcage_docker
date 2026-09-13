// Regenerates builder.json: moby's own default seccomp profile for the pinned
// MOBY_PROFILES_SECCOMP_VERSION, plus the two syscalls runc needs and that
// profile refuses at every capability. Run via `make seccomp_profile`; CI
// asserts the committed file still matches.
//
// The profile is emitted in Docker's extended format (archMap, includes,
// excludes) rather than plain OCI seccomp, because the daemon resolves the
// capability conditions itself against the container's actual capability set.
// With SYS_ADMIN held that already unlocks mount, umount2, unshare, setns and
// clone, so the additions below are all the builder needs.
import { writeFileSync } from "node:fs";

// The three keyctl operations runc performs while setting a step up: it joins
// a fresh session keyring, reads that keyring's description, then narrows its
// permissions. A rule's args are ANDed together, so each operation needs its
// own entry.
const RUNC_KEYCTL_OPS = {
  KEYCTL_JOIN_SESSION_KEYRING: 1,
  KEYCTL_SETPERM: 5,
  KEYCTL_DESCRIBE: 6,
};

// Appended as their own blocks, so the whole diff against upstream is these
// entries and nothing else.
const additions = [
  // runc pivots into the step's rootfs. Nothing in the default profile allows
  // this one, at any capability.
  { names: ["pivot_root"], action: "SCMP_ACT_ALLOW" },
  // runc gives each step a fresh session keyring unless it is told not to, and
  // BuildKit does not tell it. Ordinarily those calls land before runc installs
  // the step's own filter, but here runc is itself running under the builder's,
  // so every build fails at its first RUN without them. Narrowed to the
  // operations runc actually issues rather than opening the keyring API, and
  // add_key/request_key stay refused either way.
  ...Object.values(RUNC_KEYCTL_OPS).map((op) => ({
    names: ["keyctl"],
    action: "SCMP_ACT_ALLOW",
    args: [{ index: 0, value: op, op: "SCMP_CMP_EQ" }],
  })),
];

const version = process.argv[2];
if (!version) {
  console.error("usage: gen-profile.mjs <seccomp module version, e.g. v0.2.3>");
  process.exit(1);
}

// moby/profiles carries one module per directory, so the seccomp module's
// releases are tagged `seccomp/vX.Y.Z` rather than plain `vX.Y.Z`.
const url = `https://raw.githubusercontent.com/moby/profiles/seccomp/${version}/seccomp/default.json`;
const res = await fetch(url);
if (!res.ok) {
  console.error(`gen-profile: GET ${url} -> ${res.status}`);
  process.exit(1);
}
const profile = JSON.parse(await res.text());

profile.syscalls.push(...additions);

writeFileSync(new URL("builder.json", import.meta.url), `${JSON.stringify(profile, null, "\t")}\n`);
