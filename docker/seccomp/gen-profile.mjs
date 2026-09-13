// Regenerates builder.json, the builder container's seccomp profile. Run via
// `make seccomp_profile`; CI asserts the committed file still matches.
//
// The output keeps Docker's extended format (archMap, includes, excludes)
// rather than plain OCI seccomp, because the daemon resolves the capability
// conditions itself. Holding SYS_ADMIN already unlocks mount, umount2,
// unshare, setns and clone there, which is why so little has to be added.
import { writeFileSync } from "node:fs";

// What runc issues per step: join a fresh session keyring, read its
// description, narrow its permissions. A rule's args are ANDed together, so
// each operation needs an entry of its own.
const RUNC_KEYCTL_OPS = {
  KEYCTL_JOIN_SESSION_KEYRING: 1,
  KEYCTL_SETPERM: 5,
  KEYCTL_DESCRIBE: 6,
};

// Appended as their own blocks, so the whole diff against upstream is these
// entries and nothing else.
const additions = [
  // runc pivots into the step's rootfs.
  { names: ["pivot_root"], action: "SCMP_ACT_ALLOW" },
  // runc makes each step a session keyring unless told not to, and BuildKit
  // does not tell it. Those calls normally land before runc installs the step's
  // own filter, but here runc runs under the builder's, so every build fails at
  // its first RUN without them. add_key and request_key stay refused.
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
