// Regenerates THIRD_PARTY_LICENSES_NPM from .glf.jsonc. Run as the last step
// of `vp run build`; CI asserts the committed file still matches.
//
// The wrapper exists for the exit code. generate-license-file reports a package
// whose license text it cannot find on stderr and then leaves it out of the
// output, exiting 0 even under --ci, so without this the first unlicensed
// dependency would go missing from a green build.
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));

const { error, status, stderr } = spawnSync(
  fileURLToPath(new URL("../node_modules/.bin/generate-license-file", import.meta.url)),
  ["--ci", "--no-spinner", "--overwrite"],
  { cwd: root, encoding: "utf8" },
);

if (error) {
  throw error;
}

process.stderr.write(stderr);

if (status !== 0) {
  process.exit(status ?? 1);
}

if (stderr.trim() !== "") {
  console.error(
    "\nThe licenses above could not be collected, so those packages are missing " +
      "from THIRD_PARTY_LICENSES_NPM. Add the text under licenses/ and point at " +
      "it from .glf.jsonc's `replace`.",
  );
  process.exit(1);
}
