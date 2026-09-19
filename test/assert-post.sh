#!/bin/bash
# Verifies setup/src/post.ts (run by the caller beforehand) removed the
# builder container. Checks only "buildcage", not "buildcage-proxy" —
# post.ts's own down only knows setup/compose.yaml's "builder" service;
# buildcage-proxy is started separately by the Makefile's dev-only root
# compose.yaml and isn't post.ts's responsibility.
set -euo pipefail
source "$(dirname "$0")/helpers.sh"

BUILDER_NAME="${BUILDER_NAME:-buildcage}"

echo ""
echo "[setup post] verifying post.ts actually removed the builder container:"
if docker inspect "$BUILDER_NAME" >/dev/null 2>&1; then
  fail "$BUILDER_NAME still exists after post.ts cleanup"
else
  pass "$BUILDER_NAME removed by post.ts"
fi

assert_results
