#!/bin/bash
# Verifies src/post.ts (run by the caller beforehand) removed the builder
# container: post.ts's own down only knows docker/compose.action.yaml's
# "builder" service.
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
