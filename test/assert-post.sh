#!/bin/bash
# Verifies setup/src/post.ts (run by the caller beforehand) removed the
# builder container. Checks only "buildcage", not "buildcage-proxy" —
# post.ts's own down only knows setup/compose.yaml's "builder" service;
# buildcage-proxy is started separately by the Makefile's dev-only root
# compose.yaml and isn't post.ts's responsibility.
set -euo pipefail

FAILURES=0

BUILDER_NAME="${BUILDER_NAME:-buildcage}"

echo ""
echo "[setup post] verifying post.ts actually removed the builder container:"
if docker inspect "$BUILDER_NAME" >/dev/null 2>&1; then
  echo "  FAIL  $BUILDER_NAME still exists after post.ts cleanup"
  FAILURES=$((FAILURES + 1))
else
  echo "  PASS  $BUILDER_NAME removed by post.ts"
fi
echo ""

if [ "$FAILURES" -gt 0 ]; then
  echo "❌ FAILED: $FAILURES assertion(s) failed"
  exit 1
fi
echo "✅ All assertions passed."
echo ""
