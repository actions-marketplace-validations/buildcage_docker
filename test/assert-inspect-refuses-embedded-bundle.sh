#!/bin/bash
set -euo pipefail
source "$(dirname "$0")/helpers.sh"

# Builds Dockerfile.inspect-embedded-bundle and expects it to fail: the layer
# sweep can take the CA out of a text bundle but not out of a binary without
# shifting everything after it, so the step that packed the bundle into an
# archive has to fail rather than commit the archive, stripped or not.

BUILDER="${BUILDER_NAME:-buildcage}"
PLATFORM="${TEST_PLATFORM:-linux/arm64}"

echo ""
echo "=== A Binary Embedding The Bundle Fails The Build ==="
echo ""

set +e
OUT=$(docker buildx build --no-cache \
  --builder "$BUILDER" \
  --platform "$PLATFORM" \
  --progress=plain -f "$(dirname "$0")/Dockerfile.inspect-embedded-bundle" "$(dirname "$0")" 2>&1)
CODE=$?
set -e
echo "$OUT" | tail -20

if [ "$CODE" -eq 0 ]; then
  fail "the build succeeded, so the archive was committed"
else
  pass "the build failed"
fi

if echo "$OUT" | grep -q "cannot strip: /app/bundle.tar"; then
  pass "the failure names the archive as the file it could not strip"
else
  fail "the build log does not name /app/bundle.tar as unstrippable"
fi

assert_results
