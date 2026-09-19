#!/bin/bash
# Verifies a build through the builder lands on the host's own architecture
# when the client names no platform, and on the named one when it does — the
# builder runs BuildKit itself, so a broken platform hand-off would silently
# produce an image for the wrong architecture rather than fail.
set -euo pipefail
source "$(dirname "$0")/helpers.sh"

NATIVE_IMAGE="$1"
CROSS_IMAGE="$2"
CROSS_PLATFORM="$3"

# `docker version` and a platform string name an architecture the way Go does;
# `uname -m` inside the image names it the way the kernel does.
uname_arch() {
  case "${1##*/}" in
    amd64) echo x86_64 ;;
    arm64) echo aarch64 ;;
    *)
      echo "unsupported architecture: $1" >&2
      exit 1
      ;;
  esac
}

assert_arch() {
  local label="$1" expected="$2" actual="$3"
  if [ "$actual" = "$expected" ]; then
    pass "$label is $actual"
  else
    fail "$label is $actual, expected $expected"
  fi
}

echo ""
echo "=== Multi-Architecture Build Assertions ==="
echo ""

NATIVE_ARCH=$(uname_arch "$(docker version --format '{{.Server.Arch}}')")
assert_arch "[default platform] the image built without --platform" \
  "$NATIVE_ARCH" "$(docker run --rm "$NATIVE_IMAGE" uname -m)"

CROSS_ARCH=$(uname_arch "$CROSS_PLATFORM")
assert_arch "[cross platform] the image built for $CROSS_PLATFORM" \
  "$CROSS_ARCH" "$(docker run --rm --platform "$CROSS_PLATFORM" "$CROSS_IMAGE" uname -m)"

assert_results
