#!/bin/bash
set -euo pipefail
source "$(dirname "$0")/helpers.sh"

# Regression guard for the inspect engine's per-RUN-step CA injection
# (docker/inspect/buildcage-runc/inject.go): the environment it sets lives only
# in the transient OCI process spec, never in what BuildKit commits, and the
# certificate is taken back out of the step's own layer, by reading that layer
# rather than a list of paths (layer.go), before the snapshot is taken. This
# checks that both hold against the real image this test build produced.

IMAGE="${1:-buildcage-test}"

echo ""
echo "=== No CA Residue In The Built Image ($IMAGE) ==="
echo ""

# The standalone file NODE_EXTRA_CA_CERTS/DENO_CERT were pointed at, only
# created when the image had none of its own, removed again once the step
# that needed it ends.
if docker run --rm "$IMAGE" sh -c 'test -e /etc/buildcage-ca.pem'; then
  fail "/etc/buildcage-ca.pem is present in the built image"
else
  pass "no standalone buildcage CA file in the built image"
fi

# The certificate appended to whichever system CA bundle the rootfs had,
# removed by the same undo. The CA is generated per build, so a copy of it
# anywhere in a bundle is one the undo failed to take back out.
BUILDER="${BUILDER_NAME:-buildcage}"
CA_LINE=$(docker exec "$BUILDER" cat /opt/buildcage/ca.pem 2>/dev/null \
  | awk '/-----BEGIN CERTIFICATE-----/{getline; print; exit}' || true)
if [ -z "$CA_LINE" ]; then
  fail "could not read the injected CA out of $BUILDER, so this cannot be checked"
elif docker run --rm -e CA_LINE="$CA_LINE" "$IMAGE" sh -c '
  for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt \
           /etc/ssl/ca-bundle.pem /etc/pki/tls/cacert.pem /etc/ssl/cert.pem; do
    [ -f "$f" ] && grep -qF "$CA_LINE" "$f" && exit 0
  done
  exit 1
'; then
  fail "the buildcage CA is still present in a system CA bundle"
else
  pass "no buildcage CA in any system CA bundle"
fi

# A copy of the store the step made outside it (see the fixture Dockerfiles).
# Nothing lists those paths, so they are reached only by reading the step's own
# layer back before BuildKit commits it. The Debian fixture also re-armours the
# certificate as a TRUSTED CERTIFICATE, the shape a RHEL trust rebuild leaves
# behind, which matches neither the original block nor its whole base64.
#
# The fixtures fail the build if they cannot make these, so finding none here
# means the fixture has gone stale rather than that there is nothing to check.
COPIES=$(docker run --rm "$IMAGE" sh -c 'ls /app/*.pem 2>/dev/null' || true)
if [ -z "$CA_LINE" ]; then
  : # already reported above; an empty pattern would match every file
elif [ -z "$COPIES" ]; then
  fail "the fixture left no copy of the store under /app, so this cannot be checked"
elif docker run --rm -e CA_LINE="$CA_LINE" "$IMAGE" sh -c '
  for f in /app/*.pem; do
    grep -qF "$CA_LINE" "$f" && exit 0
  done
  exit 1
'; then
  fail "the buildcage CA is still present in a copy of the store: $(tr "\n" " " <<< "$COPIES")"
else
  pass "no buildcage CA in the step's own copies of the store: $(tr "\n" " " <<< "$COPIES")"
fi

# The CA-trust variables inject.go sets only ever reach the transient RUN-step
# process spec, never the image config BuildKit writes. Confirmed here against
# a real built image.
LEAKED_ENV=$(docker inspect "$IMAGE" --format '{{range .Config.Env}}{{println .}}{{end}}' \
  | grep -E '^(NODE_EXTRA_CA_CERTS|DENO_CERT|REQUESTS_CA_BUNDLE|PIP_CERT|SSL_CERT_FILE)=' || true)
if [ -n "$LEAKED_ENV" ]; then
  fail "a buildcage CA-trust env var leaked into the image config: $LEAKED_ENV"
else
  pass "no buildcage CA-trust env var in the image config"
fi

assert_results
