#!/bin/sh
set -e

# Assigned here rather than by Compose IPAM, so 10.200.0.0/24 stays out of the
# daemon's address space and several worktrees can run the suite at once.
ip addr add "$TEST_NET_ADDR" dev eth0

# cert.pem/key.pem are static fixtures (see cert.pem's header comment to
# regenerate). The explicit-engine builder container trusts this exact file
# as an extra CA (BUILDKIT_PROXY_EXTRA_CA_FILE, compose.test-explicit.yaml
# only), because BuildKit's internal MITM proxy makes its own upstream TLS
# connection here and validates the certificate normally, so it must both
# match the requested hostname and be trusted. universal-engine tests use
# test/test-server/ instead: HAProxy never terminates TLS, so clients there
# pass --no-check-certificate and this certificate is never validated.
echo "Starting test-server..."
exec nginx -g 'daemon off;'
