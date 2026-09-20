//go:build testhooks

// This file is a test-only escape hatch and is physically absent from the
// published image: it is compiled in only when the Docker build passes
// `--build-arg BUILDKIT_PROXY_BUILD_TAGS=testhooks` (see compose.test-explicit.yaml),
// which the release build from docker/explicit/Dockerfile never does. It exists
// because BuildKit's own internal MITM proxy (--proxy-network)
// validates its upstream TLS connection with Go's default certificate
// verification and has no flag or config to relax that (verified against
// util/network/proxyprovider/provider_linux.go's newProxyTransport(), which
// sets no TLSClientConfig at all), so a self-signed integration-test server
// cert can only be trusted by giving buildkitd's own process a CA bundle
// that includes it.
package main

import (
	"fmt"
	"os"
)

// buildkitdEnv merges the CA named by BUILDKIT_PROXY_EXTRA_CA_FILE into
// buildkitd's child-process environment. The system CAs are always included
// alongside it, so nothing else loses trust.
func buildkitdEnv() ([]string, error) {
	extraCAFile := os.Getenv("BUILDKIT_PROXY_EXTRA_CA_FILE")
	if extraCAFile == "" {
		return os.Environ(), nil
	}
	const systemBundle = "/etc/ssl/certs/ca-certificates.crt"
	base, err := os.ReadFile(systemBundle)
	if err != nil {
		return nil, fmt.Errorf("reading system CA bundle %s: %w", systemBundle, err)
	}
	extra, err := os.ReadFile(extraCAFile)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", extraCAFile, err)
	}
	combinedPath := "/etc/buildkit/combined-ca-bundle.pem"
	combined := append(append([]byte{}, base...), extra...)
	if err := os.WriteFile(combinedPath, combined, 0o644); err != nil {
		return nil, fmt.Errorf("writing %s: %w", combinedPath, err)
	}
	return append(os.Environ(), "SSL_CERT_FILE="+combinedPath), nil
}
