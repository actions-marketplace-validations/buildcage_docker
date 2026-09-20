//go:build !testhooks

package main

import "os"

// buildkitdEnv returns the environment for the buildkitd child process, with
// no extra CA trust. See ca_testhooks.go for the test-only variant.
func buildkitdEnv() ([]string, error) {
	return os.Environ(), nil
}
