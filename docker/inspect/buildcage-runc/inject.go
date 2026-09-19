package main

import (
	"os"
	"path/filepath"
)

// File the container is pointed at when a variable was not already set and the
// tool needs one of its own. Removed again when the step ends.
const ownCAPath = "/etc/buildcage-ca.pem"

// How each variable is treated when the image or Dockerfile did not set it,
// and what it falls back to when there is no system CA store to work with.
//
// The distinction between the kinds is what the variable means to the tool
// that reads it: NODE_EXTRA_CA_CERTS and DENO_CERT are added to a built-in
// set, so pointing them at a file holding only this CA leaves everything
// else trusted, store or no store. The others replace the bundle outright:
// with a store, they are pointed at it (which by then carries the CA plus
// the real public roots); with no store there is nothing left that still
// carries those roots, so they fall back to the same proxy-CA-only file
// NODE_EXTRA_CA_CERTS/DENO_CERT use. That covers ordinary HTTP(S) traffic
// (inspect re-signs all of it with this same CA) but not a passthrough
// connection's real certificate — see "No system CA store" in
// docs/inspect-engine.md for exactly which requests that leaves unable to
// verify.
type unsetBehaviour int

const (
	// The tool reads the system store on its own; with no store, falls back
	// to proxy-CA-only trust the same way pointAtSystemStore does.
	leaveUnset unsetBehaviour = iota
	// Point at a file holding only this CA, added to the tool's own set.
	pointAtOwnCA
	// Point at the system store, which replaces the tool's bundle; with no
	// store, falls back to the same proxy-CA-only file as pointAtOwnCA.
	pointAtSystemStore
)

var caVariables = []struct {
	name      string
	whenUnset unsetBehaviour
}{
	{"NODE_EXTRA_CA_CERTS", pointAtOwnCA},
	{"DENO_CERT", pointAtOwnCA},
	{"CURL_CA_BUNDLE", leaveUnset},
	{"REQUESTS_CA_BUNDLE", pointAtSystemStore},
	{"PIP_CERT", pointAtSystemStore},
	// OpenSSL's own override, replacing rather than adding to the default
	// search path: also read by Go's crypto/x509 on Unix, Ruby, wget, and
	// Rust's rustls-native-certs.
	{"SSL_CERT_FILE", pointAtSystemStore},
}

// inject makes the step trust the proxy's CA and returns a function that
// finishes the injection once the step has exited: diffing each mirrored
// directory against its pre-step state and writing back only what changed.
// A non-nil error from it means the write-back itself failed and the build
// must not proceed with a possibly half-written layer.
func inject(bundle string, ca []byte) (func() error, error) {
	s, err := loadSpec(bundle)
	if err != nil {
		return nil, err
	}

	// A store's absence is not fatal: the store itself is simply not an
	// append target, and every otherwise-unset variable falls back to the
	// proxy-CA-only file instead (see the unsetBehaviour comment above).
	systemStore, systemStorePath, storeErr := findSystemStore(s.rootfs)
	haveSystemStore := storeErr == nil
	if !haveSystemStore {
		logf("no system CA store in %s (%v); falling back to proxy-CA-only trust", s.rootfs, storeErr)
	}

	// Every bundle the CA has to go into, keyed by resolved path so a file
	// named by two variables is only written once.
	targets := map[string]bool{}
	if haveSystemStore {
		targets[systemStore] = true
	}
	newEnv := map[string]string{}
	createdOwnCA := ""

	// setOwnCA points variableName at ownCAPath, writing it once and sharing
	// it across every variable that falls back to it.
	setOwnCA := func(variableName string) {
		resolved, err := resolveInRoot(s.rootfs, ownCAPath)
		if err != nil {
			logf("cannot place %s: %v", ownCAPath, err)
			return
		}
		// More than one variable can take this path, and all of them share
		// the file: only the first to get here writes it.
		if createdOwnCA == "" {
			if _, err := os.Stat(resolved); err == nil {
				logf("%s already exists; not setting %s", ownCAPath, variableName)
				return
			}
			if err := os.WriteFile(resolved, ca, 0o644); err != nil {
				logf("cannot write %s: %v", ownCAPath, err)
				return
			}
			createdOwnCA = resolved
		}
		newEnv[variableName] = ownCAPath
	}

	for _, variable := range caVariables {
		if value, set := s.env[variable.name]; set && value != "" {
			// Already pointed somewhere: add to that file rather than
			// redirecting the variable, which would discard whatever the
			// author put there.
			resolved, err := resolveInRoot(s.rootfs, value)
			if err != nil {
				logf("%s=%s could not be resolved inside the rootfs (%v); leaving it alone",
					variable.name, value, err)
				continue
			}
			targets[resolved] = true
			continue
		}
		switch variable.whenUnset {
		case leaveUnset:
			if !haveSystemStore {
				setOwnCA(variable.name)
			}
		case pointAtSystemStore:
			if haveSystemStore {
				newEnv[variable.name] = systemStorePath
			} else {
				setOwnCA(variable.name)
			}
		case pointAtOwnCA:
			setOwnCA(variable.name)
		}
	}

	var binds []*dirBind
	for hostDir, files := range groupTargetsByDir(targets) {
		containerDir := containerPathOf(s.rootfs, hostDir)
		if containerDir == "/" {
			logf("refusing to bind the container root; skipping CA injection for %v", files)
			continue
		}
		if s.mountConflicts(containerDir) {
			logf("a mount already covers %s; skipping CA injection there", containerDir)
			continue
		}

		scratch, err := newScratchDir(bundle)
		if err != nil {
			logf("cannot create a scratch directory for %s: %v", containerDir, err)
			continue
		}
		names := make([]string, len(files))
		for i, f := range files {
			names[i] = filepath.Base(f)
		}
		b := &dirBind{
			rootfs:       s.rootfs,
			hostDir:      hostDir,
			containerDir: containerDir,
			scratchDir:   scratch,
			bundleFiles:  names,
			custom:       !(haveSystemStore && hostDir == filepath.Dir(systemStore)),
		}
		if err := b.prepare(ca); err != nil {
			logf("cannot prepare CA injection for %s: %v", containerDir, err)
			b.cleanup()
			continue
		}
		s.addBindMount(containerDir, scratch)
		binds = append(binds, b)
	}

	s.setEnv(newEnv)
	if err := s.save(); err != nil {
		logf("cannot update the process spec: %v", err)
	}

	return func() error {
		var firstErr error
		for _, b := range binds {
			if err := b.finish(); err != nil {
				logf("CA write-back failed for %s: %v", b.containerDir, err)
				if firstErr == nil {
					firstErr = err
				}
			}
			b.cleanup()
		}
		if createdOwnCA != "" {
			if err := os.Remove(createdOwnCA); err != nil && !os.IsNotExist(err) {
				logf("cannot remove %s: %v", createdOwnCA, err)
			}
		}
		return firstErr
	}, nil
}
