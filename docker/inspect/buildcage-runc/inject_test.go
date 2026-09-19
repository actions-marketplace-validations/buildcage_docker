package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newBundleNoStore lays out a bundle with no CA store at all under
// rootfs/etc/ssl/certs — the node:*-slim shape: no OS trust store, only
// Node's own bundled roots, which findSystemStore cannot find.
func newBundleNoStore(t *testing.T, env []string) (bundle, rootfs string) {
	t.Helper()
	bundle = t.TempDir()
	rootfs = filepath.Join(bundle, "rootfs")
	// /etc exists, as it does in any real base image (passwd, hostname, ...);
	// only etc/ssl/certs and its siblings are absent, which is what actually
	// makes findSystemStore fail.
	mustMkdirAll(t, filepath.Join(rootfs, "etc"))

	config := map[string]any{
		"root":    map[string]any{"path": "rootfs"},
		"process": map[string]any{"env": toAny(env)},
	}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, filepath.Join(bundle, "config.json"), string(raw))
	return bundle, rootfs
}

// newBundle is the same bundle with one system CA candidate in the rootfs,
// which is what the store-present half of the decision table needs.
func newBundle(t *testing.T, env []string) (bundle, rootfs string) {
	t.Helper()
	bundle, rootfs = newBundleNoStore(t, env)
	mustMkdirAll(t, filepath.Join(rootfs, "etc", "ssl", "certs"))
	mustWriteFile(t, filepath.Join(rootfs, "etc", "ssl", "certs", "ca-certificates.crt"), "ORIGINAL-ROOTS\n")
	return bundle, rootfs
}

func toAny(env []string) []any {
	out := make([]any, len(env))
	for i, e := range env {
		out[i] = e
	}
	return out
}

func loadEnv(t *testing.T, bundle string) map[string]string {
	t.Helper()
	s, err := loadSpec(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return s.env
}

func loadMounts(t *testing.T, bundle string) []map[string]any {
	t.Helper()
	s, err := loadSpec(bundle)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := s.raw["mounts"].([]any)
	mounts := make([]map[string]any, 0, len(raw))
	for _, m := range raw {
		if entry, ok := m.(map[string]any); ok {
			mounts = append(mounts, entry)
		}
	}
	return mounts
}

func findMount(t *testing.T, mounts []map[string]any, dest string) map[string]any {
	t.Helper()
	for _, m := range mounts {
		if m["destination"] == dest {
			return m
		}
	}
	t.Fatalf("no mount for %s", dest)
	return nil
}

// Additive variables (NODE_EXTRA_CA_CERTS, DENO_CERT) get their own file
// holding only the proxy's CA, so a tool's built-in bundle stays intact.
// Replacing variables (REQUESTS_CA_BUNDLE, PIP_CERT, SSL_CERT_FILE) get
// pointed at the system store instead, which already carries both.
func TestInjectSetsEachUnsetVariableAccordingToItsKind(t *testing.T) {
	useFakeRsync(t)
	bundle, rootfs := newBundle(t, []string{"PATH=/usr/bin"})

	restore, err := inject(bundle, []byte("BUILDCAGE-CA"))
	if err != nil {
		t.Fatal(err)
	}
	defer restore.finish()

	env := loadEnv(t, bundle)

	for _, additive := range []string{"NODE_EXTRA_CA_CERTS", "DENO_CERT"} {
		if env[additive] != ownCAPath {
			t.Errorf("%s = %q, want %q", additive, env[additive], ownCAPath)
		}
	}
	own, err := os.ReadFile(filepath.Join(rootfs, strings.TrimPrefix(ownCAPath, "/")))
	if err != nil {
		t.Fatal(err)
	}
	if string(own) != "BUILDCAGE-CA" {
		t.Fatalf("own CA file = %q", own)
	}

	systemStorePath := "/etc/ssl/certs/ca-certificates.crt"
	for _, replacing := range []string{"REQUESTS_CA_BUNDLE", "PIP_CERT", "SSL_CERT_FILE"} {
		if env[replacing] != systemStorePath {
			t.Errorf("%s = %q, want %q", replacing, env[replacing], systemStorePath)
		}
	}

	if _, set := env["CURL_CA_BUNDLE"]; set {
		t.Error("CURL_CA_BUNDLE should be left unset; curl already reads the system store")
	}

	// The CA goes into the scratch mirror bind-mounted over the store's
	// directory, never into the real rootfs directly.
	mount := findMount(t, loadMounts(t, bundle), "/etc/ssl/certs")
	scratchDir, _ := mount["source"].(string)
	mirrored, err := os.ReadFile(filepath.Join(scratchDir, "ca-certificates.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mirrored), "BUILDCAGE-CA") || !strings.HasPrefix(string(mirrored), "ORIGINAL-ROOTS") {
		t.Fatalf("scratch mirror not patched correctly: %q", mirrored)
	}

	store, err := os.ReadFile(filepath.Join(rootfs, "etc", "ssl", "certs", "ca-certificates.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(store) != "ORIGINAL-ROOTS\n" {
		t.Fatalf("the real store must stay untouched until the step changes it: %q", store)
	}
}

// A step that already points a variable somewhere of its own keeps that
// choice; the CA is appended to that file instead of the variable being
// redirected, so whatever the author put there is not discarded.
func TestInjectAppendsToAnAlreadySetVariableInstead(t *testing.T) {
	useFakeRsync(t)
	bundle, rootfs := newBundle(t, []string{"DENO_CERT=/custom/roots.pem"})
	mustMkdirAll(t, filepath.Join(rootfs, "custom"))
	mustWriteFile(t, filepath.Join(rootfs, "custom", "roots.pem"), "CUSTOM\n")

	restore, err := inject(bundle, []byte("BUILDCAGE-CA"))
	if err != nil {
		t.Fatal(err)
	}
	defer restore.finish()

	env := loadEnv(t, bundle)
	if env["DENO_CERT"] != "/custom/roots.pem" {
		t.Fatalf("DENO_CERT was redirected to %q", env["DENO_CERT"])
	}

	mount := findMount(t, loadMounts(t, bundle), "/custom")
	scratchDir, _ := mount["source"].(string)
	custom, err := os.ReadFile(filepath.Join(scratchDir, "roots.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(custom), "BUILDCAGE-CA") {
		t.Fatal("the CA was not appended to the custom file")
	}

	real, err := os.ReadFile(filepath.Join(rootfs, "custom", "roots.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if string(real) != "CUSTOM\n" {
		t.Fatalf("the real file must stay untouched until the step changes it: %q", real)
	}
}

// A step that never touches the store leaves the real rootfs file alone:
// finish() finds the scratch mirror unchanged from its post-injection
// baseline and never writes back.
func TestInjectFinishLeavesAnUntouchedStoreAlone(t *testing.T) {
	useFakeRsync(t)
	bundle, rootfs := newBundle(t, []string{"PATH=/usr/bin"})

	restore, err := inject(bundle, []byte("BUILDCAGE-CA"))
	if err != nil {
		t.Fatal(err)
	}
	if err := restore.finish(); err != nil {
		t.Fatal(err)
	}

	store, err := os.ReadFile(filepath.Join(rootfs, "etc", "ssl", "certs", "ca-certificates.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(store) != "ORIGINAL-ROOTS\n" {
		t.Fatalf("the real store was written to even though nothing changed: %q", store)
	}
	if _, err := os.Stat(filepath.Join(rootfs, strings.TrimPrefix(ownCAPath, "/"))); !os.IsNotExist(err) {
		t.Fatalf("own CA file still present: %v", err)
	}
}

// A step that regenerates the store (e.g. apt-get install --reinstall
// ca-certificates) gets its change mirrored back onto the real rootfs.
func TestInjectWritesBackWhenTheStepChangesTheStore(t *testing.T) {
	useFakeRsync(t)
	bundle, rootfs := newBundle(t, []string{"PATH=/usr/bin"})

	restore, err := inject(bundle, []byte("BUILDCAGE-CA"))
	if err != nil {
		t.Fatal(err)
	}

	mount := findMount(t, loadMounts(t, bundle), "/etc/ssl/certs")
	scratchDir, _ := mount["source"].(string)
	mustWriteFile(t, filepath.Join(scratchDir, "ca-certificates.crt"), "REGENERATED\n")

	calls := countRsync(t)

	if err := restore.finish(); err != nil {
		t.Fatal(err)
	}
	if *calls != 2 {
		t.Fatalf("got %d rsync invocations for the write-back, want 2 (dry run, then apply)", *calls)
	}

	got, err := os.ReadFile(filepath.Join(rootfs, "etc", "ssl", "certs", "ca-certificates.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "REGENERATED\n" {
		t.Fatalf("write-back did not reach the real store: %q", got)
	}
}

// A failure applying the write-back must fail the build rather than ship a
// half-written layer.
func TestInjectWriteBackFailurePropagates(t *testing.T) {
	useFakeRsync(t)
	bundle, _ := newBundle(t, []string{"PATH=/usr/bin"})

	restore, err := inject(bundle, []byte("BUILDCAGE-CA"))
	if err != nil {
		t.Fatal(err)
	}

	mount := findMount(t, loadMounts(t, bundle), "/etc/ssl/certs")
	scratchDir, _ := mount["source"].(string)
	mustWriteFile(t, filepath.Join(scratchDir, "ca-certificates.crt"), "REGENERATED\n")

	failRsyncOn(t, 2) // the apply, right after a successful dry run

	if err := restore.finish(); err == nil {
		t.Fatal("expected the write-back failure to propagate")
	}
}

func TestInjectSkipsRestoreWhenStepSwapsBundleForASymlink(t *testing.T) {
	useFakeRsync(t)
	bundle, rootfs := newBundle(t, []string{"PATH=/usr/bin"})
	outside := filepath.Join(t.TempDir(), "host-secret")
	mustWriteFile(t, outside, "SECRET")

	restore, err := inject(bundle, []byte("BUILDCAGE-CA"))
	if err != nil {
		t.Fatal(err)
	}

	mount := findMount(t, loadMounts(t, bundle), "/etc/ssl/certs")
	scratchDir, _ := mount["source"].(string)
	target := filepath.Join(scratchDir, "ca-certificates.crt")
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, outside, target)

	if err := restore.finish(); err != nil {
		t.Fatalf("restore should skip the unrestorable file, not fail the build: %v", err)
	}

	secret, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(secret) != "SECRET" {
		t.Fatalf("the symlink target was modified: %q", secret)
	}

	got := filepath.Join(rootfs, "etc", "ssl", "certs", "ca-certificates.crt")
	link, err := os.Readlink(got)
	if err != nil {
		t.Fatalf("write-back did not mirror the step's own symlink: %v", err)
	}
	if link != outside {
		t.Fatalf("got link %q, want %q", link, outside)
	}
}

// A base image with no CA store of its own (node:*-slim before
// ca-certificates is installed, or a scratch/distroless image) must not lose
// every variable just because the system store is missing: all six fall back
// to the same proxy-CA-only file. This is the corepack/node:22-slim and
// apt-install-then-curl/debian:bookworm-slim failure modes under the inspect
// engine — see docs/inspect-engine.md's "No system CA store" for what this
// fallback does and does not cover (ordinary MITM'd traffic works; a
// passthrough connection's real certificate still does not verify).
func TestInjectWithoutSystemStoreFallsBackToOwnCAForEveryVariable(t *testing.T) {
	bundle, rootfs := newBundleNoStore(t, []string{"PATH=/usr/bin"})

	restore, err := inject(bundle, []byte("BUILDCAGE-CA"))
	if err != nil {
		t.Fatal(err)
	}

	env := loadEnv(t, bundle)

	for _, variable := range []string{
		"NODE_EXTRA_CA_CERTS", "DENO_CERT",
		"CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "PIP_CERT", "SSL_CERT_FILE",
	} {
		if env[variable] != ownCAPath {
			t.Errorf("%s = %q, want %q", variable, env[variable], ownCAPath)
		}
	}
	own, err := os.ReadFile(filepath.Join(rootfs, strings.TrimPrefix(ownCAPath, "/")))
	if err != nil {
		t.Fatal(err)
	}
	if string(own) != "BUILDCAGE-CA" {
		t.Fatalf("own CA file = %q", own)
	}

	restore.finish()
	if _, err := os.Stat(filepath.Join(rootfs, strings.TrimPrefix(ownCAPath, "/"))); !os.IsNotExist(err) {
		t.Fatalf("own CA file still present after restore: %v", err)
	}
}

// newBundleWithMounts is newBundle with mounts already in the process spec,
// the way BuildKit hands them over for a cache mount or a bind.
func newBundleWithMounts(t *testing.T, env []string, destinations ...string) (bundle, rootfs string) {
	t.Helper()
	bundle, rootfs = newBundle(t, env)
	s, err := loadSpec(bundle)
	if err != nil {
		t.Fatal(err)
	}
	for _, dest := range destinations {
		s.addBindMount(dest, t.TempDir())
	}
	if err := s.save(); err != nil {
		t.Fatal(err)
	}
	return bundle, rootfs
}

// Mounting over a directory something else already covers would shadow it, so
// the store keeps whatever the build put there and injection is skipped.
func TestInjectSkipsADirectoryAMountAlreadyCovers(t *testing.T) {
	useFakeRsync(t)
	bundle, rootfs := newBundleWithMounts(t, []string{"PATH=/usr/bin"}, "/etc/ssl")

	restore, err := inject(bundle, []byte("BUILDCAGE-CA"))
	if err != nil {
		t.Fatal(err)
	}
	defer restore.finish()

	for _, m := range loadMounts(t, bundle) {
		if m["destination"] == "/etc/ssl/certs" {
			t.Fatalf("injection mounted over a covered directory: %v", m)
		}
	}
	store, err := os.ReadFile(filepath.Join(rootfs, "etc/ssl/certs/ca-certificates.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(store) != "ORIGINAL-ROOTS\n" {
		t.Fatalf("the store was written to: %q", store)
	}
}

// A variable naming a file directly under / would make the mount destination
// the container root. Binding there would shadow the whole filesystem, so the
// CA does not go in at all.
func TestInjectRefusesToBindTheContainerRoot(t *testing.T) {
	useFakeRsync(t)
	bundle, _ := newBundleNoStore(t, []string{"CURL_CA_BUNDLE=/roots.pem"})

	restore, err := inject(bundle, []byte("BUILDCAGE-CA"))
	if err != nil {
		t.Fatal(err)
	}
	defer restore.finish()

	if mounts := loadMounts(t, bundle); len(mounts) != 0 {
		t.Fatalf("expected no mounts, got %v", mounts)
	}
}

// A directory prepare refuses is skipped rather than failing the build: the
// step runs without the CA there, and its TLS failures say so.
func TestInjectSkipsADirectoryPrepareRefuses(t *testing.T) {
	useFakeRsync(t)
	bundle, rootfs := newBundle(t, []string{"DENO_CERT=/big/roots.pem"})
	big := filepath.Join(rootfs, "big")
	mustMkdirAll(t, big)
	mustSparseFile(t, filepath.Join(big, "roots.pem"), maxCustomDirBytes+1)

	restore, err := inject(bundle, []byte("BUILDCAGE-CA"))
	if err != nil {
		t.Fatal(err)
	}
	defer restore.finish()

	for _, m := range loadMounts(t, bundle) {
		if m["destination"] == "/big" {
			t.Fatalf("injection mounted a directory prepare refused: %v", m)
		}
	}
	// The store the same build does have is still injected.
	findMount(t, loadMounts(t, bundle), "/etc/ssl/certs")
}

// A file already at the wrapper's own path belongs to the image, not to this
// run: it is neither overwritten nor removed, and the variables that would
// have pointed at it stay unset.
func TestInjectLeavesAnExistingOwnCAPathAlone(t *testing.T) {
	useFakeRsync(t)
	bundle, rootfs := newBundle(t, []string{"PATH=/usr/bin"})
	existing := filepath.Join(rootfs, strings.TrimPrefix(ownCAPath, "/"))
	mustWriteFile(t, existing, "THE IMAGE PUT THIS HERE")

	restore, err := inject(bundle, []byte("BUILDCAGE-CA"))
	if err != nil {
		t.Fatal(err)
	}

	env := loadEnv(t, bundle)
	for _, additive := range []string{"NODE_EXTRA_CA_CERTS", "DENO_CERT"} {
		if _, set := env[additive]; set {
			t.Errorf("%s was pointed at a file this run did not write", additive)
		}
	}

	if err := restore.finish(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(existing)
	if err != nil {
		t.Fatalf("the image's own file was removed: %v", err)
	}
	if string(got) != "THE IMAGE PUT THIS HERE" {
		t.Fatalf("the image's own file was overwritten: %q", got)
	}
}

// A variable pointing outside the rootfs is left as the author wrote it: the
// wrapper runs as root on the host, so following it is what resolveInRoot
// exists to refuse.
func TestInjectLeavesAnUnresolvableVariableAlone(t *testing.T) {
	useFakeRsync(t)
	bundle, _ := newBundle(t, []string{"DENO_CERT=../../../../etc/passwd"})

	restore, err := inject(bundle, []byte("BUILDCAGE-CA"))
	if err != nil {
		t.Fatal(err)
	}
	defer restore.finish()

	if got := loadEnv(t, bundle)["DENO_CERT"]; got != "../../../../etc/passwd" {
		t.Errorf("DENO_CERT = %q, want it left alone", got)
	}
	if mounts := loadMounts(t, bundle); len(mounts) != 1 {
		t.Fatalf("expected only the store's own mount, got %v", mounts)
	}
}
