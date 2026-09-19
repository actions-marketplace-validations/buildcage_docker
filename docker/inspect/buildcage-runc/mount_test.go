package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGroupTargetsByDir(t *testing.T) {
	targets := map[string]bool{
		"/rootfs/etc/ssl/certs/ca-certificates.crt": true,
		"/rootfs/etc/ssl/certs/extra.pem":           true,
		"/rootfs/custom/roots.pem":                  true,
	}
	groups := groupTargetsByDir(targets)
	if len(groups["/rootfs/etc/ssl/certs"]) != 2 {
		t.Errorf("expected 2 files grouped under /rootfs/etc/ssl/certs, got %v", groups["/rootfs/etc/ssl/certs"])
	}
	if len(groups["/rootfs/custom"]) != 1 {
		t.Errorf("expected 1 file grouped under /rootfs/custom, got %v", groups["/rootfs/custom"])
	}
}

func TestContainerPathOfResolvesThroughSymlinks(t *testing.T) {
	// RHEL: the candidate file is a symlink into extracted/pem, sitting in a
	// different directory than the real store.
	t.Run("RHEL", func(t *testing.T) {
		root := t.TempDir()
		mustMkdirAll(t, filepath.Join(root, "etc/pki/ca-trust/extracted/pem"))
		mustMkdirAll(t, filepath.Join(root, "etc/pki/tls/certs"))
		mustWriteFile(t, filepath.Join(root, "etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"), "ROOTS")
		mustSymlink(t, "../../ca-trust/extracted/pem/tls-ca-bundle.pem", filepath.Join(root, "etc/pki/tls/certs/ca-bundle.crt"))

		store, err := findSystemStore(root)
		if err != nil {
			t.Fatal(err)
		}
		got := containerPathOf(root, store.dir())
		if want := "/etc/pki/ca-trust/extracted/pem"; got != want {
			t.Errorf("containerPathOf = %q, want %q", got, want)
		}
	})

	// openSUSE: the candidate is a symlink to a different top-level tree
	// entirely (/var/lib/ca-certificates), not a sibling directory.
	t.Run("openSUSE", func(t *testing.T) {
		root := t.TempDir()
		mustMkdirAll(t, filepath.Join(root, "var/lib/ca-certificates"))
		mustMkdirAll(t, filepath.Join(root, "etc/ssl"))
		mustWriteFile(t, filepath.Join(root, "var/lib/ca-certificates/ca-bundle.pem"), "ROOTS")
		mustSymlink(t, "../../var/lib/ca-certificates/ca-bundle.pem", filepath.Join(root, "etc/ssl/ca-bundle.pem"))

		store, err := findSystemStore(root)
		if err != nil {
			t.Fatal(err)
		}
		got := containerPathOf(root, store.dir())
		if want := "/var/lib/ca-certificates"; got != want {
			t.Errorf("containerPathOf = %q, want %q", got, want)
		}
	})
}

func TestContainerPathOfRefusesAnythingButAPathInsideTheRootfs(t *testing.T) {
	const rootfs = "/run/bundle/rootfs"
	cases := map[string]string{
		"the rootfs itself":       rootfs,
		"somewhere else entirely": "/somewhere/else",
		// Sharing a prefix with the rootfs is not being inside it; a bare
		// HasPrefix would hand back "-old/etc/ssl/certs" as a container path.
		"a sibling the rootfs name is a prefix of": rootfs + "-old/etc/ssl/certs",
	}
	for name, resolved := range cases {
		t.Run(name, func(t *testing.T) {
			if got := containerPathOf(rootfs, resolved); got != "/" {
				t.Errorf("containerPathOf(%q, %q) = %q, want %q", rootfs, resolved, got, "/")
			}
		})
	}
}

func TestManifestsEqualIgnoresMtimeButNotContent(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "a"), "same")
	a, err := captureManifest(dir)
	if err != nil {
		t.Fatal(err)
	}

	// A later write with identical content still bumps mtime; that alone
	// must not register as a change.
	mustWriteFile(t, filepath.Join(dir, "a"), "same")
	b, err := captureManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !manifestsEqual(a, b) {
		t.Error("identical content with a different mtime should compare equal")
	}

	mustWriteFile(t, filepath.Join(dir, "a"), "different")
	c, err := captureManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	if manifestsEqual(a, c) {
		t.Error("different content should not compare equal")
	}
}

func TestSizeAndCount(t *testing.T) {
	dir := t.TempDir()
	mustMkdirAll(t, filepath.Join(dir, "sub"))
	mustWriteFile(t, filepath.Join(dir, "a"), "1234567890")
	mustWriteFile(t, filepath.Join(dir, "sub", "b"), "12345")

	bytes, files, err := sizeAndCount(dir)
	if err != nil {
		t.Fatal(err)
	}
	if bytes != 15 || files != 2 {
		t.Errorf("got bytes=%d files=%d, want bytes=15 files=2", bytes, files)
	}
}

func TestRestoreUnchangedMtimesLeavesChangedFilesAlone(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "untouched"), "same")
	mustWriteFile(t, filepath.Join(dir, "changed"), "before")

	// Chtimes to a fixed past time instead of relying on real write timing,
	// since two writes in quick succession can land in the same mtime tick.
	past := time.Now().Add(-time.Hour).Truncate(time.Second)
	for _, name := range []string{"untouched", "changed"} {
		if err := os.Chtimes(filepath.Join(dir, name), past, past); err != nil {
			t.Fatal(err)
		}
	}
	original, err := captureManifest(dir)
	if err != nil {
		t.Fatal(err)
	}

	// A fresh mirror gives every file a new mtime regardless of whether the
	// step actually changed its content.
	mustWriteFile(t, filepath.Join(dir, "untouched"), "same")
	mustWriteFile(t, filepath.Join(dir, "changed"), "after")
	current, err := captureManifest(dir)
	if err != nil {
		t.Fatal(err)
	}

	if err := restoreUnchangedMtimes(original, current, dir); err != nil {
		t.Fatal(err)
	}

	if got := mustStatMtime(t, filepath.Join(dir, "untouched")); !got.Equal(past) {
		t.Errorf("untouched file's mtime = %v, want restored to %v", got, past)
	}
	if got := mustStatMtime(t, filepath.Join(dir, "changed")); got.Equal(past) {
		t.Error("changed file's mtime should not have been reset")
	}
}

// newCAStoreBind lays out a rootfs holding one CA bundle and prepares a
// dirBind over its directory, the way inject does.
func newCAStoreBind(t *testing.T) (*dirBind, string) {
	t.Helper()
	rootfs := t.TempDir()
	mustMkdirAll(t, filepath.Join(rootfs, "etc/ssl/certs"))
	mustWriteFile(t, filepath.Join(rootfs, "etc/ssl/certs/ca-certificates.crt"), "ORIGINAL-ROOTS\n")

	store, err := findSystemStore(rootfs)
	if err != nil {
		t.Fatal(err)
	}
	hostDir := store.dir()
	scratch, err := newScratchDir("bundle")
	if err != nil {
		t.Fatal(err)
	}
	b := &dirBind{
		rootfs:       rootfs,
		hostDir:      hostDir,
		containerDir: containerPathOf(rootfs, hostDir),
		scratchDir:   scratch,
		bundleFiles:  []string{filepath.Base(store.hostPath)},
	}
	if err := b.prepare([]byte("BUILDCAGE-CA")); err != nil {
		t.Fatal(err)
	}
	return b, rootfs
}

// redirectStoreDir repoints /etc/ssl, so containerDir no longer resolves to
// where injection left it.
func redirectStoreDir(t *testing.T, rootfs string) {
	t.Helper()
	elsewhere := filepath.Join(rootfs, "elsewhere")
	mustMkdirAll(t, filepath.Join(elsewhere, "certs"))
	if err := os.RemoveAll(filepath.Join(rootfs, "etc/ssl")); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, "/elsewhere", filepath.Join(rootfs, "etc/ssl"))
}

// A destination that no longer resolves where injection left it fails the
// step rather than being written to.
func TestFinishRefusesARedirectedWriteBackTarget(t *testing.T) {
	useFakeRsync(t)
	b, rootfs := newCAStoreBind(t)
	mustWriteFile(t, filepath.Join(b.scratchDir, "ca-certificates.crt"), "REGENERATED\n")
	redirectStoreDir(t, rootfs)

	calls := countRsync(t)
	if err := b.finish(); err == nil {
		t.Fatal("expected finish to refuse the redirected target")
	}
	if *calls != 0 {
		t.Errorf("got %d rsync invocations, want none before the target is verified", *calls)
	}
}

func TestFinishWritesBackWhenTheTargetStillResolves(t *testing.T) {
	useFakeRsync(t)
	b, rootfs := newCAStoreBind(t)
	mustWriteFile(t, filepath.Join(b.scratchDir, "ca-certificates.crt"), "REGENERATED\n")

	calls := countRsync(t)
	if err := b.finish(); err != nil {
		t.Fatal(err)
	}
	if *calls != 2 {
		t.Errorf("got %d rsync invocations, want 2 (dry run, then apply)", *calls)
	}
	got, err := os.ReadFile(filepath.Join(rootfs, "etc/ssl/certs/ca-certificates.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "REGENERATED\n" {
		t.Errorf("write-back did not reach the real store: %q", got)
	}
}

// An untouched store returns before the check, so a build that never writes
// to the store cannot start failing on it.
func TestFinishSkipsTheCheckWhenTheStoreIsUnchanged(t *testing.T) {
	useFakeRsync(t)
	b, rootfs := newCAStoreBind(t)
	redirectStoreDir(t, rootfs)

	calls := countRsync(t)
	if err := b.finish(); err != nil {
		t.Fatalf("an unchanged store must not fail: %v", err)
	}
	if *calls != 0 {
		t.Errorf("got %d rsync invocations, want none for an unchanged store", *calls)
	}
}

// A custom path comes from the Dockerfile, so it can name anything; mirroring
// it wholesale is bounded rather than trusted. Over either limit, injection is
// refused for that directory instead.
func TestPrepareRefusesACustomDirOverTheLimits(t *testing.T) {
	cases := map[string]func(t *testing.T, dir string){
		"too many files": func(t *testing.T, dir string) {
			for i := range maxCustomDirFiles + 1 {
				mustWriteFile(t, filepath.Join(dir, fmt.Sprintf("f%d", i)), "x")
			}
		},
		"too many bytes": func(t *testing.T, dir string) {
			mustSparseFile(t, filepath.Join(dir, "huge.pem"), maxCustomDirBytes+1)
		},
	}
	for name, fill := range cases {
		t.Run(name, func(t *testing.T) {
			useFakeRsync(t)
			rootfs := t.TempDir()
			hostDir := filepath.Join(rootfs, "custom")
			mustMkdirAll(t, hostDir)
			fill(t, hostDir)

			scratch, err := newScratchDir("bundle")
			if err != nil {
				t.Fatal(err)
			}
			b := &dirBind{
				rootfs:       rootfs,
				hostDir:      hostDir,
				containerDir: "/custom",
				scratchDir:   scratch,
				bundleFiles:  []string{"roots.pem"},
				custom:       true,
			}
			if err := b.prepare([]byte("BUILDCAGE-CA")); err == nil {
				t.Fatal("expected prepare to refuse the directory")
			}
			if entries, err := os.ReadDir(scratch); err != nil || len(entries) != 0 {
				t.Errorf("nothing should have been mirrored: %v, %v", entries, err)
			}
		})
	}
}

// The store directory is not a custom path, so the limits do not apply to it:
// a distribution that ships a large trust store still gets the CA.
func TestPrepareDoesNotBoundTheSystemStoreDir(t *testing.T) {
	useFakeRsync(t)
	rootfs := t.TempDir()
	hostDir := filepath.Join(rootfs, "etc/ssl/certs")
	mustMkdirAll(t, hostDir)
	mustSparseFile(t, filepath.Join(hostDir, "ca-certificates.crt"), maxCustomDirBytes+1)

	scratch, err := newScratchDir("bundle")
	if err != nil {
		t.Fatal(err)
	}
	b := &dirBind{
		rootfs:       rootfs,
		hostDir:      hostDir,
		containerDir: "/etc/ssl/certs",
		scratchDir:   scratch,
		bundleFiles:  []string{"ca-certificates.crt"},
	}
	if err := b.prepare([]byte("BUILDCAGE-CA")); err != nil {
		t.Fatalf("the store directory must not be bounded: %v", err)
	}
}

// The scratch root is a real host path in production. A wrapper that cannot
// make it has to say so rather than mirror into nowhere.
func TestNewScratchDirReportsARootItCannotMake(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "blocked"), "")
	old := scratchRoot
	scratchRoot = filepath.Join(dir, "blocked", "ca")
	t.Cleanup(func() { scratchRoot = old })

	if _, err := newScratchDir("bundle"); err == nil {
		t.Fatal("expected newScratchDir to fail")
	}
}

func TestMirrorDirReportsADestinationItCannotMake(t *testing.T) {
	useFakeRsync(t)
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "blocked"), "")

	if err := mirrorDir(t.TempDir(), filepath.Join(dir, "blocked", "scratch")); err == nil {
		t.Fatal("expected mirrorDir to fail")
	}
}

// The dry run is what makes a write-back auditable, so a failure in it stops
// the real one rather than going ahead unlogged.
func TestWriteBackReportsAFailedDryRun(t *testing.T) {
	useFakeRsync(t)
	scratch, hostDir := t.TempDir(), t.TempDir()
	mustWriteFile(t, filepath.Join(scratch, "ca-certificates.crt"), "REGENERATED\n")
	// failRsyncOn first, so the counter wraps it and sees every call.
	failRsyncOn(t, 1)
	calls := countRsync(t)

	if err := writeBack(scratch, hostDir); err == nil {
		t.Fatal("expected the dry run's failure to propagate")
	}
	if *calls != 1 {
		t.Errorf("got %d rsync invocations, want 1: the apply must not follow a failed dry run", *calls)
	}
}

// A walk that cannot start at all is the error the callback is handed, and
// both of these return it rather than reporting an empty tree.
func TestWalkingSomethingThatIsNotThere(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "not-there")

	if _, err := captureManifest(missing); err == nil {
		t.Error("captureManifest reported no error for a missing root")
	}
	if _, _, err := sizeAndCount(missing); err == nil {
		t.Error("sizeAndCount reported no error for a missing root")
	}
}

func TestHashFileReportsAFileItCannotOpen(t *testing.T) {
	skipIfRoot(t)
	path := filepath.Join(t.TempDir(), "bundle.pem")
	mustWriteFile(t, path, "ROOTS")
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}

	if _, err := hashFile(path); err == nil {
		t.Fatal("expected hashFile to fail")
	}
}

// The mtime reset walks the manifest, not the directory, so an entry naming
// something no longer there is a real possibility rather than a guard.
func TestRestoreUnchangedMtimesReportsAFileItCannotTouch(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "a"), "same")
	manifest, err := captureManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "a")); err != nil {
		t.Fatal(err)
	}

	if err := restoreUnchangedMtimes(manifest, manifest, dir); err == nil {
		t.Fatal("expected the missing file to be reported")
	}
}

// prepare measures a custom directory before mirroring it. A directory it
// cannot measure is refused, the same as one over the limits.
func TestPrepareReportsADirectoryItCannotMeasure(t *testing.T) {
	useFakeRsync(t)
	rootfs := t.TempDir()
	scratch, err := newScratchDir("bundle")
	if err != nil {
		t.Fatal(err)
	}
	b := &dirBind{
		rootfs:       rootfs,
		hostDir:      filepath.Join(rootfs, "not-there"),
		containerDir: "/not-there",
		scratchDir:   scratch,
		bundleFiles:  []string{"roots.pem"},
		custom:       true,
	}

	if err := b.prepare([]byte("BUILDCAGE-CA")); err == nil {
		t.Fatal("expected prepare to refuse the directory")
	}
}

func TestPrepareReportsAMirrorThatFailed(t *testing.T) {
	useFakeRsync(t)
	b, _ := newCAStoreBind(t)
	// prepare already ran once in the fixture; run it again with rsync failing.
	failRsyncOn(t, 1)

	if err := b.prepare([]byte("BUILDCAGE-CA")); err == nil {
		t.Fatal("expected the mirror's failure to propagate")
	}
}

// A step is free to leave a symlink where the bundle was. The CA is not
// written through it, and the rest of the directory is still mirrored, so
// injection carries on without that one file.
func TestPrepareLeavesABundleFileItCannotOpen(t *testing.T) {
	useFakeRsync(t)
	rootfs := t.TempDir()
	hostDir := filepath.Join(rootfs, "etc/ssl/certs")
	mustMkdirAll(t, hostDir)
	mustSymlink(t, "/somewhere/else", filepath.Join(hostDir, "ca-certificates.crt"))
	mustWriteFile(t, filepath.Join(hostDir, "other.pem"), "OTHER\n")

	scratch, err := newScratchDir("bundle")
	if err != nil {
		t.Fatal(err)
	}
	b := &dirBind{
		rootfs:       rootfs,
		hostDir:      hostDir,
		containerDir: "/etc/ssl/certs",
		scratchDir:   scratch,
		bundleFiles:  []string{"ca-certificates.crt"},
	}

	if err := b.prepare([]byte("BUILDCAGE-CA")); err != nil {
		t.Fatalf("an unwritable bundle file must not fail the step: %v", err)
	}
	if target, err := os.Readlink(filepath.Join(scratch, "ca-certificates.crt")); err != nil || target != "/somewhere/else" {
		t.Errorf("the symlink was not mirrored as one: %q, %v", target, err)
	}
	if got, err := os.ReadFile(filepath.Join(scratch, "other.pem")); err != nil || string(got) != "OTHER\n" {
		t.Errorf("the rest of the directory was not mirrored: %q, %v", got, err)
	}
}

// The write-back target is re-resolved before anything is written. A
// destination that now points outside the rootfs fails the step rather than
// being followed, since the wrapper runs as root on the host.
func TestFinishRefusesATargetThatNowEscapesTheRootfs(t *testing.T) {
	useFakeRsync(t)
	b, rootfs := newCAStoreBind(t)
	mustWriteFile(t, filepath.Join(b.scratchDir, "ca-certificates.crt"), "REGENERATED\n")
	if err := os.RemoveAll(filepath.Join(rootfs, "etc/ssl")); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, "../../../../../../etc", filepath.Join(rootfs, "etc/ssl"))

	calls := countRsync(t)
	err := b.finish()
	if !errors.Is(err, errEscapesRoot) {
		t.Fatalf("got %v, want it to name errEscapesRoot", err)
	}
	if *calls != 0 {
		t.Errorf("got %d rsync invocations, want none before the target is verified", *calls)
	}
}

// Failing to remove the scratch mirror leaves a directory behind on the
// builder, which is worth a log line but not worth failing a step that
// otherwise succeeded.
func TestCleanupReportsAScratchDirItCannotRemove(t *testing.T) {
	skipIfRoot(t)
	useTempLog(t)
	parent := t.TempDir()
	scratch := filepath.Join(parent, "scratch")
	mustMkdirAll(t, scratch)
	mustMakeReadOnly(t, parent)

	b := &dirBind{scratchDir: scratch, containerDir: "/etc/ssl/certs"}
	b.cleanup()

	var out strings.Builder
	dumpOwnLog(&out)
	if !strings.Contains(out.String(), "cannot remove") {
		t.Errorf("the failure is not in the log:\n%s", out.String())
	}
}
