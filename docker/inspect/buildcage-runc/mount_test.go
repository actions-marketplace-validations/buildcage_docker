package main

import (
	"fmt"
	"os"
	"path/filepath"
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
