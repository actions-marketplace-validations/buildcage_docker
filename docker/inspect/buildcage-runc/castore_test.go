package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The rootfs comes from an image the build chose, so a symlink placed at one of
// the CA paths is attacker-controlled input to a process running as root on the
// host.
func TestResolveInRootRefusesToEscape(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "host-secret")
	mustWriteFile(t, outside, "x")
	mustMkdirAll(t, filepath.Join(root, "etc"))

	cases := map[string]string{
		"symlink to an absolute host path": outside,
		"symlink climbing out with ..":     "../../../../../../etc/passwd",
	}
	for name, target := range cases {
		t.Run(name, func(t *testing.T) {
			link := filepath.Join(root, "etc", "ca.pem")
			mustSymlink(t, target, link)
			// The property that matters is that nothing outside the rootfs is
			// ever returned. Refusing outright and failing to find a path that
			// only exists on the host are both acceptable.
			resolved, err := resolveInRoot(root, "/etc/ca.pem")
			if err == nil && !strings.HasPrefix(resolved, root+string(os.PathSeparator)) {
				t.Fatalf("resolved outside the rootfs: %s", resolved)
			}
			if resolved == outside {
				t.Fatal("resolved to the host file")
			}
		})
	}
}

// An absolute symlink inside a container points at the container's own root,
// not the host's, and must keep working.
func TestResolveInRootFollowsAbsoluteLinksInsideTheRootfs(t *testing.T) {
	root := t.TempDir()
	mustMkdirAll(t, filepath.Join(root, "etc", "ssl", "certs"))
	real := filepath.Join(root, "etc", "ssl", "certs", "ca-certificates.crt")
	mustWriteFile(t, real, "real")
	mustSymlink(t, "/etc/ssl/certs/ca-certificates.crt", filepath.Join(root, "etc", "ssl", "cert.pem"))
	resolved, err := resolveInRoot(root, "/etc/ssl/cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	if resolved != real {
		t.Fatalf("got %s, want %s", resolved, real)
	}
}

func TestResolveInRootAllowsAMissingFinalComponent(t *testing.T) {
	root := t.TempDir()
	mustMkdirAll(t, filepath.Join(root, "etc"))
	resolved, err := resolveInRoot(root, "/etc/not-there.pem")
	if err != nil {
		t.Fatal(err)
	}
	if resolved != filepath.Join(root, "etc", "not-there.pem") {
		t.Fatalf("unexpected path %s", resolved)
	}
}

// Removal has to be exact rather than length-based: a step may append its own
// certificates, and cutting back to a remembered size would take them with it.
func TestRemoveCALeavesLaterAdditionsIntact(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.pem")
	original := "ORIGINAL\n"
	mustWriteFile(t, path, original)
	if err := appendCA(path, []byte("BUILDCAGE-CA")); err != nil {
		t.Fatal(err)
	}
	mustAppendFile(t, path, "USER-ADDED\n")

	if err := removeCA(path); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != original+"USER-ADDED\n" {
		t.Fatalf("got %q", got)
	}
	if strings.Contains(string(got), "BUILDCAGE-CA") {
		t.Fatal("the CA is still present")
	}
}

func TestRemoveCARestoresTheFileExactly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.pem")
	original := "ORIGINAL CONTENT\nSECOND LINE\n"
	mustWriteFile(t, path, original)
	if err := appendCA(path, []byte("CA")); err != nil {
		t.Fatal(err)
	}
	if err := removeCA(path); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != original {
		t.Fatalf("got %q, want %q", got, original)
	}
}

// A step that rewrote the file entirely leaves no block to find.
func TestRemoveCAIsANoOpWhenTheBlockIsGone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.pem")
	mustWriteFile(t, path, "REWRITTEN\n")
	if err := removeCA(path); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "REWRITTEN\n" {
		t.Fatalf("got %q", got)
	}
}

// filler is content removeCA has to leave alone, sized to the byte so a
// marker lands at an exact offset.
func filler(n int) string {
	const line = "FILLER-LINE\n"
	return strings.Repeat(line, n/len(line)+1)[:n]
}

// A step can leave the bundle far larger than one window, so the block has to
// come out exactly wherever it falls relative to a boundary.
func TestRemoveCAStripsABlockAcrossWindowBoundaries(t *testing.T) {
	cases := map[string]struct{ beginAt, caSize, after int }{
		"well inside one window":            {17, 32, 0},
		"begin marker ending a window":      {scanChunk - len(beginMarker), 32, scanChunk},
		"begin marker opening a window":     {scanChunk, 32, scanChunk},
		"begin marker over a read boundary": {scanChunk + len(beginMarker)/2, 32, 2 * scanChunk},
		"a block wider than a window":       {64, 2 * scanChunk, scanChunk},
		"spanning several windows":          {3 * scanChunk, 32, 3 * scanChunk},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "bundle.pem")
			// appendCA opens the block with a newline, so the marker lands
			// one byte past what is already there.
			before, after := filler(c.beginAt-1), filler(c.after)
			mustWriteFile(t, path, before)
			if err := appendCA(path, []byte(strings.Repeat("C", c.caSize))); err != nil {
				t.Fatal(err)
			}
			mustAppendFile(t, path, after)

			if err := removeCA(path); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != before+after {
				t.Fatalf("got %d bytes, want %d", len(got), len(before)+len(after))
			}
		})
	}
}

// A step that rewrites the bundle can leave the block without the newlines
// appendCA wrote around it, or as the whole file.
func TestRemoveCAStripsABlockWithoutSurroundingNewlines(t *testing.T) {
	block := beginMarker + "\nCA\n" + endMarker
	cases := map[string]struct{ content, want string }{
		"no newline on either side": {"HEAD" + block + "TAIL\n", "HEADTAIL\n"},
		"the whole file":            {block, ""},
		"at the end of the file":    {"HEAD\n" + block, "HEAD"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "bundle.pem")
			mustWriteFile(t, path, c.content)
			if err := removeCA(path); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestRemoveCARefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "host-secret")
	mustWriteFile(t, outside, "SECRET")
	path := filepath.Join(dir, "bundle.pem")
	mustSymlink(t, outside, path)

	if err := removeCA(path); !errors.Is(err, errNotRegular) {
		t.Fatalf("got %v, want errNotRegular", err)
	}
	got, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "SECRET" {
		t.Fatalf("the symlink target was modified: %q", got)
	}
}

func TestAppendCARefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "host-secret")
	mustWriteFile(t, outside, "SECRET")
	path := filepath.Join(dir, "bundle.pem")
	mustSymlink(t, outside, path)

	if err := appendCA(path, []byte("CA")); !errors.Is(err, errNotRegular) {
		t.Fatalf("got %v, want errNotRegular", err)
	}
	got, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "SECRET" {
		t.Fatalf("the symlink target was modified: %q", got)
	}
}

func TestRemoveCARefusesAFIFOWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.pem")
	if err := syscall.Mkfifo(path, 0o644); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- removeCA(path) }()

	select {
	case err := <-done:
		if !errors.Is(err, errNotRegular) {
			t.Fatalf("got %v, want errNotRegular", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("removeCA blocked opening a FIFO")
	}
}

func TestAppendCARefusesAFIFOWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.pem")
	if err := syscall.Mkfifo(path, 0o644); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- appendCA(path, []byte("CA")) }()

	select {
	case err := <-done:
		if !errors.Is(err, errNotRegular) {
			t.Fatalf("got %v, want errNotRegular", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("appendCA blocked opening a FIFO")
	}
}

func TestRemoveCARefusesADirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.pem")
	mustMkdirAll(t, path)
	if err := removeCA(path); err == nil {
		t.Fatal("removeCA succeeded on a directory")
	}
}

// "/" survives filepath.Clean as a path with nothing in it. A variable set to
// it resolves to the rootfs itself, which containerPathOf then refuses to bind
// over, rather than to some path made from an empty component.
func TestResolveInRootResolvesTheRootItself(t *testing.T) {
	root := t.TempDir()

	resolved, err := resolveInRoot(root, "/")
	if err != nil {
		t.Fatal(err)
	}
	if resolved != root {
		t.Errorf("resolveInRoot(%q, \"/\") = %q, want the rootfs itself", root, resolved)
	}
}

// A chain long enough to be a loop is refused rather than followed: the rootfs
// comes from an image the build chose, and following it is work done as root on
// the host.
func TestResolveInRootRefusesALongSymlinkChain(t *testing.T) {
	root := t.TempDir()
	mustMkdirAll(t, filepath.Join(root, "etc"))
	// hops is allowed up to 32, so 33 links is one past the limit. The last
	// one points at a real file, so only the length can be what refuses it.
	const links = 33
	for i := range links {
		mustSymlink(t,
			fmt.Sprintf("/etc/link%d", i+1),
			filepath.Join(root, "etc", fmt.Sprintf("link%d", i)))
	}
	mustWriteFile(t, filepath.Join(root, "etc", fmt.Sprintf("link%d", links)), "ROOTS")

	if _, err := resolveInRoot(root, "/etc/link0"); !errors.Is(err, errTooManySymlinks) {
		t.Fatalf("got %v, want errTooManySymlinks", err)
	}

	// One shorter, and the same chain resolves, so it is the count that decides.
	if _, err := resolveInRoot(root, "/etc/link1"); err != nil {
		t.Fatalf("a chain of %d should still resolve: %v", links-1, err)
	}
}

// The CA path can name a directory the image does not have. Creating it is
// fine; being unable to is not something to write through.
func TestAppendCARefusesAPathItCannotCreateADirectoryFor(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "blocked"), "")
	// A regular file stands where the directory would have to go.
	if err := appendCA(filepath.Join(dir, "blocked", "bundle.pem"), []byte("CA")); err == nil {
		t.Fatal("expected appendCA to refuse the path")
	}
}

// A step is free to delete the bundle outright. There is then no block to
// strip, and no reason to fail the build over it.
func TestRemoveCAIsANoOpWhenTheFileIsGone(t *testing.T) {
	if err := removeCA(filepath.Join(t.TempDir(), "gone.pem")); err != nil {
		t.Fatalf("got %v, want nil", err)
	}
}

// An empty bundle has no bytes to scan. The scan has to end on its own rather
// than read past the end of the file.
func TestRemoveCAIsANoOpOnAnEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.pem")
	mustWriteFile(t, path, "")

	if err := removeCA(path); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("got %q, want it left empty", got)
	}
}

// A step that truncated the bundle mid-block leaves a begin marker with no end.
// Cutting from there to the end of the file would take whatever the step wrote
// with it, so nothing is removed.
func TestRemoveCALeavesAnUnterminatedBlockAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.pem")
	content := "ORIGINAL\n" + beginMarker + "\nCA-WITH-NO-END-MARKER\n"
	mustWriteFile(t, path, content)

	if err := removeCA(path); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != content {
		t.Fatalf("got %q, want it unchanged", got)
	}
}
