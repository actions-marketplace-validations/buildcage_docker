package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestMain points the package's own log somewhere disposable for the whole
// run. logf writes to logFile and appends to ownLog, both package level, and
// the injection tests reach it without setting out to: six of them log while
// running. Left alone, a run with write access to /var/log appends those lines
// to the real builder log.
//
// Each test that reads the log back still takes a file of its own through
// useTempLog, since it counts the lines in it.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "buildcage-runc-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	logFile = filepath.Join(dir, "runc.log")
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// mustAppendFile stands in for whatever writes to a file the wrapper already
// owns: a step adding its own certificates, or a neighbouring step's line
// landing in the shared log.
func mustAppendFile(t *testing.T, path, content string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
}

// mustSparseFile makes a file that reports size bytes without writing them;
// sizeAndCount reads the reported size, which is what the limits bound.
func mustSparseFile(t *testing.T, path string, size int64) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
}

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	_ = os.Remove(link)
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func mustStatMtime(t *testing.T, path string) time.Time {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.ModTime()
}

// useFakeRsync makes dirBind's filesystem operations hermetic: a fake copy
// instead of a real rsync process, and a scratch root under the test's own
// temp directory instead of the real host path (which a test process
// usually can't create or write to). The one test that needs the real
// rsync binary and the real scratch root lives in mount_rsync_smoke_test.go.
func useFakeRsync(t *testing.T) {
	t.Helper()
	oldRsync, oldScratchRoot := runRsync, scratchRoot
	runRsync = fakeRsyncCopy
	scratchRoot = t.TempDir()
	t.Cleanup(func() {
		runRsync = oldRsync
		scratchRoot = oldScratchRoot
	})
}

// fakeRsyncCopy stands in for `rsync -a[HAX] [--checksum] [--delete] ... src/ dst/`:
// it only looks at the last two arguments and replaces dst wholesale with
// src's tree, which is close enough to mirror/writeBack's actual usage for
// unit tests to observe the resulting on-disk state.
func fakeRsyncCopy(args []string) ([]byte, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("not enough args: %v", args)
	}
	src := strings.TrimSuffix(args[len(args)-2], "/")
	dst := strings.TrimSuffix(args[len(args)-1], "/")
	if err := os.RemoveAll(dst); err != nil {
		return nil, err
	}
	return nil, copyTree(src, dst)
}

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			return os.MkdirAll(target, 0o755)
		case info.Mode()&os.ModeSymlink != 0:
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		default:
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			return os.WriteFile(target, data, info.Mode())
		}
	})
}

// countRsync counts from the call it is installed on, leaving out a bind's
// own mirroring during prepare.
func countRsync(t *testing.T) *int {
	t.Helper()
	var calls int
	orig := runRsync
	runRsync = func(args []string) ([]byte, error) {
		calls++
		return orig(args)
	}
	t.Cleanup(func() { runRsync = orig })
	return &calls
}

// failRsyncOn makes the nth rsync call from here fail, so a test can pick
// which half of a write-back breaks. Every other call still runs.
func failRsyncOn(t *testing.T, n int) {
	t.Helper()
	calls := 0
	orig := runRsync
	runRsync = func(args []string) ([]byte, error) {
		calls++
		if calls == n {
			return []byte("boom"), fmt.Errorf("simulated rsync failure")
		}
		return orig(args)
	}
	t.Cleanup(func() { runRsync = orig })
}
