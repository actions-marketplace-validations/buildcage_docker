package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// useTempLog points logf and the dump at a file the test owns, since a test
// process usually can't write the real host path.
func useTempLog(t *testing.T) {
	t.Helper()
	oldFile, oldTag := logFile, logTag
	logFile = filepath.Join(t.TempDir(), "runc.log")
	logTag = "[this-step]"
	ownLog.Reset()
	t.Cleanup(func() {
		logFile, logTag = oldFile, oldTag
		ownLog.Reset()
	})
}

// A failure must report the failing step's lines and no one else's, however
// the concurrent steps ended up interleaved on disk.
func TestDumpOwnLogCoversOnlyThisInvocation(t *testing.T) {
	useTempLog(t)
	appendToSharedLog(t, "[another-step] an earlier step on this builder\n")
	logf("CA write-back failed for %s: %v", "/etc/ssl/certs", "rsync exit status 23")
	appendToSharedLog(t, "[another-step] a neighbouring step, still running\n")

	var out strings.Builder
	dumpOwnLog(&out)

	got := out.String()
	if strings.Contains(got, "another-step") {
		t.Errorf("the dump picked up a neighbouring step's lines:\n%s", got)
	}
	if !strings.Contains(got, "rsync exit status 23") {
		t.Errorf("the dump left out this step's own failure:\n%s", got)
	}
	if !strings.Contains(got, logFile) {
		t.Errorf("the dump does not say where the lines came from:\n%s", got)
	}
}

// Nothing to report means no output at all, not a bare header.
func TestDumpOwnLogWithNothingToReport(t *testing.T) {
	useTempLog(t)

	var out strings.Builder
	dumpOwnLog(&out)
	if out.String() != "" {
		t.Errorf("expected no output before anything was logged, got %q", out.String())
	}

	appendToSharedLog(t, "[another-step] an earlier step on this builder\n")
	out.Reset()
	dumpOwnLog(&out)
	if out.String() != "" {
		t.Errorf("a step that logged nothing should report nothing, got %q", out.String())
	}
}

// The shared file is what's left to read after the fact, so every line in it
// has to name the step that wrote it.
func TestLogfTagsEachSharedLine(t *testing.T) {
	useTempLog(t)
	logf("no CA at %s (%v); running without injection", "/opt/buildcage/ca.pem", "file does not exist")
	logf("injection failed for %s: %v", "/run/bundle", "permission denied")

	content, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(content), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("wrote %d lines to the shared log, want 2:\n%s", len(lines), content)
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, logTag+" ") {
			t.Errorf("line %q is not tagged with %s", line, logTag)
		}
	}
}

func appendToSharedLog(t *testing.T, line string) {
	t.Helper()
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(line); err != nil {
		t.Fatal(err)
	}
}
