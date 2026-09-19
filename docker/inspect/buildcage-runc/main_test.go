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
	mustAppendFile(t, logFile, "[another-step] an earlier step on this builder\n")
	logf("CA write-back failed for %s: %v", "/etc/ssl/certs", "rsync exit status 23")
	mustAppendFile(t, logFile, "[another-step] a neighbouring step, still running\n")

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

	mustAppendFile(t, logFile, "[another-step] an earlier step on this builder\n")
	out.Reset()
	dumpOwnLog(&out)
	if out.String() != "" {
		t.Errorf("a step that logged nothing should report nothing, got %q", out.String())
	}
}

// A log path the wrapper cannot open must not take the step down with it: the
// line still has to reach ownLog, which is what dumpOwnLog puts in the build
// log when a write-back fails.
func TestLogfKeepsTheLineWhenTheSharedFileCannotBeOpened(t *testing.T) {
	useTempLog(t)
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "blocked"), "")
	// A regular file stands where logf would have to create a directory.
	logFile = filepath.Join(dir, "blocked", "runc.log")

	logf("CA write-back failed for %s: %v", "/etc/ssl/certs", "rsync exit status 23")

	// ENOTDIR, not ENOENT: a file sits where the directory would be.
	if _, err := os.Stat(logFile); err == nil {
		t.Fatal("the shared log was reachable after all, so this proves nothing")
	}

	var out strings.Builder
	dumpOwnLog(&out)
	if !strings.Contains(out.String(), "rsync exit status 23") {
		t.Errorf("the line did not reach the dump:\n%s", out.String())
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

func TestParseArgs(t *testing.T) {
	cases := []struct {
		name   string
		args   []string
		sub    string
		bundle string
	}{
		{"--bundle and its value as separate arguments",
			[]string{"--log", "/x", "run", "--bundle", "/b", "--keep", "id"}, "run", "/b"},
		{"--bundle=value as one argument",
			[]string{"--log-format", "json", "create", "--bundle=/b", "id"}, "create", "/b"},
		{"a subcommand carrying no bundle",
			[]string{"delete", "id"}, "delete", ""},
		{"a global flag's value is not mistaken for the subcommand",
			[]string{"--log", "/x", "state", "id"}, "state", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sub, bundle := parseArgs(c.args)
			if sub != c.sub || bundle != c.bundle {
				t.Errorf("parseArgs(%v) = %q,%q want %q,%q", c.args, sub, bundle, c.sub, c.bundle)
			}
		})
	}
}
