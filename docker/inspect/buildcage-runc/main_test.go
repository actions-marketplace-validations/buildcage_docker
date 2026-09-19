package main

import (
	"fmt"
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

// BuildKit reads the step's result from runc's exit code, so the wrapper has
// to hand back exactly what the real runc exited with.
func TestRunReturnsTheWrappedExitCode(t *testing.T) {
	useTempLog(t)
	for _, want := range []int{0, 1, 7, 137} {
		t.Run(fmt.Sprintf("exit %d", want), func(t *testing.T) {
			useFakeRunc(t, fmt.Sprintf("exit %d", want))
			if got := run([]string{"state", "id"}); got != want {
				t.Errorf("run exited %d, want %d", got, want)
			}
		})
	}
}

// A runc that cannot be started is the wrapper's own failure, not the step's,
// and has to say so in the log rather than passing for a clean step.
func TestRunReportsARuncItCannotStart(t *testing.T) {
	useTempLog(t)
	realRuncWas := realRunc
	realRunc = filepath.Join(t.TempDir(), "not-there")
	t.Cleanup(func() { realRunc = realRuncWas })

	if got := run([]string{"state", "id"}); got != 1 {
		t.Errorf("run exited %d, want 1", got)
	}
	var out strings.Builder
	dumpOwnLog(&out)
	if !strings.Contains(out.String(), "cannot run") {
		t.Errorf("the failure is not in the log:\n%s", out.String())
	}
}

// A write-back that fails leaves the store half-written, so a step that
// otherwise succeeded must not be allowed to pass: BuildKit would commit the
// snapshot. The wrapper's own log has to reach the build log too, since
// nothing else collects it from the builder container.
func TestRunFailsAStepWhoseWriteBackFailed(t *testing.T) {
	useTempLog(t)
	useFakeRsync(t)
	useTempCAFile(t, "BUILDCAGE-CA")
	bundle, _ := newBundle(t, []string{"PATH=/usr/bin"})

	// The step regenerates the store, which is what makes finish write back.
	t.Setenv("SCRATCH_ROOT", scratchRoot)
	// sh does not glob a redirection target, so the loop resolves it first.
	useFakeRunc(t, `for f in "$SCRATCH_ROOT"/*/ca-certificates.crt; do echo REGENERATED > "$f"; done`)
	// 1 is prepare's mirror and 2 is the write-back's dry run, so 3 is the apply.
	failRsyncOn(t, 3)

	readStderr := captureStderr(t)
	code := run([]string{"run", "--bundle", bundle, "id"})
	stderr := readStderr()

	if code != 1 {
		t.Errorf("run exited %d, want 1: a failed write-back has to fail the step", code)
	}
	if !strings.Contains(stderr, "CA write-back failed") {
		t.Errorf("the failure did not reach stderr:\n%s", stderr)
	}
}
