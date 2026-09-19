package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixture lays out a one-file module and the profile that goes with it. source
// is the file's body, so a test can place markers where it wants them; blocks
// are profile lines as "startLine-endLine:stmts:count".
func fixture(t *testing.T, source string, blocks ...string) (pkg, profile string) {
	t.Helper()
	pkg = t.TempDir()
	mustWrite(t, filepath.Join(pkg, "go.mod"), "module example.com/thing\n\ngo 1.24\n")
	mustWrite(t, filepath.Join(pkg, "thing.go"), source)

	var b strings.Builder
	b.WriteString("mode: set\n")
	for _, spec := range blocks {
		var start, end, stmts, count int
		if _, err := fmt.Sscanf(spec, "%d-%d:%d:%d", &start, &end, &stmts, &count); err != nil {
			t.Fatalf("bad block spec %q: %v", spec, err)
		}
		fmt.Fprintf(&b, "example.com/thing/thing.go:%d.2,%d.3 %d %d\n", start, end, stmts, count)
	}
	profile = filepath.Join(t.TempDir(), "cov.out")
	mustWrite(t, profile, b.String())
	return pkg, profile
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// runFilter returns the exit code and everything covfilter printed.
func runFilter(t *testing.T, pkg, profile string, extra ...string) (int, string) {
	t.Helper()
	var out strings.Builder
	args := append([]string{"-profile=" + profile, "-pkg=" + pkg}, extra...)
	return run(&out, args), out.String()
}

// The source below is the shape every case reuses: one function whose second
// statement is the one a test decides to cover, mark, or leave bare.
const source = `package thing

func f(ok bool) error {
	if !ok {
		return errBad
	}
	return nil
}
`

// The plain case: everything the profile reports is covered, so there is
// nothing to excuse and nothing to report.
func TestFullyCoveredPasses(t *testing.T) {
	pkg, profile := fixture(t, source, "3-4:1:1", "4-6:1:1", "7-7:1:1")

	code, out := runFilter(t, pkg, profile)
	if code != 0 {
		t.Fatalf("exit %d, want 0:\n%s", code, out)
	}
	if !strings.Contains(out, "100.0% of 3 statements") {
		t.Errorf("unexpected summary:\n%s", out)
	}
}

// A gap is what the whole tool exists to catch, and the message has to say
// where to look rather than only how many there are.
func TestAGapFails(t *testing.T) {
	pkg, profile := fixture(t, source, "3-4:1:1", "4-6:1:0", "7-7:1:1")

	code, out := runFilter(t, pkg, profile)
	if code != 1 {
		t.Fatalf("exit %d, want 1:\n%s", code, out)
	}
	for _, want := range []string{"thing.go:4", "f()", "66.7% of 3 statements"} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not mention %q:\n%s", want, out)
		}
	}
}

// The same gap, marked: the statement leaves the denominator rather than
// counting as covered, and the summary says how much was excused.
func TestAMarkedGapPasses(t *testing.T) {
	marked := strings.Replace(source, "	if !ok {\n		return errBad\n	}\n", `	//coverage:ignore start
	if !ok {
		return errBad
	}
	//coverage:ignore stop
`, 1)
	pkg, profile := fixture(t, marked, "3-4:1:1", "5-7:1:0", "9-9:1:1")

	code, out := runFilter(t, pkg, profile)
	if code != 0 {
		t.Fatalf("exit %d, want 0:\n%s", code, out)
	}
	if !strings.Contains(out, "100.0% of 2 statements; 1 marker excludes 1 more, 1 of them unreached") {
		t.Errorf("unexpected summary:\n%s", out)
	}
}

// A marker has to excuse something. One over code the tests reach, or over no
// code at all, is either in the wrong place or left over from code that has
// gone; either way it no longer says anything true. This is the check that
// keeps a list of deliberate exclusions from rotting as the code under it
// changes.
func TestAMarkerThatExcusesNothingFails(t *testing.T) {
	marked := strings.Replace(source, "	if !ok {\n		return errBad\n	}\n", `	//coverage:ignore start
	if !ok {
		return errBad
	}
	//coverage:ignore stop
`, 1)
	cases := map[string]struct {
		source string
		blocks []string
	}{
		"over code the tests reach": {marked, []string{"3-4:1:1", "5-7:1:3", "9-9:1:1"}},
		"over no code at all": {
			source + "\n//coverage:ignore start\n// nothing here any more\n//coverage:ignore stop\n",
			[]string{"3-4:1:1", "4-6:1:1", "7-7:1:1"},
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			pkg, profile := fixture(t, c.source, c.blocks...)

			code, out := runFilter(t, pkg, profile)
			if code != 1 {
				t.Fatalf("exit %d, want 1:\n%s", code, out)
			}
			if !strings.Contains(out, "excuses nothing") {
				t.Errorf("output does not say the marker excuses nothing:\n%s", out)
			}
		})
	}
}

// An unmatched marker silently un-excuses whatever came after it, so it is an
// error rather than something to guess at.
func TestUnbalancedMarkersFail(t *testing.T) {
	cases := map[string]string{
		"start without stop": source + "\n//coverage:ignore start\n",
		"stop without start": source + "\n//coverage:ignore stop\n",
		"start inside start": source + "\n//coverage:ignore start\n//coverage:ignore start\n//coverage:ignore stop\n",
	}
	for name, marked := range cases {
		t.Run(name, func(t *testing.T) {
			pkg, profile := fixture(t, marked, "3-4:1:1", "4-6:1:1", "7-7:1:1")

			code, out := runFilter(t, pkg, profile)
			if code != 1 {
				t.Fatalf("exit %d, want 1:\n%s", code, out)
			}
			if !strings.Contains(out, "coverage:ignore") {
				t.Errorf("output does not name the marker:\n%s", out)
			}
		})
	}
}

// The threshold is what lets the gap be closed a step at a time instead of all
// at once, so it has to be the number the run is actually held to.
func TestThresholdIsWhatTheRunIsHeldTo(t *testing.T) {
	pkg, profile := fixture(t, source, "3-4:1:1", "4-6:1:0", "7-7:1:1")

	if code, out := runFilter(t, pkg, profile, "-threshold=66"); code != 0 {
		t.Errorf("66.7%% should clear a threshold of 66: exit %d\n%s", code, out)
	}
	if code, _ := runFilter(t, pkg, profile, "-threshold=67"); code != 1 {
		t.Errorf("66.7%% should not clear a threshold of 67: exit %d", code)
	}
}

// The filtered profile is what go tool cover -html is pointed at, so the
// marked blocks have to be gone from it rather than merely discounted.
func TestFilteredProfileDropsTheMarkedBlocks(t *testing.T) {
	marked := strings.Replace(source, "	if !ok {\n		return errBad\n	}\n", `	//coverage:ignore start
	if !ok {
		return errBad
	}
	//coverage:ignore stop
`, 1)
	pkg, profile := fixture(t, marked, "3-4:1:1", "5-7:1:0", "9-9:1:1")
	out := filepath.Join(t.TempDir(), "filtered.out")

	if code, printed := runFilter(t, pkg, profile, "-out="+out); code != 0 {
		t.Fatalf("exit %d:\n%s", code, printed)
	}
	content, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(content), "mode: set\n") {
		t.Errorf("the filtered profile lost its header:\n%s", content)
	}
	if lines := strings.Count(strings.TrimSpace(string(content)), "\n"); lines != 2 {
		t.Errorf("got %d blocks, want 2 (the marked one dropped):\n%s", lines, content)
	}
}

// Bad input is the tool's own failure, not the package's, and has to be
// distinguishable from a coverage gap.
func TestUsageErrorsExitTwo(t *testing.T) {
	var out strings.Builder
	if code := run(&out, nil); code != 2 {
		t.Errorf("missing -profile exited %d, want 2", code)
	}
	if code := run(&out, []string{"-nonsense"}); code != 2 {
		t.Errorf("an unknown flag exited %d, want 2", code)
	}
}

func TestAProfileThatIsNotOneFails(t *testing.T) {
	pkg, _ := fixture(t, source)
	profile := filepath.Join(t.TempDir(), "cov.out")
	mustWrite(t, profile, "this is not a coverage profile\n")

	code, out := runFilter(t, pkg, profile)
	if code != 1 {
		t.Fatalf("exit %d, want 1:\n%s", code, out)
	}
	if !strings.Contains(out, "not a coverage profile") {
		t.Errorf("unexpected message:\n%s", out)
	}
}

func TestAMarkerDoesNotTakeTheRunUpToAnIf(t *testing.T) {
	marked := `package thing

func f(ok bool) error {
	x := setUp()
	//coverage:ignore start
	if !ok {
		return errBad
	}
	//coverage:ignore stop
	return use(x)
}
`
	// The run-up ends on line 6, where the body begins; the marker spans 5-9.
	pkg, profile := fixture(t, marked, "4-6:2:1", "6-8:1:0", "10-10:1:1")

	code, out := runFilter(t, pkg, profile)
	if code != 0 {
		t.Fatalf("exit %d, want 0:\n%s", code, out)
	}
	if !strings.Contains(out, "100.0% of 3 statements; 1 marker excludes 1 more, 1 of them unreached") {
		t.Errorf("the run-up was taken with the body:\n%s", out)
	}
}
