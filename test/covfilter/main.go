// Command covfilter decides whether a Go coverage profile is complete once the
// blocks a source comment marks as deliberately untested are taken out.
//
// Go has no way to say "this statement does not need a test": cmd/cover takes
// no exclusion flag and the toolchain carries no directive for it (the proposal
// for one, golang/go#53271, was closed without it). A profile is one line per
// block, though, so the decision can be made afterwards from markers that sit
// next to the code they excuse:
//
//	// Untested by design: <why>
//	//coverage:ignore start
//	...
//	//coverage:ignore stop
//
// A marker is held to its word. One covering a block the tests do reach, or
// covering no block at all, fails the run the same way a gap does, so the list
// of what is deliberately untested cannot quietly stop being true.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	markerStart = "//coverage:ignore start"
	markerStop  = "//coverage:ignore stop"
)

func main() {
	os.Exit(run(os.Stderr, os.Args[1:]))
}

// block is one entry of a coverage profile: a half-open span of source holding
// stmts statements, which the instrumented run entered count times.
type block struct {
	file      string // as the profile spells it, module path and all
	startLine int
	endLine   int
	stmts     int
	count     int
}

// region is one //coverage:ignore start/stop pair, by line number.
type region struct{ start, stop int }

func (r region) holds(line int) bool { return line >= r.start && line <= r.stop }

func run(w io.Writer, args []string) int {
	flags := flag.NewFlagSet("covfilter", flag.ContinueOnError)
	flags.SetOutput(w)
	profile := flags.String("profile", "", "coverage profile from `go test -coverprofile`")
	pkg := flags.String("pkg", ".", "directory of the module the profile covers")
	threshold := flags.Float64("threshold", 100, "percentage the remaining statements must reach")
	out := flags.String("out", "", "write the filtered profile here as well")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *profile == "" {
		fmt.Fprintln(w, "covfilter: -profile is required")
		return 2
	}

	if err := check(w, *profile, *pkg, *threshold, *out); err != nil {
		fmt.Fprintf(w, "covfilter: %v\n", err)
		return 1
	}
	return 0
}

func check(w io.Writer, profile, pkg string, threshold float64, out string) error {
	blocks, header, err := parseProfile(profile)
	if err != nil {
		return err
	}
	module, err := modulePath(pkg)
	if err != nil {
		return err
	}

	// Markers are read once per file, from the source the profile names.
	regions := map[string][]region{}
	sources := map[string][]string{}
	for _, b := range blocks {
		if _, done := regions[b.file]; done {
			continue
		}
		path := filepath.Join(pkg, strings.TrimPrefix(strings.TrimPrefix(b.file, module), "/"))
		lines, err := readLines(path)
		if err != nil {
			return err
		}
		found, err := findRegions(b.file, lines)
		if err != nil {
			return err
		}
		sources[b.file], regions[b.file] = lines, found
	}

	var kept, stale, gaps []block
	used := map[string]map[region]bool{}
	for _, b := range blocks {
		r, ignored := regionFor(regions[b.file], b.startLine)
		if !ignored {
			kept = append(kept, b)
			if b.count == 0 {
				gaps = append(gaps, b)
			}
			continue
		}
		if used[b.file] == nil {
			used[b.file] = map[region]bool{}
		}
		used[b.file][r] = true
		if b.count > 0 {
			stale = append(stale, b)
		}
	}

	if out != "" {
		if err := writeProfile(out, header, kept); err != nil {
			return err
		}
	}

	var problems []string
	if len(stale) > 0 {
		report(w, "marked untested by design, but the tests reach them", stale, sources, module)
		problems = append(problems, fmt.Sprintf("%s marked but covered", plural(len(stale), "statement")))
	}
	if empty := unusedRegions(regions, used); len(empty) > 0 {
		for _, e := range empty {
			fmt.Fprintf(w, "\n%s: ignore marker covers no statement\n", e)
		}
		problems = append(problems, fmt.Sprintf("%s covering nothing", plural(len(empty), "ignore marker")))
	}

	stmts, covered := 0, 0
	for _, b := range kept {
		stmts += b.stmts
		if b.count > 0 {
			covered += b.stmts
		}
	}
	pct := 100.0
	if stmts > 0 {
		pct = float64(covered) / float64(stmts) * 100
	}
	if pct < threshold {
		report(w, "neither covered nor marked untested by design", gaps, sources, module)
		problems = append(problems, fmt.Sprintf("%.1f%% of %d statements, want %.1f%%", pct, stmts, threshold))
	}

	if len(problems) > 0 {
		return fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	ignoredStmts := 0
	for _, b := range blocks {
		if _, ignored := regionFor(regions[b.file], b.startLine); ignored {
			ignoredStmts += b.stmts
		}
	}
	fmt.Fprintf(w, "covfilter: %.1f%% of %d statements (%d marked untested by design)\n",
		pct, stmts, ignoredStmts)
	return nil
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

func regionFor(regions []region, line int) (region, bool) {
	for _, r := range regions {
		if r.holds(line) {
			return r, true
		}
	}
	return region{}, false
}

func unusedRegions(regions map[string][]region, used map[string]map[region]bool) []string {
	var empty []string
	for file, rs := range regions {
		for _, r := range rs {
			if !used[file][r] {
				empty = append(empty, fmt.Sprintf("%s:%d", filepath.Base(file), r.start))
			}
		}
	}
	sort.Strings(empty)
	return empty
}

var funcLine = regexp.MustCompile(`^func (?:\([^)]*\) )?(\w+)`)

// report prints one line per block, naming the function it sits in, so the
// output says what to go and look at rather than only how many there are.
func report(w io.Writer, what string, blocks []block, sources map[string][]string, module string) {
	if len(blocks) == 0 {
		return
	}
	fmt.Fprintf(w, "\n%s %s:\n\n", plural(len(blocks), "statement"), what)
	sort.Slice(blocks, func(i, j int) bool {
		if blocks[i].file != blocks[j].file {
			return blocks[i].file < blocks[j].file
		}
		return blocks[i].startLine < blocks[j].startLine
	})
	for _, b := range blocks {
		lines := sources[b.file]
		name, text := "?", ""
		for i, line := range lines {
			if i >= b.startLine {
				break
			}
			if m := funcLine.FindStringSubmatch(line); m != nil {
				name = m[1]
			}
		}
		if b.startLine-1 < len(lines) {
			text = strings.TrimSpace(lines[b.startLine-1])
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(b.file, module), "/")
		fmt.Fprintf(w, "  %s:%d  %s()  %s\n", rel, b.startLine, name, text)
	}
	fmt.Fprintln(w)
}

func parseProfile(path string) ([]block, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()

	var blocks []block
	header := ""
	scan := bufio.NewScanner(f)
	for line := 1; scan.Scan(); line++ {
		text := scan.Text()
		if line == 1 {
			header = text
			continue
		}
		if text == "" {
			continue
		}
		b, err := parseBlock(text)
		if err != nil {
			return nil, "", fmt.Errorf("%s:%d: %w", path, line, err)
		}
		blocks = append(blocks, b)
	}
	if err := scan.Err(); err != nil {
		return nil, "", err
	}
	if !strings.HasPrefix(header, "mode:") {
		return nil, "", fmt.Errorf("%s: not a coverage profile", path)
	}
	return blocks, header, nil
}

// parseBlock reads one profile line: "file:startLine.col,endLine.col stmts count".
func parseBlock(text string) (block, error) {
	fields := strings.Fields(text)
	if len(fields) != 3 {
		return block{}, fmt.Errorf("want 3 fields, got %d", len(fields))
	}
	file, span, ok := strings.Cut(fields[0], ":")
	if !ok {
		return block{}, fmt.Errorf("no file in %q", fields[0])
	}
	from, to, ok := strings.Cut(span, ",")
	if !ok {
		return block{}, fmt.Errorf("no span in %q", fields[0])
	}
	start, err := lineOf(from)
	if err != nil {
		return block{}, err
	}
	end, err := lineOf(to)
	if err != nil {
		return block{}, err
	}
	stmts, err := strconv.Atoi(fields[1])
	if err != nil {
		return block{}, err
	}
	count, err := strconv.Atoi(fields[2])
	if err != nil {
		return block{}, err
	}
	return block{file: file, startLine: start, endLine: end, stmts: stmts, count: count}, nil
}

func lineOf(pos string) (int, error) {
	line, _, ok := strings.Cut(pos, ".")
	if !ok {
		return 0, fmt.Errorf("no line in %q", pos)
	}
	return strconv.Atoi(line)
}

// findRegions pairs the markers in one file. An unmatched or nested marker is
// an error rather than a guess: the block it was meant to cover would silently
// stop being excused.
func findRegions(file string, lines []string) ([]region, error) {
	var regions []region
	open := 0
	for i, line := range lines {
		switch strings.TrimSpace(line) {
		case markerStart:
			if open != 0 {
				return nil, fmt.Errorf("%s:%d: %s inside the one opened at line %d", file, i+1, markerStart, open)
			}
			open = i + 1
		case markerStop:
			if open == 0 {
				return nil, fmt.Errorf("%s:%d: %s without a start", file, i+1, markerStop)
			}
			regions = append(regions, region{start: open, stop: i + 1})
			open = 0
		}
	}
	if open != 0 {
		return nil, fmt.Errorf("%s:%d: %s without a stop", file, open, markerStart)
	}
	return regions, nil
}

func readLines(path string) ([]string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return strings.Split(string(content), "\n"), nil
}

// modulePath reads the module line of pkg's go.mod, which is the prefix the
// profile puts in front of every file name.
func modulePath(pkg string) (string, error) {
	content, err := os.ReadFile(filepath.Join(pkg, "go.mod"))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(content), "\n") {
		if path, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
			return strings.TrimSpace(path), nil
		}
	}
	return "", fmt.Errorf("%s/go.mod: no module line", pkg)
}

func writeProfile(path, header string, blocks []block) error {
	var b strings.Builder
	b.WriteString(header + "\n")
	for _, blk := range blocks {
		fmt.Fprintf(&b, "%s:%d.1,%d.1 %d %d\n", blk.file, blk.startLine, blk.endLine, blk.stmts, blk.count)
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}
