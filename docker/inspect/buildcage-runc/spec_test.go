package main

import (
	"fmt"
	"path/filepath"
	"testing"
)

func TestMountConflicts(t *testing.T) {
	cases := []struct {
		name      string
		mounts    []any
		dest      string
		conflicts bool
	}{
		{"no mounts", nil, "/etc/ssl/certs", false},
		{"exact match", []any{map[string]any{"destination": "/etc/ssl/certs"}}, "/etc/ssl/certs", true},
		{"existing is an ancestor", []any{map[string]any{"destination": "/etc"}}, "/etc/ssl/certs", true},
		{"existing is a descendant", []any{map[string]any{"destination": "/etc/ssl/certs/sub"}}, "/etc/ssl/certs", true},
		{"unrelated sibling", []any{map[string]any{"destination": "/etc/ssl/other"}}, "/etc/ssl/certs", false},
		{"an entry that is not a mount at all", []any{"/etc/ssl/certs"}, "/etc/ssl/certs", false},
		{"a mount with no destination", []any{map[string]any{"source": "/somewhere"}}, "/etc/ssl/certs", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &spec{raw: map[string]any{"mounts": c.mounts}}
			if got := s.mountConflicts(c.dest); got != c.conflicts {
				t.Errorf("mountConflicts(%v, %q) = %v, want %v", c.mounts, c.dest, got, c.conflicts)
			}
		})
	}
}

func TestAddBindMount(t *testing.T) {
	s := &spec{raw: map[string]any{}}
	s.addBindMount("/etc/ssl/certs", "/run/buildcage/ca/x")
	mounts, _ := s.raw["mounts"].([]any)
	if len(mounts) != 1 {
		t.Fatalf("got %d mounts, want 1", len(mounts))
	}
	entry := mounts[0].(map[string]any)
	if entry["destination"] != "/etc/ssl/certs" || entry["source"] != "/run/buildcage/ca/x" || entry["type"] != "bind" {
		t.Errorf("unexpected mount entry: %v", entry)
	}

	// Appending to an existing mounts array must not drop what was there.
	s = &spec{raw: map[string]any{"mounts": []any{map[string]any{"destination": "/proc"}}}}
	s.addBindMount("/etc/ssl/certs", "/run/buildcage/ca/x")
	mounts, _ = s.raw["mounts"].([]any)
	if len(mounts) != 2 {
		t.Fatalf("got %d mounts, want 2", len(mounts))
	}
}

// newSpecBundle writes just a config.json, which is all loadSpec reads.
func newSpecBundle(t *testing.T, config string) string {
	t.Helper()
	bundle := t.TempDir()
	mustWriteFile(t, filepath.Join(bundle, "config.json"), config)
	return bundle
}

// BuildKit always writes a config.json before calling runc, so a bundle
// without a readable one means something is wrong enough that injecting into
// it would be guesswork.
func TestLoadSpecRefusesABundleItCannotRead(t *testing.T) {
	cases := map[string]func(t *testing.T) string{
		"no config.json": func(t *testing.T) string { return t.TempDir() },
		"config.json is not JSON": func(t *testing.T) string {
			return newSpecBundle(t, "this is not a runtime spec")
		},
	}
	for name, makeBundle := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := loadSpec(makeBundle(t)); err == nil {
				t.Fatal("expected loadSpec to refuse the bundle")
			}
		})
	}
}

// process.env is a JSON array, so nothing stops it holding something that is
// not a string. Such an entry is skipped rather than taken as an empty name.
func TestLoadSpecSkipsEnvEntriesThatAreNotStrings(t *testing.T) {
	bundle := newSpecBundle(t, `{
		"root": {"path": "rootfs"},
		"process": {"env": ["PATH=/usr/bin", 42, null, {"DENO_CERT": "/x"}, "TZ=UTC"]}
	}`)

	s, err := loadSpec(bundle)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"PATH": "/usr/bin", "TZ": "UTC"}
	if len(s.env) != len(want) {
		t.Fatalf("env = %v, want %v", s.env, want)
	}
	for key, value := range want {
		if s.env[key] != value {
			t.Errorf("env[%q] = %q, want %q", key, s.env[key], value)
		}
	}
}

// setEnv is called with whatever the variable pass decided, which can be
// nothing at all; it must leave the spec exactly as BuildKit wrote it.
func TestSetEnvLeavesTheSpecAloneWithNothingToAdd(t *testing.T) {
	cases := map[string]struct {
		raw   map[string]any
		extra map[string]string
	}{
		"no variables to set": {
			raw:   map[string]any{"process": map[string]any{"env": []any{"PATH=/usr/bin"}}},
			extra: map[string]string{},
		},
		"no process to set them on": {
			raw:   map[string]any{"root": map[string]any{"path": "rootfs"}},
			extra: map[string]string{"SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt"},
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			s := &spec{raw: c.raw}
			before := fmt.Sprint(c.raw)
			s.setEnv(c.extra)
			if got := fmt.Sprint(s.raw); got != before {
				t.Errorf("the spec changed:\n got %s\nwant %s", got, before)
			}
		})
	}
}
