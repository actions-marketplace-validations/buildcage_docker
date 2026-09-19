package main

import "testing"

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
