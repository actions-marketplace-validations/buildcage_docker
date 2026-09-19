#!/bin/bash
# Shared by the assertion scripts under test/. Sourced rather than executed, so
# it sets no shell options of its own: each script keeps its own.
#
# The log assertions read $LOGS, which the sourcing script fills once up front
# with builder_log. A snapshot rather than a fresh read per assertion, so a
# line arriving mid-run can't make two assertions disagree about the same log.

# The base image the assertion scripts build or run throwaway containers
# from. Pinned by digest like every fixture Dockerfile under test/, so a
# moved tag or a Docker Hub rate limit cannot fail a run for a reason the
# proxy had no part in.
# renovate: datasource=docker depName=alpine
TEST_ALPINE_IMAGE="alpine:3.24.0@sha256:a2d49ea686c2adfe3c992e47dc3b5e7fa6e6b5055609400dc2acaeb241c829f4"

FAILURES=0

pass() { echo "  PASS  $1"; }

fail() {
  echo "  FAIL  $1"
  FAILURES=$((FAILURES + 1))
}

assert_results() {
  echo ""
  if [ "$FAILURES" -gt 0 ]; then
    echo "❌ FAILED: $FAILURES assertion(s) failed"
    exit 1
  fi
  echo "✅ All assertions passed."
  echo ""
}

# One of the builder's s6 service logs: haproxy (universal/inspect), buildkitd
# (explicit) or coredns (inspect's resolver).
builder_log() {
  docker compose exec builder cat "/var/log/$1/current" 2>/dev/null
}

# Escapes a URL for the grep -E patterns below, where it is matched literally.
esc() { printf '%s' "$1" | sed 's/[][\.*^$?+(){}|/]/\\&/g'; }

# ---------------------------------------------------------------------------
# universal engine: connection-level decisions, one line per host:port
# ---------------------------------------------------------------------------

assert_log_contains() {
  local marker="$1"
  local host_port="$2"
  local reason="${3:-}"
  local pattern="\[$marker\].*\"$host_port\""
  local label="[$marker] $host_port"
  if [ -n "$reason" ]; then
    pattern="$pattern $reason"
    label="$label $reason"
  fi
  local buildcage_logs
  buildcage_logs=$(grep buildcage <<< "$LOGS" || true)
  if grep -q "$pattern" <<< "$buildcage_logs"; then
    pass "$label"
  else
    fail "$label -- not found in logs"
  fi
}

assert_log_not_matching() {
  local marker="$1"
  local host_port="$2"
  local reason="${3:-}"
  local pattern="\[$marker\].*\"$host_port\""
  local label="[$marker] $host_port"
  if [ -n "$reason" ]; then
    pattern="$pattern $reason"
    label="$label $reason"
  fi
  local buildcage_logs
  buildcage_logs=$(grep buildcage <<< "$LOGS" || true)
  if grep -q "$pattern" <<< "$buildcage_logs"; then
    fail "found unexpected $label line"
  else
    pass "no $label line"
  fi
}

assert_log_not_contains() {
  local marker="$1"
  local count
  count=$(echo "$LOGS" | grep buildcage | grep -c "\[$marker\]" || true)
  if [ "$count" -eq 0 ]; then
    pass "no [$marker] entries"
  else
    fail "found $count unexpected [$marker] entries"
  fi
}

assert_no_forged_log_lines() {
  local decision_logs
  # Restrict to actual decision lines ("buildcage [...]") -- the plausibility
  # startup line ("buildcage haproxy starting", see s6-rc.d/haproxy/run) has
  # no bracket after "buildcage " and would otherwise false-positive below.
  decision_logs=$(grep 'buildcage \[' <<< "$LOGS" || true)
  local bad_lines
  # A well-formed buildcage line has exactly two double quotes (the
  # host:port field) and no embedded control characters. A forged line
  # (unsanitized attacker bytes) breaks one of those two invariants.
  bad_lines=$(awk '{ n = gsub(/"/, "\""); if (n != 2) print; else if (/[[:cntrl:]]/) print }' <<< "$decision_logs")
  if [ -z "$bad_lines" ]; then
    pass "no forged/malformed buildcage log lines"
  else
    fail "found malformed buildcage log line(s):"
    echo "$bad_lines" | sed 's/^/    /'
  fi
}

# ---------------------------------------------------------------------------
# inspect engine: request-level decisions, one line per method+URL
# ---------------------------------------------------------------------------

# The log line is buildcage's own format (see haproxy-config.ts), so this
# matches on it exactly rather than on a substring that could drift.
assert_logged() {
  local method="$1" url="$2" status="$3"
  if grep -qE "^buildcage [0-9]+ https? ${method} ${status} [0-9]+ ts=\S* reason=\S+ dst=\S+ $(esc "$url")$" <<< "$LOGS"; then
    pass "[$status] $method $url"
  else
    fail "[$status] $method $url -- no such line in the proxy log"
  fi
}
