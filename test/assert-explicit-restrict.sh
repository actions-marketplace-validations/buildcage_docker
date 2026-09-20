#!/bin/bash
set -euo pipefail
source "$(dirname "$0")/helpers.sh"

LOGS=$(builder_log buildkitd)

# BuildKit's exec-proxy identifier omits an explicit ":443"/":80" when the
# original request didn't specify a port, so callers must pass the exact
# target URL they expect in the log, port included only when it's non-default.
assert_denied() {
  local target="$1"
  if grep -qF "ref=\"${target}\"" <<< "$LOGS"; then
    pass "[BLOCKED] $target"
  else
    fail "[BLOCKED] $target -- not found in logs"
  fi
}

# Anchors the needle to right after "://" so e.g. "sub.wildcard.example.com"
# does not spuriously match a denial for "deep.sub.wildcard.example.com".
assert_no_denials_for() {
  local needle="$1"
  local escaped count
  escaped=$(printf '%s' "$needle" | sed 's/[.]/\\./g')
  count=$(echo "$LOGS" | grep -F "denied by policy" | grep -cE "://${escaped}[:/]" || true)
  if [ "$count" -eq 0 ]; then
    pass "no denial entries for \"$needle\""
  else
    fail "found $count unexpected denial entries for \"$needle\""
  fi
}

echo ""
echo "=== Explicit Proxy Engine Assertions ==="
echo ""

echo "[BLOCKED] expected (source-policy denials in buildkitd's own debug log):"
assert_denied "https://blocked.example.com/"
assert_denied "http://blocked.example.com/"
assert_denied "https://blocked.example.com:8443/"
assert_denied "http://blocked.example.com:8080/"
assert_denied "https://deep.sub.wildcard.example.com/"
assert_denied "http://10.200.0.100/"
echo ""

echo "[ALLOWED] must not be denied:"
assert_no_denials_for "allowed.example.com"
assert_no_denials_for "sub.wildcard.example.com"
echo ""

echo "[FROM pull] must not be denied (docker-image:// is out of the ^https?:// policy scope):"
FROM_DENIALS=$(echo "$LOGS" | grep -F "denied by policy" | grep -cF "docker-image://" || true)
if [ "$FROM_DENIALS" -eq 0 ]; then
  pass "no denial entries for docker-image:// sources"
else
  fail "found $FROM_DENIALS unexpected denial entries for docker-image:// sources"
fi
echo ""

REPORT_MARKDOWN=$(GITHUB_STEP_SUMMARY= node report/src/main.ts 2>&1 || true)

echo "[report action] Allowed Hosts table (rendered markdown, from buildctl aggregation):"
if grep -qF "### ✅ Allowed Hosts" <<< "$REPORT_MARKDOWN" \
  && grep -qF "| allowed.example.com:443 | HTTPS | 1 |" <<< "$REPORT_MARKDOWN" \
  && grep -qF "| sub.wildcard.example.com:443 | HTTPS | 1 |" <<< "$REPORT_MARKDOWN"; then
  pass "rendered markdown has an Allowed Hosts table incl. allowed.example.com and sub.wildcard.example.com"
else
  fail "rendered markdown missing expected Allowed Hosts table content"
fi
echo ""

echo "[report action] Blocked Hosts table (rendered markdown, from buildkitd's source-policy denial log):"
if grep -qF "### 🚫 Blocked Hosts" <<< "$REPORT_MARKDOWN" \
  && grep -qF "| blocked.example.com:443 | HTTPS | not-allowed | 1 |" <<< "$REPORT_MARKDOWN" \
  && grep -qF "| deep.sub.wildcard.example.com:443 | HTTPS | not-allowed | 1 |" <<< "$REPORT_MARKDOWN" \
  && grep -qF "| 10.200.0.100:80" <<< "$REPORT_MARKDOWN"; then
  pass "rendered markdown has a Blocked Hosts table incl. blocked.example.com, deep.sub.wildcard.example.com, and 10.200.0.100"
else
  fail "rendered markdown missing expected Blocked Hosts table content"
fi
echo ""

# Step-counter brackets are escaped in the rendered markdown (see
# communication-details.ts's escapeMarkdown): "* \[ 3/15\] RUN ...".
echo "[report action] per-command communication detail (rendered markdown):"
if grep -qF "Communication details" <<< "$REPORT_MARKDOWN" \
  && grep -qF "Allowed Urls" <<< "$REPORT_MARKDOWN" \
  && grep -qE '^ *\* \\\[ *[0-9]+/[0-9]+\\\] RUN ' <<< "$REPORT_MARKDOWN" \
  && grep -qF "(no communication)" <<< "$REPORT_MARKDOWN" \
  && grep -qE -- '- GET https://allowed\.example\.com/ -> 200' <<< "$REPORT_MARKDOWN" \
  && grep -qF "Blocked Urls" <<< "$REPORT_MARKDOWN" \
  && grep -qF "https://blocked.example.com/" <<< "$REPORT_MARKDOWN"; then
  pass "rendered markdown has per-command breakdown, (no communication), and a Blocked Urls list"
else
  fail "rendered markdown missing expected Communication details content"
fi

assert_results
