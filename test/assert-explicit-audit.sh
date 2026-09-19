#!/bin/bash
# Verifies audit mode: buildkitd never denies anything, and accessed hosts
# show up in the rendered Audited Hosts table.
set -euo pipefail
source "$(dirname "$0")/helpers.sh"

LOGS=$(builder_log buildkitd)

echo ""
echo "=== Explicit Proxy Engine Audit Mode Assertions ==="
echo ""

echo "[no denials] audit mode's empty source policy must never deny anything:"
DENIAL_COUNT=$(echo "$LOGS" | grep -cF "denied by policy" || true)
if [ "$DENIAL_COUNT" -eq 0 ]; then
  pass "no denial entries found in buildkitd's debug log"
else
  fail "found $DENIAL_COUNT unexpected denial entries"
fi
echo ""

# report-action.js renders the full stepSummary itself; report/src/main.ts
# just relays it. GITHUB_STEP_SUMMARY is unset so it prints to stdout
# instead of a job-summary file.
REPORT_MARKDOWN=$(GITHUB_STEP_SUMMARY= node report/src/main.ts 2>&1 || true)

echo "[report action] Audited Hosts table (rendered markdown, from buildctl aggregation):"
if grep -qF "### 📋 Audited Hosts" <<< "$REPORT_MARKDOWN" \
  && grep -qF "| blocked.example.com:443 | HTTPS | 1 |" <<< "$REPORT_MARKDOWN" \
  && grep -qF "| 10.200.0.100:80 | HTTP | 1 |" <<< "$REPORT_MARKDOWN"; then
  pass "rendered markdown has an Audited Hosts table incl. blocked.example.com and 10.200.0.100"
else
  fail "rendered markdown missing expected Audited Hosts table content"
fi
echo ""

# Step-counter brackets are escaped in the rendered markdown (see
# communication-details.ts's escapeMarkdown): "* \[3/8\] RUN ...".
echo "[report action] per-command communication detail (rendered markdown):"
if grep -qF "Communication details" <<< "$REPORT_MARKDOWN" \
  && grep -qF "Allowed Urls" <<< "$REPORT_MARKDOWN" \
  && grep -qE '^ *\* \\\[ *[0-9]+/[0-9]+\\\] RUN ' <<< "$REPORT_MARKDOWN" \
  && grep -qE -- '- GET https://blocked\.example\.com/ -> 200' <<< "$REPORT_MARKDOWN" \
  && ! grep -qF "Blocked Urls" <<< "$REPORT_MARKDOWN"; then
  pass "rendered markdown has per-command breakdown with no Blocked Urls section"
else
  fail "rendered markdown missing expected Communication details content"
fi

assert_results
