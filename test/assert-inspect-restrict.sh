#!/bin/bash
set -euo pipefail
source "$(dirname "$0")/helpers.sh"

LOGS=$(builder_log haproxy)
DNS_LOG=$(builder_log coredns)

echo ""
echo "=== Inspect Proxy Engine Assertions (restrict) ==="
echo ""

echo "[allowed] recorded with the method and the full URL:"
assert_logged GET "https://allowed.example.com/public/pkg.tgz" 200
assert_logged POST "https://api.example.com/v1/thing" 200
assert_logged DELETE "https://sub.wildcard.example.com/anything/at/all" 200
assert_logged GET "http://allowed.example.com/public/pkg.tgz" 200
assert_logged GET "https://attacker.wildcard.example.com/public/pkg.tgz" 200
assert_logged GET "https://blocked.example.com:9443/public/pkg.tgz" 200
assert_logged GET "https://blocked.example.com/defaultport/pkg.tgz" 200
assert_logged GET "https://ok.wildcard.example.com/regexpub/deep/pkg.tgz" 200
assert_logged GET "https://ok.wildcard.example.com/regexexact" 200
echo ""

echo "[refused] recorded with the method and the full URL, before any origin was contacted:"
assert_logged GET "https://allowed.example.com/private/secret" 403
assert_logged POST "https://allowed.example.com/public/pkg.tgz" 403
assert_logged GET "https://absent.example.com/" 502
assert_logged GET "https://v6only.example.com/" 502
assert_logged GET "https://attacker.wildcard.example.com/private/secret" 403
assert_logged GET "https://blocked.example.com:9443/private/secret" 403
assert_logged GET "https://blocked.example.com/public/pkg.tgz" 403
assert_logged GET "https://blocked.example.com:9443/defaultport/pkg.tgz" 403
assert_logged GET "https://not-ok.wildcard.example.com/regexpub/pkg.tgz" 403
assert_logged GET "https://ok.wildcard.example.com/regexexactly" 403
echo ""

echo "[traversal] the path is normalized before the rules see it:"
# Whether the proxy logs the raw or the normalized path, what must never appear
# is a 200: that would mean the origin served /private/ for a /public/ rule.
if grep -qE "^buildcage [0-9]+ https GET 403 [0-9]+ ts=\S* reason=\S+ dst=\S+ sni=\S+ https://allowed\.example\.com/(public/\.\./)?private/secret$" <<< "$LOGS"; then
  pass "GET /public/../private/secret was refused"
else
  fail "GET /public/../private/secret -- no 403 recorded"
fi
echo ""

echo "[client left first] the connection is named by its SNI, the only name it gave:"
# %HM and the Host capture both come from a request that never arrived, so
# without the SNI the line would name no host at all.
# The `https://--` tail is pinned: the parser wants a scheme and something
# behind it, which holds because haproxy writes `-` for the empty Host capture
# and the unset path. A version writing them as nothing would leave a bare
# `https://`, unreadable to the parser and so a failed step. Caught here.
if grep -qE "^buildcage [0-9]+ https <BADREQ> [0-9-]+ [0-9]+ ts=[Cc]R reason=\S+ dst=\S+ sni=aborted\.example\.com https://--$" <<< "$LOGS"; then
  pass "recorded with the handshake's SNI"
else
  fail "no such line for aborted.example.com"
  grep -E "aborted\.example\.com" <<< "$LOGS" || echo "    (no matching log line at all)"
fi
echo ""

echo "[exfiltration] the query string is kept, which is where the payload goes:"
if grep -qF "https://blocked.example.com/exfil?token=SECRET-VALUE" <<< "$LOGS"; then
  pass "the refused URL was recorded with its query string intact"
else
  fail "the refused URL's query string was not recorded"
fi
echo ""

echo "[long URL] a URL the size a signed one really is, recorded whole:"
# The marker is the last thing on the line, so finding it proves nothing was cut.
if grep -qE "^buildcage [0-9]+ https GET 403 [0-9]+ ts=\S+ reason=\S+ dst=\S+ sni=\S+ https://blocked\.example\.com/exfil\?pad=A+&end=TAIL-MARKER$" <<< "$LOGS"; then
  pass "the whole ~1.3KB line was recorded, tail included"
else
  fail "the long URL was cut or dropped"
  grep -c "end=TAIL-MARKER" <<< "$LOGS" || true
fi
# Independent of the pattern above: without the raised `len` (haproxy-sections.ts's
# `log stdout len 16384`), no line could pass 1024 bytes at all.
LONGEST=$(grep -E "^buildcage [0-9]+ https? " <<< "$LOGS" | awk '{print length($0)}' | sort -n | tail -1)
if [ "${LONGEST:-0}" -gt 1024 ]; then
  pass "the log carries a line past haproxy's 1024-byte default ($LONGEST bytes)"
else
  fail "no line passed 1024 bytes, so the length limit is back"
fi
echo ""

echo "[non-standard port] the original port survives to the origin connection:"
if grep -qE "^buildcage [0-9]+ https GET 200 [0-9]+ ts=\S+ reason=\S+ dst=10\.200\.0\.100:9443 sni=\S+ https://allowed\.example\.com:9443/public/pkg\.tgz$" <<< "$LOGS"; then
  pass "reached 10.200.0.100:9443, not the listener's own port"
else
  fail "9443 did not survive to the origin connection"
  grep -E "9443" <<< "$LOGS" || true
fi
echo ""

echo "[forged Host] the destination came from our resolution, not the client's:"
if grep -qE "^buildcage [0-9]+ https GET 200 [0-9]+ ts=\S+ reason=\S+ dst=10\.200\.0\.100:443 sni=\S+ https://allowed\.example\.com/public/pkg\.tgz$" <<< "$LOGS"; then
  pass "connected to 10.200.0.100, the address we resolved"
else
  fail "no request recorded as reaching the resolved address"
fi
# A refused request never connected, so its dst is still where the client
# aimed. Only a request that got an answer proves anything was reached.
if grep -qE "^buildcage [0-9]+ https? [A-Z]+ 2[0-9][0-9] [0-9]+ ts=\\S+ reason=\\S+ dst=10\\.200\\.0\\.101:" <<< "$LOGS"; then
  fail "a request reached the impostor at 10.200.0.101"
else
  pass "nothing reached the impostor at 10.200.0.101"
fi
echo ""

echo "[SSRF] an allowlisted name resolving inward is refused before connecting:"
if grep -qE "^buildcage [0-9]+ https GET 403 [0-9]+ ts=PR reason=internal-address dst=169\.254\.169\.254:443 sni=\S+ https://metadata\.example\.com/latest/meta-data$" <<< "$LOGS"; then
  pass "the name passed the rules but the resolved metadata address was refused"
else
  fail "the internal-destination guard did not fire"
  grep -E "metadata" <<< "$LOGS" || true
fi
echo ""

echo "[SSRF] an allowlisted name resolving back to the runner is refused too:"
if grep -qE "^buildcage [0-9]+ https GET 403 [0-9]+ ts=PR reason=internal-address dst=10\.200\.0\.199:443 sni=\S+ https://runner\.example\.com/$" <<< "$LOGS"; then
  pass "the resolved runner address was refused despite being RFC1918"
else
  fail "the runner's own addresses did not reach the internal-destination guard"
  grep -E "runner\.example\.com" <<< "$LOGS" || true
fi
echo ""

echo "[address destination] reached without asking any resolver:"
if grep -qE "^buildcage [0-9]+ http GET 200 [0-9]+ ts=-- reason=- dst=10\.200\.0\.100:80 http://10\.200\.0\.100/pub-by-addr/x$" <<< "$LOGS"; then
  pass "a rule naming an address reached it, and the path rule still applied"
else
  fail "the address destination was not reached"
fi
# Asking would fail, since no resolver can answer an address, and would also
# put a confusing "name refused" line in the report.
if grep -qE "name=10\.200\.0\.100" <<< "$DNS_LOG"; then
  fail "the resolver was asked about an address"
else
  pass "no resolver was asked about the address"
fi
echo ""

echo "[TLS passthrough] recorded, but never decrypted:"
# It has to appear, or the one thing a build was explicitly allowed to tunnel
# would be the one thing the report cannot show.
if grep -qE "^buildcage [0-9]+ pass tls [0-9]+ ts=\S+ reason=\S+ dst=\S+ sni=tlspass\.example\.com$" <<< "$LOGS"; then
  pass "recorded as an undecrypted passthrough, with its byte count"
else
  fail "the passthrough was not recorded at all"
fi
# Only the ~regex rule names port 8443, so reaching it there proves the rule
# was matched by regex rather than mangled into a wildcard that happens to
# also match :443.
if grep -qE "^buildcage [0-9]+ pass tls [0-9]+ ts=\S+ reason=\S+ dst=10\.200\.0\.100:8443 sni=tlspass\.example\.com$" <<< "$LOGS"; then
  pass "the ~regex TLS rule's own port (8443) reached the resolved origin"
else
  fail "no passthrough was recorded on the ~regex rule's port 8443"
fi
# A request line for it would mean the TLS was terminated after all.
if grep -qE "^buildcage [0-9]+ https? [A-Z]+ [0-9-]+ [0-9]+ ts=\S+ reason=\S+ .*tlspass\.example\.com" <<< "$LOGS"; then
  fail "a passthrough connection was decrypted and logged as a request"
else
  pass "no request-level record, so nothing was decrypted"
fi
echo ""

echo "[Regex IP rule] a ~regex allowed_ip_rules entry passes through, on its own port:"
if grep -qE "^buildcage [0-9]+ pass tcp [0-9]+ ts=\S+ reason=\S+ dst=10\.200\.0\.100:9080 sni=-$" <<< "$LOGS"; then
  pass "recorded as an undecrypted tcp passthrough, on the rule's own port"
else
  fail "no tcp passthrough was recorded on the ~regex ip rule's port 9080"
fi
echo ""

# Everything not passed through is recorded by the frontend that terminates it,
# so nothing else may appear at the tcp stage or it would be counted twice.
# The count is not asserted: a reused container's log spans several builds.
OTHER=$(grep -E "^buildcage [0-9]+ pass " <<< "$LOGS" \
  | grep -v "sni=tlspass\.example\.com" \
  | grep -cv "dst=10\.200\.0\.100:9080" || true)
if [ "$OTHER" -eq 0 ]; then
  pass "only the passthrough is logged at the tcp stage"
else
  fail "found $OTHER tcp-stage lines for hosts that were not passed through"
fi
echo ""

echo "[DNS] a name outside the allowlist is refused and recorded:"
if grep -qiF "buildcage dns denied name=SECRET-IN-A-NAME.attacker.example" <<< "$DNS_LOG"; then
  pass "the exfiltration name was refused by the resolver"
else
  fail "the exfiltration name was not recorded as refused"
fi
if grep -qiF "buildcage dns allowed name=allowed.example.com" <<< "$DNS_LOG"; then
  pass "an allowlisted name was logged as allowed"
else
  fail "no allowlisted name was recorded as allowed"
fi
echo ""

echo "[DNS] a wildcard-host rule's path restriction does not narrow the DNS-layer decision:"
# *.wildcard.example.com/public/** is the rule; attacker.wildcard.example.com
# matches only the host half. CoreDNS cannot see the path, so it logs this
# name as allowed regardless, and answers it with the proxy's own address
# either way (see coredns-config.ts), never resolving it for real. The path
# restriction is enforced entirely by HAProxy, after this DNS decision, which
# is why the request itself still gets refused (checked above via the 403).
if grep -qiF "buildcage dns allowed name=attacker.wildcard.example.com" <<< "$DNS_LOG"; then
  pass "the wildcard-matching name was logged as allowed, on the host alone"
else
  fail "the wildcard-matching name was not recorded as allowed"
fi
echo ""

echo "[DNS] a service-discovery lookup is recorded without being judged:"
# No discovery record is ever served, so no rule could make this lookup
# succeed and a denied row for it would fail a build that worked.
if grep -qF "buildcage dns discovery name=_http._tcp.allowed.example.com. type=SRV" <<< "$DNS_LOG"; then
  pass "the service-discovery lookup was recorded under its own verb, with its type"
else
  fail "the service-discovery lookup was not recorded"
fi
if grep -qF "buildcage dns denied name=_http._tcp.allowed.example.com" <<< "$DNS_LOG"; then
  fail "the service-discovery lookup was recorded as a denied name"
else
  pass "the service-discovery lookup was not recorded as denied"
fi
# Only a service name under a host the rules allow is treated that way, or
# prefixing `_a._tcp.` to an exfiltration name would be a way out.
if grep -qiF "buildcage dns service-denied name=_mongodb._tcp.secret-in-a-name.attacker.example" <<< "$DNS_LOG"; then
  pass "a service name under a host no rule allows was still refused and recorded"
else
  fail "a service name under a host no rule allows was not recorded as refused"
fi

echo "[DNS] a reverse lookup is recorded without being judged:"
# No rule can name a reverse zone, so calling one denied would put a row in the
# report that writing a rule could never take away. The resolver still records
# the lookup, under a verb of its own that the report layer does not read.
if grep -qF "buildcage dns reverse name=1.0.20.172.in-addr.arpa" <<< "$DNS_LOG"; then
  pass "the reverse lookup was recorded under its own verb"
else
  fail "the reverse lookup was not recorded"
fi
if grep -qF "buildcage dns denied name=1.0.20.172.in-addr.arpa" <<< "$DNS_LOG"; then
  fail "the reverse lookup was recorded as a denied name"
else
  pass "the reverse lookup was not recorded as denied"
fi
# Only an address backwards is a reverse lookup. An invented name under the
# same zone is judged like any other, or appending `.in-addr.arpa` would be a
# way out of the report.
if grep -qiF "buildcage dns denied name=SECRET-IN-A-NAME.in-addr.arpa" <<< "$DNS_LOG"; then
  pass "an invented name under the reverse zone was still refused and recorded"
else
  fail "an invented name under the reverse zone was not recorded as refused"
fi
echo ""

echo "[UDP] the echo server the build could not reach is reachable from beside it:"
# Without this control, a build that reached nothing would pass even if the
# fixture were simply dead.
UDP_REPLY=$(docker compose exec -T test-dns sh -c \
  'echo probe | nc -u -w 3 10.200.0.102 9999' 2>/dev/null | tr -d '\r\n' || true)
if [ "$UDP_REPLY" = "probe" ]; then
  pass "the echo server answers on test-net, so the build's silence was the cage"
else
  fail "the echo server did not answer from test-net either (got \"$UDP_REPLY\")"
fi
echo ""

REPORT_MARKDOWN=$(GITHUB_STEP_SUMMARY= node report/src/main.ts 2>&1 || true)

echo "[report] Allowed Hosts:"
if grep -qF "### ✅ Allowed Hosts" <<< "$REPORT_MARKDOWN" \
  && grep -qF "| allowed.example.com:443 | HTTPS |" <<< "$REPORT_MARKDOWN" \
  && grep -qF "| allowed.example.com:80 | HTTP |" <<< "$REPORT_MARKDOWN" \
  && grep -qF "| 10.200.0.100:9080 | IP |" <<< "$REPORT_MARKDOWN"; then
  pass "the table lists the hosts that were reached"
else
  fail "the Allowed Hosts table is missing expected rows"
fi
echo ""

echo "[report] Blocked Hosts, including a name that never reached the proxy:"
if grep -qF "### 🚫 Blocked Hosts" <<< "$REPORT_MARKDOWN" \
  && grep -qF "| blocked.example.com:443 | HTTPS | not-allowed |" <<< "$REPORT_MARKDOWN" \
  && grep -qF "| absent.example.com:443 | HTTPS | dns-failed |" <<< "$REPORT_MARKDOWN" \
  && grep -qF "| v6only.example.com:443 | HTTPS | dns-failed |" <<< "$REPORT_MARKDOWN" \
  && grep -qiF "| secret-in-a-name.attacker.example | DNS | dns-not-allowed |" <<< "$REPORT_MARKDOWN"; then
  pass "the table separates a refused request, an unresolvable name and a refused name"
else
  fail "the Blocked Hosts table is missing expected rows"
fi
echo ""

echo "[report] one timeline, with everything the build did in order:"
if grep -qF "Communication details" <<< "$REPORT_MARKDOWN" \
  && grep -qF "✅ " <<< "$REPORT_MARKDOWN" \
  && grep -qF "🚫 " <<< "$REPORT_MARKDOWN"; then
  pass "allowed and refused are interleaved rather than split"
else
  fail "the Communication details section is missing or still split"
fi

# A refusal names why: 403, 502 and 503 mean different things and the number
# does not say which.
if grep -qF "POST https://allowed.example.com/public/pkg.tgz -> not-allowed" <<< "$REPORT_MARKDOWN" \
  && grep -qF "https://absent.example.com/ -> dns-failed" <<< "$REPORT_MARKDOWN" \
  && grep -qF "https://blocked.example.com/exfil?token=*** -> not-allowed" <<< "$REPORT_MARKDOWN"; then
  pass "a refusal names its reason and keeps its URL"
else
  fail "a refusal is missing its reason or its URL"
fi

# The report is as readable as the run; the traffic artifact, checked below, is
# where the value itself survives.
if grep -qF "token=SECRET-VALUE" <<< "$REPORT_MARKDOWN"; then
  fail "a credential parameter's value reached the report"
else
  pass "a credential parameter's value was replaced"
fi

# The summary is where a reader looks first.
if grep -qF "end=TAIL-MARKER -> not-allowed" <<< "$REPORT_MARKDOWN"; then
  pass "the ~1.3KB refused URL reached the summary with its tail"
else
  fail "the long refused URL is missing or cut in the summary"
fi

# A passthrough is never decrypted, so this is the only place it can appear.
if grep -qE 'TLS tlspass\.example\.com:443 -> \([0-9.]+[A-Za-z]+\)' <<< "$REPORT_MARKDOWN"; then
  pass "an undecrypted passthrough is in the timeline with its byte count"
else
  fail "the passthrough is missing from the timeline"
fi

if grep -qF "DNS secret-in-a-name.attacker.example -> dns-not-allowed" <<< "$REPORT_MARKDOWN"; then
  pass "a refused name is in the timeline, having no other trace"
else
  fail "the refused name is missing from the timeline"
fi

# No rule decided it, so it belongs in neither table and the timeline is the
# only place it can appear.
if grep -qE "⚠️ .*: HTTPS aborted\.example\.com:443 -> client-(aborted|timeout)$" <<< "$REPORT_MARKDOWN"; then
  pass "a connection the client left is in the timeline, with a mark of its own"
else
  fail "the aborted connection is missing from the timeline"
fi
if grep -qF "| aborted.example.com:443 | HTTPS |" <<< "$REPORT_MARKDOWN"; then
  fail "the aborted connection was put in one of the host tables"
else
  pass "the aborted connection is in neither host table"
fi
# No rule takes the row above away, so the refused lookup for the same name has
# to survive: it is the only row a reader can act on.
if grep -qF "| aborted.example.com | DNS | dns-not-allowed |" <<< "$REPORT_MARKDOWN"; then
  pass "the refused lookup for the same name is still its own Blocked row"
else
  fail "the refused lookup for the aborted host was folded away"
fi

if grep -qF "1.0.20.172.in-addr.arpa" <<< "$REPORT_MARKDOWN"; then
  fail "a reverse lookup reached the report"
else
  pass "a reverse lookup is left out of the report entirely"
fi

if grep -qiF "secret-in-a-name.in-addr.arpa" <<< "$REPORT_MARKDOWN"; then
  pass "an invented name under the reverse zone still reaches the report"
else
  fail "an invented name under the reverse zone was dropped from the report too"
fi

# The lookup no rule could permit stays out of the blocked table; the timeline
# carries it instead, with the type.
if grep -qE '_http\._tcp\.allowed\.example\.com.*dns-(service-)?not-allowed' <<< "$REPORT_MARKDOWN"; then
  fail "a service-discovery lookup under an allowed host was reported as blocked"
else
  pass "a service-discovery lookup under an allowed host was not reported as blocked"
fi
if grep -qF "DNS SRV _http._tcp.allowed.example.com -> no data" <<< "$REPORT_MARKDOWN"; then
  pass "the service-discovery lookup is in the timeline, with its type"
else
  fail "the service-discovery lookup is missing from the timeline"
fi
# The refusal names its own remedy: the host below the name, which is what a
# rule can be written against.
if grep -qiF "dns-service-not-allowed" <<< "$REPORT_MARKDOWN"; then
  pass "a refused service name is reported with a reason of its own"
else
  fail "a refused service name was reported as an ordinary refused name"
fi

# Listing a name that resolved doubles every line, and the request that
# followed already says it did.
if grep -qE 'DNS allowed\.example\.com ->' <<< "$REPORT_MARKDOWN"; then
  fail "a name that merely resolved is in the timeline"
else
  pass "a name that merely resolved is left out"
fi
echo ""

echo "[report] the traffic artifact:"
# writeTrafficFile only runs when BUILDCAGE_TRAFFIC_FILE is set, which
# report/src/main.ts normally does itself from upload_traffic_artifact; set
# it directly here to reach the same path without a real GitHub Actions
# runtime to upload through.
BUILDER_CID=$(docker compose ps -q builder)
SCRATCH_DIR=$(mktemp -d)
docker cp "$BUILDER_CID:/opt/buildcage/scripts/report-action.js" "$SCRATCH_DIR/report-action.js" 2>/dev/null
TRAFFIC_FILE="$SCRATCH_DIR/traffic.json"
GITHUB_STEP_SUMMARY= BUILDCAGE_TRAFFIC_FILE="$TRAFFIC_FILE" \
  node "$SCRATCH_DIR/report-action.js" "$BUILDER_CID" >/dev/null 2>&1 || true
TRAFFIC=$(cat "$TRAFFIC_FILE" 2>/dev/null || true)
if [ -n "$TRAFFIC" ] \
  && echo "$TRAFFIC" | node -e '
      const rows = JSON.parse(require("fs").readFileSync(0, "utf8"));
      const need = [
        // Filtering is on action, never on status: a refusal has no status.
        (r) => r.action === "block" && r.method === "POST" && r.status === undefined,
        (r) => r.action === "block" && (r.url || "").includes("token=SECRET-VALUE"),
        // Long enough to be cut by the default line length.
        (r) => r.action === "block" && (r.url || "").endsWith("end=TAIL-MARKER"),
        (r) => r.action === "allow" && r.protocol === "https" && r.status === 200 && r.bytes > 0,
        // Only inspect can report these two at all.
        (r) => r.protocol === "tls" && r.host === "tlspass.example.com" && r.bytes > 0,
        (r) => r.protocol === "dns" && r.action === "block" && r.reason === "dns-not-allowed",
        // The JSON keeps a lookup the summary folds into the request that followed.
        (r) => r.protocol === "dns" && r.action === "allow",
      ];
      const ok = need.every((f) => rows.some(f))
        && rows.every((r) => r.time && r.action && r.protocol && r.host)
        && rows.every((r) => r.protocol !== "dns" || r.port === undefined)
        && rows.every((r) => r.action !== "block" || r.reason)
        && rows.every((r, i) => i === 0 || rows[i - 1].time <= r.time);
      process.exit(ok ? 0 : 1);
    '; then
  pass "valid JSON, time-ordered, with action/protocol/host on every record"
else
  echo "  ---- traffic.json ----"
  cat "$TRAFFIC_FILE" 2>/dev/null || echo "(missing)"
  fail "the traffic artifact is missing or malformed"
fi
rm -rf "$SCRATCH_DIR"
echo ""

assert_results
