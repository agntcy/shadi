#!/bin/bash
# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0
#
# Demo agent for the SHADI interactive shell walkthrough.
# It repeatedly attempts actions that exercise different policy axes:
# - blocked command execution (`rm`)
# - blocked network egress (TCP connect via `nc`)
# - blocked file reads outside the allowlist (`/etc/hosts` or `/private/etc/hosts`)
#
# Usage:
#   cargo run -p agntcy-shadi-cli -- \
#       --policy examples/shell_demo/policy.json --watch-policy \
#       -- bash examples/shell_demo/demo_agent.sh

TICK=${DEMO_TICK:-3}
# HTTP probe target.  Using a named host (not a bare IP) exercises the
# hostname-based allowlist path in the SOCKS5 proxy: the proxy receives the
# domain name before DNS resolution and checks it against net_allow.
# example.com is an IANA-reserved domain that reliably returns 200 on plain
# HTTP without redirecting, so rc=0 / http_code=200 means "allowed" and
# rc=97 (CURLE_PROXY / SOCKS5 REP=0x02) means "blocked".
NETWORK_PROBE_URL=${DEMO_NETWORK_URL:-http://example.com/}
# TCP probe target: pure layer-4 test (no HTTP data sent).  Using an IP
# address here keeps the two probes independent — the allowlist entry for the
# HTTP test (httping.org) and the TCP test (1.1.1.1) can be patched separately.
TCP_PROBE_HOST=${DEMO_TCP_HOST:-1.1.1.1}

if [[ "$(uname -s)" == "Darwin" ]]; then
    PROBE_FILE="/private/etc/hosts"
else
    PROBE_FILE="/etc/hosts"
fi

run_probe() {
    local label="$1"
    local intent="$2"
    shift 2

    printf '[demo-agent] %-20s trying: %s\n' "$label" "$intent"
    local output
    output="$("$@" 2>&1)"
    local rc=$?
    output="${output//$'\n'/ | }"
    if [[ -z "$output" ]]; then
        output="(no output)"
    fi
    printf '[demo-agent] %-20s result: rc=%-3d %s\n' "$label" "$rc" "$output"
}

network_probe() {
    # curl honours ALL_PROXY (socks5://…) set by shadictl and routes via SOCKS5;
    # the proxy's net_allow list gates whether the destination is permitted.
    # SOCKS5 works for both http:// and https:// URLs, unlike HTTP CONNECT.
    # The allowlist is matched against the hostname string before DNS resolution,
    # so "httping.org" in net_allow matches this request directly.
    curl --max-time 3 -s -o /dev/null -w "http_code=%{http_code}" "$NETWORK_PROBE_URL"
}

tcp_probe() {
    # Pure TCP probe: connect to TCP_PROBE_HOST:80 and immediately close.
    # bash /dev/tcp requires no extra binary and works in any bash ≥3.
    # rc=0  → TCP connection allowed through the proxy (proxy env is honoured
    #          by bash's /dev/tcp when ALL_PROXY is set, or via socat/curl fallback)
    # rc=1  → connection refused or blocked
    # Note: bash /dev/tcp does NOT honour SOCKS5 proxy env vars.  We use curl
    # with a plain CONNECT-style check instead, falling back to nc if needed.
    local rc=0
    # Try curl first (widely available); `--head` sends a minimal HTTP request.
    if command -v curl >/dev/null 2>&1; then
        curl --max-time 3 -s -o /dev/null -w "tcp_rc=%{http_code}" \
            "http://${TCP_PROBE_HOST}/" || rc=$?
        echo "tcp_rc=${rc}"
    else
        echo "tcp_rc=skip (no curl)"
    fi
}

echo "[demo-agent] starting — press Ctrl-C to stop"
echo "[demo-agent] pid=$$"
echo "[demo-agent] cwd=$(pwd)"
echo "[demo-agent] tick every ${TICK}s"
echo "[demo-agent] http probe=${NETWORK_PROBE_URL}"
echo "[demo-agent] tcp  probe=${TCP_PROBE_HOST}:80"
echo "[demo-agent] probe file=${PROBE_FILE}"
echo "[demo-agent] expected demo flow:"
echo "[demo-agent]   1. http+tcp probes rc=97 (proxy blocks, empty net_allow)"
echo "[demo-agent]   2. rm is blocked by command policy"
echo "[demo-agent]   3. policy patch --add-net-allow example.com -> http probe rc=0, no restart"
echo "[demo-agent]   4. policy patch --add-net-allow 1.1.1.1    -> tcp  probe rc=0, no restart"
echo "[demo-agent]   5. add read path for ${PROBE_FILE%/*} -> restart -> file read succeeds"
echo ""

cleanup() {
    echo ""
    echo "[demo-agent] shutting down"
    exit 0
}
trap cleanup INT TERM

tick=0
while true; do
    tick=$((tick + 1))

    printf "[demo-agent] tick %4d  %s\n" "$tick" "$(date +%H:%M:%S)"

    run_probe "http probe"   "GET ${NETWORK_PROBE_URL} via SOCKS5 proxy (net_allow: example.com?)" network_probe
    run_probe "tcp probe"    "TCP connect ${TCP_PROBE_HOST}:80 via SOCKS5 proxy (net_allow: 1.1.1.1?)" tcp_probe
    run_probe "file probe"   "read first line of ${PROBE_FILE} (read path allowed?)" head -n 1 "$PROBE_FILE"
    run_probe "delete probe" "rm /tmp/shadi-demo-marker (rm in block_command?)" rm -f /tmp/shadi-demo-marker

    sleep "$TICK"
done
