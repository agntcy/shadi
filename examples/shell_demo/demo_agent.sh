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
#   cargo run -p shadictl -- \
#       --policy examples/shell_demo/policy.json --watch-policy \
#       -- bash examples/shell_demo/demo_agent.sh

TICK=${DEMO_TICK:-3}
NETWORK_PROBE_IP=${DEMO_NETWORK_IP:-1.1.1.1}
NETWORK_PROBE_PORT=${DEMO_NETWORK_PORT:-80}

if [[ "$(uname -s)" == "Darwin" ]]; then
    PROBE_FILE="/private/etc/hosts"
else
    PROBE_FILE="/etc/hosts"
fi

run_probe() {
    local label="$1"
    shift

    local output
    output="$("$@" 2>&1)"
    local rc=$?
    output="${output//$'\n'/ | }"
    if [[ -z "$output" ]]; then
        output="(no output)"
    fi
    printf '[demo-agent] %-20s rc=%-3d %s\n' "$label" "$rc" "$output"
}

network_probe() {
    nc -vz -w 2 "$NETWORK_PROBE_IP" "$NETWORK_PROBE_PORT"
}

echo "[demo-agent] starting — press Ctrl-C to stop"
echo "[demo-agent] pid=$$"
echo "[demo-agent] cwd=$(pwd)"
echo "[demo-agent] tick every ${TICK}s"
echo "[demo-agent] network probe=tcp://${NETWORK_PROBE_IP}:${NETWORK_PROBE_PORT}"
echo "[demo-agent] probe file=${PROBE_FILE}"
echo "[demo-agent] expected demo flow:"
echo "[demo-agent]   1. TCP connect probe is blocked by network policy"
echo "[demo-agent]   2. rm is blocked by command policy"
echo "[demo-agent]   3. restart with network enabled -> network probe succeeds"
echo "[demo-agent]   4. add read path for ${PROBE_FILE%/*} -> restart -> file read succeeds"
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

    run_probe "network probe" network_probe
    run_probe "file probe" head -n 1 "$PROBE_FILE"
    run_probe "delete probe" rm -f /tmp/shadi-demo-marker

    sleep "$TICK"
done
