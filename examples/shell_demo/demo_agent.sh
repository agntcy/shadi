#!/bin/bash
# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0
#
# Minimal demo agent for the SHADI interactive shell walkthrough.
# Uses only /bin/bash builtins so it runs inside the Minimal sandbox
# profile without extra --read paths.
#
# Usage:
#   cargo run -p shadictl -- \
#       --policy examples/shell_demo/policy.json --watch-policy \
#       -- bash examples/shell_demo/demo_agent.sh

TICK=${DEMO_TICK:-3}

echo "[demo-agent] starting — press Ctrl-C to stop"
echo "[demo-agent] pid=$$"
echo "[demo-agent] cwd=$(pwd)"
echo "[demo-agent] tick every ${TICK}s"
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
    sleep "$TICK"
done
