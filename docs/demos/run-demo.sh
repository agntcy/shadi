#!/usr/bin/env bash
# One-command DID agent-group demo (see did-agent-group.md).
#
# Orchestrates the whole flow so you don't have to hand-coordinate terminals:
#   moderator (avatar) starts a node, creates a channel, invites claude-code /
#   codex / copilot / cursor-agent (each a DID derived from one human key), the
#   agents join, and the moderator broadcasts a message that the agents receive.
#
# Run from the repo root:  bash docs/demos/run-demo.sh
set -uo pipefail
cd "$(dirname "$0")/../.."   # repo root

BIN=target/debug/shadictl
[ -x "$BIN" ] || { echo "building shadictl…"; cargo build -p agntcy-shadi-cli || exit 1; }

# Fresh, isolated run dir + endpoint; clear any stale shells holding the port.
export SHADI_TMP_DIR="$(mktemp -d /tmp/shadi-did-demo.XXXXXX)"
export SLIM_ENDPOINT="127.0.0.1:47590"
pkill -f "$BIN shell" 2>/dev/null; sleep 1
# shellcheck source=/dev/null
source docs/demos/demo-env.sh
bash tools/generate_slim_mtls_certs.sh "$SHADI_TMP_DIR/shadi-slim-mtls" >/dev/null 2>&1 \
  || { echo "mTLS generation failed"; exit 1; }

CH="agntcy/shadi/dev-room"
LOG="$SHADI_TMP_DIR/logs"; mkdir -p "$LOG"

# Four coding-agent CLIs: join, introduce themselves to the group, then collect
# everyone else's introductions (roll call).
for a in claude-code codex copilot cursor-agent; do
  ( sleep 3
    echo "/slim join $CH --timeout 60"
    echo "/slim whoami"
    sleep 6                                   # let every member finish joining
    echo "/slim send Hi, I am $a — reporting in"
    for _ in 1 2 3 4 5; do echo "/slim recv --timeout 8"; done
    echo "/exit"
  ) | env SHADI_AGENT_ID="$a" "$BIN" shell >"$LOG/$a.log" 2>&1 &
done

# Moderator (avatar): node, channel, invite all four, greet, then collect the roll call.
( echo "/slim start node"; sleep 2
  echo "/slim create $CH"; sleep 4
  for a in claude-code codex copilot cursor-agent; do echo "/slim invite agntcy/shadi/$a"; done
  echo "/slim whoami"
  sleep 6
  echo "/slim send Welcome — moderator here; please introduce yourselves"
  for _ in 1 2 3 4 5; do echo "/slim recv --timeout 8"; done
  echo "/exit"
) | env SHADI_AGENT_ID=avatar "$BIN" shell >"$LOG/avatar.log" 2>&1 &

wait
pkill -f "$BIN shell" 2>/dev/null

strip() { sed 's/\x1b\[[0-9;]*m//g'; }
echo
echo "================ MODERATOR (avatar) ================"
strip <"$LOG/avatar.log" | grep -iE "created channel|invited|sent to|role:|did:|human:|received:"
for a in claude-code codex copilot cursor-agent; do
  echo "================ $a ================"
  strip <"$LOG/$a.log" | grep -iE "joined|role:|did:|human:|sent to|received:"
done
echo
echo "logs: $LOG"
