#!/usr/bin/env bash
# One-command DID agent-group demo (see did-agent-group.md).
#
# Orchestrates the whole flow so you don't have to hand-coordinate terminals:
#   moderator (avatar) starts a node, creates a channel, and invites claude-code /
#   codex / copilot / cursor-agent (each a DID derived from one human key) — this
#   shows off the DID/moderator role UX. Then all five members run
#   `/slim a2a-collaborate` — an A2A operation backed by SLIM's group channel — to
#   broadcast an intro and collect everyone else's (a roll-call full mesh).
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
ALL_AGENTS=(avatar claude-code codex copilot cursor-agent)

# One SLIM node spans both parts below; only killed at the very end.
"$BIN" slim start-node >"$LOG/node.log" 2>&1 &
NODE_PID=$!
sleep 2

# --- Part 1: DID/moderator role UX (create/invite/join) -------------------

# Four coding-agent CLIs join the channel and report their role.
SHELL_PIDS=()
for a in claude-code codex copilot cursor-agent; do
  ( sleep 2
    echo "/slim join $CH --timeout 60"
    echo "/slim whoami"
    sleep 6                                   # let every member finish joining
    echo "/exit"
  ) | env SHADI_AGENT_ID="$a" "$BIN" shell >"$LOG/$a.log" 2>&1 &
  SHELL_PIDS+=($!)
done

# Moderator (avatar): create the channel, invite all four.
( echo "/slim create $CH"; sleep 4
  for a in claude-code codex copilot cursor-agent; do echo "/slim invite agntcy/shadi/$a"; done
  echo "/slim whoami"
  sleep 6
  echo "/exit"
) | env SHADI_AGENT_ID=avatar "$BIN" shell >"$LOG/avatar.log" 2>&1 &
SHELL_PIDS+=($!)

for p in "${SHELL_PIDS[@]}"; do wait "$p"; done
pkill -f "$BIN shell" 2>/dev/null

# --- Part 2: roll call over A2A's Collaborate op (SLIM group channel underneath) ---

sleep 1
COLLAB_PIDS=()
for a in "${ALL_AGENTS[@]}"; do
  others=""
  for p in "${ALL_AGENTS[@]}"; do
    [ "$p" != "$a" ] && others="${others:+$others,}$p"
  done
  env SHADI_AGENT_ID="$a" "$BIN" slim a2a-collaborate --agent-id "$a" --peer-agent-ids "$others" \
    --message "Hi, I am $a — reporting in" --timeout-seconds 15 >"$LOG/$a-collaborate.log" 2>&1 &
  COLLAB_PIDS+=($!)
done
for p in "${COLLAB_PIDS[@]}"; do wait "$p"; done

kill "$NODE_PID" 2>/dev/null
pkill -f "target/debug/shadictl" 2>/dev/null

strip() { sed 's/\x1b\[[0-9;]*m//g'; }
echo
echo "================ MODERATOR (avatar) ================"
strip <"$LOG/avatar.log" | grep -iE "created channel|invited|role:|did:|human:"
strip <"$LOG/avatar-collaborate.log" | grep -iE "^broadcast|^  "
for a in claude-code codex copilot cursor-agent; do
  echo "================ $a ================"
  strip <"$LOG/$a.log" | grep -iE "joined|role:|did:|human:"
  strip <"$LOG/$a-collaborate.log" | grep -iE "^broadcast|^  "
done
echo
echo "logs: $LOG"
