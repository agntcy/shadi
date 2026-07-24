#!/usr/bin/env bash
# One-command DID agent-group demo (see did-agent-group.md).
#
# Orchestrates the whole flow so you don't have to hand-coordinate terminals:
#   moderator (avatar) starts a node, creates a channel, and invites claude-code /
#   codex / copilot / cursor-agent (each a DID derived from one human key) — this
#   shows off the DID/moderator role UX. Then all five members run
#   `/slim a2a-collaborate` — an A2A operation backed by SLIM's group channel — to
#   broadcast an intro and collect everyone else's (a roll-call full mesh). Finally,
#   claude-code/codex/copilot register as `agentbridge` adapters backed by the real
#   installed CLI binaries, and the moderator chains a real task across them: codex
#   reports real disk usage, copilot ranks real processes by CPU, and claude-code
#   synthesizes both into an operational report — real work, not a canned reply.
#
# Run from the repo root:  bash docs/content/demos/run-demo.sh
set -uo pipefail
cd "$(dirname "$0")/../../.."   # repo root

BIN=target/debug/shadictl
[ -x "$BIN" ] || { echo "building shadictl…"; cargo build -p agntcy-shadi-cli || exit 1; }
AB=target/debug/agentbridge
[ -x "$AB" ] || { echo "building agentbridge…"; cargo build -p agntcy-agentbridge-cli || exit 1; }

# Fresh, isolated run dir + endpoint; clear any stale shells holding the port.
export SHADI_TMP_DIR="$(mktemp -d /tmp/shadi-did-demo.XXXXXX)"
export SLIM_ENDPOINT="127.0.0.1:47590"
pkill -f "$BIN shell" 2>/dev/null; sleep 1
# shellcheck source=/dev/null
source docs/content/demos/demo-env.sh
bash tools/generate_slim_mtls_certs.sh "$SHADI_TMP_DIR/shadi-slim-mtls" >/dev/null 2>&1 \
  || { echo "mTLS generation failed"; exit 1; }

CH="agntcy/shadi/dev-room"
LOG="$SHADI_TMP_DIR/logs"; mkdir -p "$LOG"
ALL_AGENTS=(avatar claude-code codex copilot cursor-agent)

step() { echo "[$(date +%H:%M:%S)] $*"; }

step "logs: $LOG"
step "watch live progress in another terminal:  bash docs/content/demos/watch-demo.sh"

# One SLIM node spans both parts below; only killed at the very end.
step "starting SLIM node..."
"$BIN" slim start-node >"$LOG/node.log" 2>&1 &
NODE_PID=$!
sleep 2

# --- Part 1: DID/moderator role UX (create/invite/join) -------------------

step "Part 1: agents joining, moderator creating channel + inviting..."

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
step "Part 1 done."

# --- Part 2: roll call over A2A's Collaborate op (SLIM group channel underneath) ---

step "Part 2: roll call — every member broadcasting via /slim a2a-collaborate..."
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
step "Part 2 done."

# --- Part 3: chain a real task across the real coding-agent CLIs (agentbridge) ---
# claude-code, codex, copilot register as live A2A/SLIM adapters backed by the
# actual installed CLI binary — the same DID identity from Part 1 carries over
# automatically (agentbridge checks the same SHADI_SLIM_AUTH=did env). cursor-agent
# has no `agentbridge register` listener yet, so it's skipped here.
# codex checks real disk usage, copilot ranks real processes by CPU, and
# claude-code is given both real outputs and asked to synthesize a report — each
# step depends on the previous agent's real result, not a canned reply.
# A failed delegate below usually means that CLI isn't installed/authenticated on
# this machine, not a SHADI bug — the script continues regardless.

step "Part 3: registering claude-code/codex/copilot as real agentbridge adapters..."
REGISTER_PIDS=()
for a in claude-code codex copilot; do
  env SHADI_AGENT_ID="$a" "$AB" register --tool "$a" --command "$(pwd)" --slim-endpoint "$SLIM_ENDPOINT" \
    >"$LOG/$a-agent.log" 2>&1 &
  REGISTER_PIDS+=($!)
done
sleep 3

step "Part 3: delegating a disk-usage check to codex (real CLI call, can take ~30s)..."
env SHADI_AGENT_ID=avatar "$AB" delegate \
  "Run a disk usage check on this machine (e.g. df -h) and report the real output. Return only the command output, no commentary." \
  --to codex --agent-id avatar --endpoint "$SLIM_ENDPOINT" >"$LOG/codex-delegate.log" 2>&1
DISK_REPORT=$(sed 's/\x1b\[[0-9;]*m//g' "$LOG/codex-delegate.log" | sed -n '/^Response from/,$p' | tail -n +2)

step "Part 3: delegating a top-CPU-processes check to copilot (real CLI call, can take ~30s)..."
env SHADI_AGENT_ID=avatar "$AB" delegate \
  "Rank the top 10 processes on this machine by CPU usage (e.g. ps aux sorted by %CPU) and report the real output. Return only the command output, no commentary." \
  --to copilot --agent-id avatar --endpoint "$SLIM_ENDPOINT" >"$LOG/copilot-delegate.log" 2>&1
CPU_REPORT=$(sed 's/\x1b\[[0-9;]*m//g' "$LOG/copilot-delegate.log" | sed -n '/^Response from/,$p' | tail -n +2)

step "Part 3: delegating report synthesis to claude-code (real CLI call, can take ~30s)..."
REPORT_PROMPT="You are given two real system-health snippets gathered by other agents on this machine. Write a short operational report (a few sentences plus key numbers) summarizing disk usage and CPU load, and flag anything that looks concerning.

=== Disk usage (from codex) ===
$DISK_REPORT

=== Top CPU processes (from copilot) ===
$CPU_REPORT"
env SHADI_AGENT_ID=avatar "$AB" delegate "$REPORT_PROMPT" --to claude-code \
  --agent-id avatar --endpoint "$SLIM_ENDPOINT" >"$LOG/claude-code-delegate.log" 2>&1
step "Part 3 done."

for p in "${REGISTER_PIDS[@]}"; do kill -INT "$p" 2>/dev/null; wait "$p" 2>/dev/null; done

# Every process this script spawned is already tracked and reaped above (SHELL_PIDS,
# COLLAB_PIDS, REGISTER_PIDS, NODE_PID) — deliberately NOT using a blanket
# `pkill -f target/debug/shadictl|agentbridge` here, since that would also kill any
# other run-demo.sh instance running concurrently on this machine.
kill "$NODE_PID" 2>/dev/null
wait "$NODE_PID" 2>/dev/null

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
echo "================ agentbridge: chained real task delegation ================"
echo "-- codex: disk usage --"
strip <"$LOG/codex-delegate.log" | sed -n '/^Response from/,$p'
echo
echo "-- copilot: top CPU processes --"
strip <"$LOG/copilot-delegate.log" | sed -n '/^Response from/,$p'
echo
echo "-- claude-code: synthesized report --"
strip <"$LOG/claude-code-delegate.log" | sed -n '/^Response from/,$p'
echo
echo "logs: $LOG"
