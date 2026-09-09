#!/usr/bin/env bash
# Constrained A2A unicast — same DID addressing and fifo cargo-test outcome
# as the SLIM collab demo, without a SLIM node or paid CLIs.
#
# Binding (default grpc):  TRANSPORT=grpc|jsonrpc|http+json
# Run from the repo root:  bash docs/content/demos/run-a2a-grpc-demo.sh
set -uo pipefail
cd "$(dirname "$0")/../../.."   # repo root

BIN="${CARGO_TARGET_DIR:-target}/debug/shadictl"
[ -x "$BIN" ] || { echo "building shadictl…"; cargo build -p agntcy-shadi-cli || exit 1; }
AB="${CARGO_TARGET_DIR:-target}/debug/agentbridge"
[ -x "$AB" ] || { echo "building agentbridge…"; cargo build -p agntcy-agentbridge-cli || exit 1; }
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
AB="$(cd "$(dirname "$AB")" && pwd)/$(basename "$AB")"
APPLY=docs/content/demos/collab-apply.py
SCRIPT=docs/content/demos/a2a-grpc-stdio.py
[ -f "$APPLY" ] || { echo "missing $APPLY"; exit 1; }
[ -f "$SCRIPT" ] || { echo "missing $SCRIPT"; exit 1; }
PYTHON="$(command -v python3)" || { echo "python3 is required"; exit 1; }

"$PYTHON" "$SCRIPT" --self-test || exit 1

SHADI_TMP_DIR_RAW="$(mktemp -d /tmp/shadi-a2a-grpc-demo.XXXXXX)"
export SHADI_TMP_DIR="$(cd "$SHADI_TMP_DIR_RAW" && pwd -P)"
# shellcheck source=/dev/null
source docs/content/demos/demo-env.sh
# clap register --slim-endpoint reads SLIM_ENDPOINT. Unicast-only must not dual-listen.
unset SLIM_ENDPOINT
TRANSPORT="${TRANSPORT:-grpc}"
case "$TRANSPORT" in
  grpc|jsonrpc|http+json) ;;
  *) echo "TRANSPORT must be grpc, jsonrpc, or http+json (got $TRANSPORT)"; exit 1 ;;
esac

LOG="$SHADI_TMP_DIR/logs"; mkdir -p "$LOG"
WS="$SHADI_TMP_DIR/workspace"; mkdir -p "$WS"
PROFILES="$SHADI_TMP_DIR/profiles"; mkdir -p "$PROFILES"
export AGENTBRIDGE_PROFILES_DIR="$PROFILES"
export TMPDIR="$SHADI_TMP_DIR"
export AGENTBRIDGE_A2A_FORWARD=1
export AGENTBRIDGE_A2A_PEERS="copilot,codex"
export PYTHONDONTWRITEBYTECODE=1

SCRIPT_ABS="$(cd "$(dirname "$SCRIPT")" && pwd)/$(basename "$SCRIPT")"
PYTHON_BIN="$PYTHON"
if command -v python3 >/dev/null; then
  PYTHON_BIN="$("$PYTHON" -c 'import sys; print(sys.executable)')"
fi

write_profile() {
  local id="$1"
  cat >"$PROFILES/${id}.json" <<EOF
{
  "id": "${id}",
  "bin": "${PYTHON_BIN}",
  "pin_tmpdir": false,
  "current_dir_workdir": true,
  "stdin_null": true,
  "execute": {
    "args": ["${SCRIPT_ABS}", "--prompt", "{prompt}"]
  },
  "result": { "kind": "stdout" }
}
EOF
}
write_profile copilot
write_profile codex

COPILOT_LISTEN="${COPILOT_LISTEN:-127.0.0.1:50151}"
CODEX_LISTEN="${CODEX_LISTEN:-127.0.0.1:50152}"
COPILOT_LISTEN_2="${COPILOT_LISTEN_2:-127.0.0.1:50161}"

step() { echo "[$(date +%H:%M:%S)] $*"; }
strip() { sed 's/\x1b\[[0-9;]*m//g'; }

step "logs: $LOG"

NET_ALLOW_FLAGS=(
  --net-allow "$COPILOT_LISTEN"
  --net-allow "$CODEX_LISTEN"
  --net-allow "$COPILOT_LISTEN_2"
)

register_one() {
  local id="$1" listen="$2"
  env -u SLIM_ENDPOINT \
    SHADI_AGENT_ID="$id" TMPDIR="$SHADI_TMP_DIR" \
    AGENTBRIDGE_A2A_FORWARD=1 AGENTBRIDGE_A2A_PEERS="$AGENTBRIDGE_A2A_PEERS" \
    AGENTBRIDGE_PROFILES_DIR="$PROFILES" PYTHONDONTWRITEBYTECODE=1 \
    "$BIN" --net-block "${NET_ALLOW_FLAGS[@]}" \
    --read "$SHADI_TMP_DIR" --write "$SHADI_TMP_DIR" \
    --read "$PWD" --read "$HOME" --read /usr --read /opt/homebrew --read /Library \
    --read "$(dirname "$AB")" --read "$(dirname "$BIN")" -- \
    "$AB" register --tool "$id" --command "$WS" --a2a-listen "$listen" \
    --a2a-binding "$TRANSPORT" \
    >"$LOG/${id}-agent.log" 2>&1 &
  echo $!
}

wait_leases() {
  local want="$1"
  local i
  for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    env SHADI_AGENT_ID=avatar "$AB" list --local >"$LOG/list-local.log" 2>&1 || true
    n=$(grep -cE '(grpc|jsonrpc|http\+json)://127\.0\.0\.1' "$LOG/list-local.log" 2>/dev/null || true)
    [ "${n:-0}" -ge "$want" ] && return 0
    sleep 1
  done
  step "listeners not ready:"
  strip <"$LOG/list-local.log" | sed 's/^/  /'
  return 1
}

lease_field() {
  local name="$1" which="$2"
  # name  did=DID  grpc://... | jsonrpc://... | http+json://...
  awk -v n="$name" -v w="$which" '
    $1 == n {
      if (w == "did") {
        for (i = 1; i <= NF; i++) if ($i ~ /^did=/) { sub(/^did=/, "", $i); print $i; exit }
      }
      if (w == "url") {
        for (i = 1; i <= NF; i++) if ($i ~ /^(grpc|jsonrpc|http\+json):\/\//) { print $i; exit }
      }
    }
  ' "$LOG/list-local.log"
}

locator_uri() {
  echo "${TRANSPORT}://$1"
}

REGISTER_PIDS=()
cleanup() {
  local p
  for p in "${REGISTER_PIDS[@]:-}"; do
    kill -INT "$p" 2>/dev/null
    wait "$p" 2>/dev/null
  done
}
trap cleanup EXIT

step "registering copilot + codex on A2A $TRANSPORT..."
REGISTER_PIDS+=("$(register_one copilot "$COPILOT_LISTEN")")
REGISTER_PIDS+=("$(register_one codex "$CODEX_LISTEN")")
wait_leases 2 || { cat "$LOG/copilot-agent.log" "$LOG/codex-agent.log"; exit 1; }
step "local listeners:"
strip <"$LOG/list-local.log" | sed 's/^/  /'

COPILOT_DID="$(lease_field copilot did)"
CODEX_DID="$(lease_field codex did)"
COPILOT_URL="$(lease_field copilot url)"
[ -n "$COPILOT_DID" ] && [ -n "$COPILOT_URL" ] || { echo "missing copilot lease"; exit 1; }

step "1/4 echo PONG by DID (locator from lease)..."
env SHADI_AGENT_ID=avatar "$AB" delegate "PING from avatar" \
  --to "$COPILOT_DID" --agent-id avatar \
  >"$LOG/echo.raw" 2>&1 || true
strip <"$LOG/echo.raw" | sed 's/^/  /'
grep -q "PONG" "$LOG/echo.raw" || { echo "expected PONG"; exit 1; }

step "2/4 dest DID mismatch is rejected (URL is only a locator)..."
env SHADI_AGENT_ID=avatar "$AB" delegate "PING should not run" \
  --to "did:key:zWrongDestinationDidxxxxxxxxxxxxxxxxxxxxxxxx" \
  --a2a-url "$COPILOT_URL" --agent-id avatar \
  >"$LOG/mismatch.raw" 2>&1 || true
strip <"$LOG/mismatch.raw" | sed 's/^/  /'
if grep -q "PONG" "$LOG/mismatch.raw"; then
  echo "listener executed a task addressed to another DID"
  exit 1
fi
if ! grep -qiE "destination DID|Rejected|locator|wrong" "$LOG/mismatch.raw"; then
  echo "expected dest-DID rejection in $LOG/mismatch.raw"
  exit 1
fi

step "3/4 same DID after URL change..."
kill -INT "${REGISTER_PIDS[0]}" 2>/dev/null
wait "${REGISTER_PIDS[0]}" 2>/dev/null || true
for _ in 1 2 3 4 5 6 7 8 9 10; do
  env SHADI_AGENT_ID=avatar "$AB" list --local >"$LOG/list-local.log" 2>&1 || true
  if ! awk '$1=="copilot"{found=1} END{exit !found}' "$LOG/list-local.log"; then
    break
  fi
  sleep 0.3
done
REGISTER_PIDS[0]="$(register_one copilot "$COPILOT_LISTEN_2")"
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  env SHADI_AGENT_ID=avatar "$AB" list --local >"$LOG/list-local.log" 2>&1 || true
  MOVED_URL="$(lease_field copilot url)"
  [ "$MOVED_URL" = "$(locator_uri "$COPILOT_LISTEN_2")" ] && break
  sleep 0.4
done
MOVED_URL="$(lease_field copilot url)"
step "  copilot moved $COPILOT_URL → $MOVED_URL (did=$COPILOT_DID)"
[ "$MOVED_URL" != "$COPILOT_URL" ] || { echo "expected a new listen URL"; cat "$LOG/copilot-agent.log" | tail -n 30; exit 1; }
env SHADI_AGENT_ID=avatar "$AB" delegate "PING after move" \
  --to "$COPILOT_DID" --agent-id avatar \
  >"$LOG/moved.raw" 2>&1 || true
strip <"$LOG/moved.raw" | sed 's/^/  /'
grep -q "PONG" "$LOG/moved.raw" || { echo "DID lookup did not follow the new URL"; exit 1; }

write_fifo_scaffold() {
  local dir="$1"
  mkdir -p "$dir/src"
  cat >"$dir/Cargo.toml" <<'EOF'
[package]
name = "collab_fifo"
version = "0.1.0"
edition = "2021"
EOF
  cat >"$dir/src/lib.rs" <<'EOF'
/// First-in, first-out queue.
pub struct Fifo<T> {
    items: Vec<T>,
}

impl<T> Fifo<T> {
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }

    pub fn push(&mut self, _item: T) {}

    pub fn pop(&mut self) -> Option<T> {
        None
    }

    pub fn len(&self) -> usize {
        0
    }

    pub fn is_empty(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_new() {
        let mut q: Fifo<i32> = Fifo::new();
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);
        assert_eq!(q.pop(), None);
    }

    #[test]
    fn push_pop_order() {
        let mut q = Fifo::new();
        q.push(1);
        q.push(2);
        q.push(3);
        assert_eq!(q.len(), 3);
        assert_eq!(q.pop(), Some(1));
        assert_eq!(q.pop(), Some(2));
        assert_eq!(q.pop(), Some(3));
        assert!(q.is_empty());
    }
}
EOF
}

numbered_src() { nl -ba -w2 -s'| ' "$1"; }

build_prompt() {
  local goal="$1" src="$2" testlog="$3" agent="$4" hop="$5"
  cat <<EOF
You are ${agent} on hop ${hop} of a token-passing collaboration.
Peers: copilot, codex.
You are both an A2A server (this prompt arrived over A2A) and an A2A client
(after your edit, this listener sends NEXT to the peer you name).

GOAL: ${goal}

HARD RULE: you may output AT MOST TWO lines of Rust. A third line of code is discarded.
Only REPLACE a stub method body (None, 0, false, empty Vec, empty put, or empty push).

Reply with EXACTLY one of these shapes, then one routing line:

REPLACE <1-based-line-number>
<one line of rust>
<optional second line of rust>
NEXT <peer-id>

NEXT must be one of copilot, codex and must not be you.
If you believe cargo test will pass after your edit, write DONE instead of NEXT.

Current src/lib.rs:
$(numbered_src "$src")

Last cargo test:
$(tail -n 40 "$testlog")
EOF
}

step "4/4 fifo token-passing until cargo test (same outcome as SLIM collab)..."
DIR="$WS/fifo"
SRC="$DIR/src/lib.rs"
TESTLOG="$LOG/fifo-test.log"
TRANSCRIPT="$LOG/fifo-turns.log"
: >"$TRANSCRIPT"
write_fifo_scaffold "$DIR"
( cd "$DIR" && cargo test --offline -- --nocapture ) >"$TESTLOG" 2>&1 || true

AGENTS=(copilot codex)
GOAL="Implement Fifo<T> (new/push/pop/len/is_empty) as a real FIFO so every unit test passes."
agent="copilot"
hop=0
max_hops=8
STATUS=1
while [ "$hop" -lt "$max_hops" ]; do
  hop=$((hop + 1))
  turn_id="fifo-h${hop}-${agent}"
  prompt_file="$LOG/${turn_id}.prompt"
  raw_file="$LOG/${turn_id}.raw"
  before="$LOG/${turn_id}.before.rs"
  cp "$SRC" "$before"
  build_prompt "$GOAL" "$SRC" "$TESTLOG" "$agent" "$hop" >"$prompt_file"
  step "  hop $hop / $max_hops → $agent"
  env SHADI_AGENT_ID=avatar "$AB" delegate "$(cat "$prompt_file")" \
    --to "$agent" --agent-id avatar \
    >"$raw_file" 2>&1 || true
  reply="$LOG/${turn_id}.reply"
  strip <"$raw_file" | sed -n '/^Response from/,$p' | tail -n +2 >"$reply"
  python3 "$APPLY" "$SRC" <"$reply" >"$SRC.next" 2>"$LOG/${turn_id}.apply" || cp "$SRC" "$SRC.next"
  mv "$SRC.next" "$SRC"
  echo "--- $turn_id ---" >>"$TRANSCRIPT"
  echo "apply: $(cat "$LOG/${turn_id}.apply")" >>"$TRANSCRIPT"
  if ! cmp -s "$before" "$SRC"; then
    echo "diff:" >>"$TRANSCRIPT"
    diff -u "$before" "$SRC" | sed 's/^/  /' >>"$TRANSCRIPT" || true
  fi
  chosen="$(python3 "$APPLY" --next <"$reply" || true)"
  echo "next: ${chosen:-none}" >>"$TRANSCRIPT"
  ( cd "$DIR" && cargo test --offline -- --nocapture ) >"$TESTLOG" 2>&1 || true
  if grep -q "test result: ok" "$TESTLOG"; then
    step "fifo SOLVED after hop $hop ($agent)"
    echo "SOLVED fifo after $turn_id" >>"$TRANSCRIPT"
    STATUS=0
    break
  fi
  if [ "$chosen" = "DONE" ]; then
    step "  $agent said DONE but cargo test is still failing"
    break
  elif [ "$chosen" = "copilot" ] || [ "$chosen" = "codex" ]; then
    agent="$chosen"
  else
    [ "$agent" = "copilot" ] && agent="codex" || agent="copilot"
  fi
done

echo
echo "================ local listeners ================"
strip <"$LOG/list-local.log"
echo
echo "================ fifo turns ================"
cat "$TRANSCRIPT"
echo
echo "================ fifo src/lib.rs (final) ================"
cat "$SRC"
echo
echo "================ fifo cargo test (last) ================"
strip <"$TESTLOG" | tail -n 20
echo
echo "logs: $LOG"
if [ "$STATUS" -ne 0 ]; then
  echo "fifo was not solved after $max_hops hops"
  cat "$LOG/copilot-agent.log" | tail -n 40
  cat "$LOG/codex-agent.log" | tail -n 40
fi
exit "$STATUS"
