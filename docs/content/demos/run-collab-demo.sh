#!/usr/bin/env bash
# Round-robin Rust collaboration (see collab-rust.md).
#
# Coding-agent CLIs (claude-code, copilot, codex, cursor-agent, goose) write a
# well-known Rust snippet. Each turn may add or change at most TWO lines of
# code — the orchestrator enforces the cap even if an agent dumps a whole file.
# The agent also chooses the next peer (NEXT <id> / DONE). Avatar starts the
# first hop; the finishing listener dispatches that A2A handoff itself.
# Override the set with COLLAB_AGENTS=goose,claude-code (comma-separated).
# Goose uses the operator's existing Goose config; this script does not set a
# model or provider. --net-allow includes cisco.com and *.cisco.com. Extra
# hosts: COLLAB_NET_ALLOW=host1,host2.
#
# Problems (set PROBLEM=lru|fifo|both, default lru):
#   lru   — Lru<K, V> cache (many stubs; typically ~20 two-line hops)
#   fifo  — Fifo<T> queue
#
# Run from the repo root:  bash docs/content/demos/run-collab-demo.sh
# Same fifo/lru outcome over official A2A unicast (no SLIM node):
#   TRANSPORT=grpc PROBLEM=fifo bash docs/content/demos/run-collab-demo.sh
#   TRANSPORT=jsonrpc PROBLEM=fifo bash docs/content/demos/run-collab-demo.sh
set -uo pipefail
cd "$(dirname "$0")/../../.."   # repo root

BIN="${CARGO_TARGET_DIR:-target}/debug/shadictl"
[ -x "$BIN" ] || { echo "building shadictl…"; cargo build -p agntcy-shadi-cli || exit 1; }
AB="${CARGO_TARGET_DIR:-target}/debug/agentbridge"
[ -x "$AB" ] || { echo "building agentbridge…"; cargo build -p agntcy-agentbridge-cli || exit 1; }
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
AB="$(cd "$(dirname "$AB")" && pwd)/$(basename "$AB")"
APPLY=docs/content/demos/collab-apply.py
[ -f "$APPLY" ] || { echo "missing $APPLY"; exit 1; }

TRANSPORT="${TRANSPORT:-slim}"
unicast_transport() {
  case "$TRANSPORT" in
    grpc|jsonrpc|http+json) return 0 ;;
    *) return 1 ;;
  esac
}
if [ -z "${SHADI_TMP_DIR:-}" ]; then
  SHADI_TMP_DIR_RAW="$(mktemp -d /tmp/shadi-collab-demo.XXXXXX)"
  export SHADI_TMP_DIR="$(cd "$SHADI_TMP_DIR_RAW" && pwd -P)"
else
  mkdir -p "$SHADI_TMP_DIR"
  export SHADI_TMP_DIR="$(cd "$SHADI_TMP_DIR" && pwd -P)"
fi
export SLIM_ENDPOINT="${SLIM_ENDPOINT:-127.0.0.1:47591}"
A2A_BASE_PORT="${A2A_BASE_PORT:-50151}"
# shellcheck source=/dev/null
source docs/content/demos/demo-env.sh
if unicast_transport; then
  # clap register --slim-endpoint reads SLIM_ENDPOINT. Unicast-only must not dual-listen.
  unset SLIM_ENDPOINT
else
  bash tools/generate_slim_mtls_certs.sh "$SHADI_TMP_DIR/shadi-slim-mtls" >/dev/null 2>&1 \
    || { echo "mTLS generation failed"; exit 1; }
fi

LOG="$SHADI_TMP_DIR/logs"; mkdir -p "$LOG"
WS="$SHADI_TMP_DIR/workspace"; mkdir -p "$WS"
if [ -n "${COLLAB_AGENTS:-}" ]; then
  IFS=',' read -r -a AGENTS <<<"$COLLAB_AGENTS"
else
  AGENTS=(claude-code copilot codex cursor-agent goose)
fi
PROBLEM="${PROBLEM:-lru}"
MAX_CYCLES="${MAX_CYCLES:-8}"

step() { echo "[$(date +%H:%M:%S)] $*"; }
strip() { sed 's/\x1b\[[0-9;]*m//g'; }

step "logs: $LOG"
step "watch live:  bash docs/content/demos/watch-collab-demo.sh"
step "transport: $TRANSPORT"

NODE_PID=""
if ! unicast_transport; then
  step "starting SLIM node..."
  "$BIN" slim start-node >"$LOG/node.log" 2>&1 &
  NODE_PID=$!
  sleep 2
fi

step "registering ${#AGENTS[@]} agentbridge adapters..."
REGISTER_PIDS=()
# Copilot/Codex inherit TMPDIR; pin it to the writable demo tree.
export TMPDIR="$SHADI_TMP_DIR"
# HOME stays read-only. These CLI state dirs need write for token refresh
# and app-server sockets (cursor chats, Codex ~/.codex, Claude keychain).
CURSOR_HOME="$HOME/.cursor"
CODEX_HOME_DIR="$HOME/.codex"
CLAUDE_HOME="$HOME/.claude"
GOOSE_CONFIG="$HOME/.config/goose"
GOOSE_SHARE="$HOME/.local/share/goose"
GOOSE_STATE="$HOME/.local/state/goose"
KEYCHAINS="$HOME/Library/Keychains"
mkdir -p "$CURSOR_HOME/projects" "$CURSOR_HOME/chats" "$CODEX_HOME_DIR" "$CLAUDE_HOME" \
  "$GOOSE_CONFIG" "$GOOSE_SHARE" "$GOOSE_STATE"
export AGENTBRIDGE_A2A_FORWARD=1
export AGENTBRIDGE_A2A_PEERS="${AGENTS[*]}"
AGENTBRIDGE_A2A_PEERS="${AGENTBRIDGE_A2A_PEERS// /,}"

# SLIM or per-agent gRPC listen ports, plus cisco.com (and subdomains).
# COLLAB_NET_ALLOW adds more hosts.
NET_ALLOW_FLAGS=(
  --net-allow cisco.com
  --net-allow "*.cisco.com"
)
A2A_LISTEN_ADDRS=()
if unicast_transport; then
  i=0
  for _a in "${AGENTS[@]}"; do
    A2A_LISTEN_ADDRS+=("127.0.0.1:$((A2A_BASE_PORT + i))")
    i=$((i + 1))
  done
  for listen in "${A2A_LISTEN_ADDRS[@]}"; do
    NET_ALLOW_FLAGS+=(--net-allow "$listen")
  done
else
  NET_ALLOW_FLAGS+=(--net-allow "$SLIM_ENDPOINT")
fi
if [ -n "${COLLAB_NET_ALLOW:-}" ]; then
  IFS=',' read -r -a EXTRA_NET <<<"$COLLAB_NET_ALLOW"
  for dest in "${EXTRA_NET[@]}"; do
    dest="${dest#"${dest%%[![:space:]]*}"}"
    dest="${dest%"${dest##*[![:space:]]}"}"
    [ -n "$dest" ] || continue
    NET_ALLOW_FLAGS+=(--net-allow "$dest")
  done
fi

EXTRA_READ=()
if [ -n "${AGENTBRIDGE_PROFILES_DIR:-}" ]; then
  EXTRA_READ+=(--read "$AGENTBRIDGE_PROFILES_DIR" --read "$PWD")
fi

i=0
for a in "${AGENTS[@]}"; do
  register_args=(register --tool "$a" --command "$WS")
  if unicast_transport; then
    register_args+=(--a2a-listen "${A2A_LISTEN_ADDRS[$i]}" --a2a-binding "$TRANSPORT")
  else
    register_args+=(--slim-endpoint "$SLIM_ENDPOINT")
  fi
  register_env=(
    SHADI_AGENT_ID="$a"
    TMPDIR="$SHADI_TMP_DIR"
    AGENTBRIDGE_A2A_FORWARD=1
    AGENTBRIDGE_A2A_PEERS="$AGENTBRIDGE_A2A_PEERS"
    PYTHONDONTWRITEBYTECODE=1
  )
  if [ -n "${AGENTBRIDGE_PROFILES_DIR:-}" ]; then
    register_env+=(AGENTBRIDGE_PROFILES_DIR="$AGENTBRIDGE_PROFILES_DIR")
  fi
  env "${register_env[@]}" \
    "$BIN" --net-block "${NET_ALLOW_FLAGS[@]}" \
    --read "$SHADI_TMP_DIR" --write "$SHADI_TMP_DIR" \
    --read "$HOME" \
    --write "$CURSOR_HOME" --write "$CODEX_HOME_DIR" --write "$CLAUDE_HOME" \
    --write "$GOOSE_CONFIG" --write "$GOOSE_SHARE" --write "$GOOSE_STATE" \
    --write "$KEYCHAINS" --read /opt/homebrew --read /usr \
    --read "$(dirname "$AB")" --read "$(dirname "$BIN")" "${EXTRA_READ[@]}" -- \
    "$AB" "${register_args[@]}" \
    >"$LOG/$a-agent.log" 2>&1 &
  REGISTER_PIDS+=($!)
  i=$((i + 1))
done
# Leases appear after each listener binds; a fixed 3s sleep often lists none.
LEASE_MARK="slim://"
case "$TRANSPORT" in
  grpc) LEASE_MARK="grpc://" ;;
  jsonrpc) LEASE_MARK="jsonrpc://" ;;
  http+json) LEASE_MARK="http+json://" ;;
esac
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  env SHADI_AGENT_ID=avatar "$AB" list --local >"$LOG/list-local.log" 2>&1 || true
  n=$(grep -c "$LEASE_MARK" "$LOG/list-local.log" 2>/dev/null || true)
  [ "${n:-0}" -ge "${#AGENTS[@]}" ] && break
  sleep 1
done
step "local listeners:"
strip <"$LOG/list-local.log" | sed 's/^/  /'

write_lru_scaffold() {
  local dir="$1"
  local src_root="docs/content/demos/scaffolds/collab_lru"
  mkdir -p "$dir/src"
  cp "$src_root/Cargo.toml" "$dir/Cargo.toml"
  cp "$src_root/src/lib.rs" "$dir/src/lib.rs"
}

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

extract_response() {
  strip | sed -n '/^Response from/,$p' | tail -n +2
}

numbered_src() {
  nl -ba -w2 -s'| ' "$1"
}

run_tests() {
  local dir="$1"
  ( cd "$dir" && cargo test --offline -- --nocapture ) >"$2" 2>&1
}

fallback_next() {
  local current="$1"
  local i
  for i in "${!AGENTS[@]}"; do
    if [ "${AGENTS[$i]}" = "$current" ]; then
      echo "${AGENTS[$(( (i + 1) % ${#AGENTS[@]} ))]}"
      return
    fi
  done
  echo "${AGENTS[0]}"
}

valid_peer() {
  local name="$1"
  local a
  for a in "${AGENTS[@]}"; do
    [ "$a" = "$name" ] && return 0
  done
  return 1
}

build_prompt() {
  local goal="$1" src="$2" testlog="$3" agent="$4" hop="$5" last_share="${6:-}"
  local peers="${AGENTS[*]}"
  peers="${peers// /, }"
  cat <<EOF
You are ${agent} on hop ${hop} of a token-passing collaboration.
Peers: ${peers}.
You are both an A2A server (this prompt arrived over A2A) and an A2A client
(after your edit, this listener sends NEXT to the peer you name).

GOAL: ${goal}

HARD RULE: you may output AT MOST TWO lines of Rust. A third line of code is discarded.
Only REPLACE a stub method body (None, 0, false, empty Vec, empty put, or empty push).
Never REPLACE a pub fn / pub struct signature, a doc comment, or any test.
Never emit a second copy of an existing function.
Do not finish get or put in one hop if more than two lines are needed.
Do not rewrite the file. Do not explain. No markdown fences.

Reply with EXACTLY one of these shapes, then one routing line:

REPLACE <1-based-line-number>
<one line of rust>
<optional second line of rust>
NEXT <peer-id>

INSERT <1-based-line-number>
<one line of rust>
<optional second line of rust>
NEXT <peer-id>

APPEND
<one line of rust>
<optional second line of rust>
NEXT <peer-id>

NEXT must be one of ${peers} and must not be you.
Pick the peer best placed to finish the remaining stubs or failing tests.
If you believe cargo test will pass after your edit, write DONE instead of NEXT.
NEXT and DONE are routing, not Rust — they are not applied to the file.

Current src/lib.rs:
$(numbered_src "$src")

Last cargo test:
$(tail -n 40 "$testlog")
EOF
  if [ -n "$last_share" ] && [ -f "$last_share" ]; then
    printf '\nLast peer shared (their A2A turn):\n'
    cat "$last_share"
  fi
}

run_problem() {
  local name="$1" goal="$2"
  local dir="$WS/$name"
  local src="$dir/src/lib.rs"
  local testlog="$LOG/$name-test.log"
  local transcript="$LOG/$name-turns.log"
  : >"$transcript"

  step "problem $name — scaffolding at $dir"
  mkdir -p "$dir"
  case "$name" in
    lru) write_lru_scaffold "$dir" ;;
    fifo) write_fifo_scaffold "$dir" ;;
    *) echo "unknown problem $name"; return 1 ;;
  esac

  run_tests "$dir" "$testlog" || true
  if grep -q "test result: ok" "$testlog"; then
    step "problem $name already passes (unexpected); skipping"
    return 0
  fi

  local max_hops=$((MAX_CYCLES * ${#AGENTS[@]}))
  local hop=0
  local agent="${AGENTS[0]}"
  local last_share=""
  while [ "$hop" -lt "$max_hops" ]; do
    hop=$((hop + 1))
    local turn_id="$name-h${hop}-${agent}"
    local prompt_file="$LOG/${turn_id}.prompt"
    local raw_file="$LOG/${turn_id}.raw"
    local apply_note="$LOG/${turn_id}.apply"
    local before="$LOG/${turn_id}.before.rs"
    cp "$src" "$before"
    build_prompt "$goal" "$src" "$testlog" "$agent" "$hop" "$last_share" >"$prompt_file"

    step "problem $name — hop $hop / $max_hops → $agent (max 2 lines; agent picks next)"
    env SHADI_AGENT_ID=avatar "$AB" delegate "$(cat "$prompt_file")" \
      --to "$agent" --agent-id avatar --endpoint "$SLIM_ENDPOINT" \
      >"$raw_file" 2>&1 || true
    extract_response <"$raw_file" >"$LOG/${turn_id}.reply"

    if grep -q "agentbridge error:" "$LOG/${turn_id}.reply"; then
      echo "--- $turn_id ---" >>"$transcript"
      echo "DELEGATE FAILED" >>"$transcript"
      strip <"$LOG/${turn_id}.reply" >>"$transcript"
      echo >>"$transcript"
      step "  $agent: delegate failed (see $LOG/${turn_id}.reply)"
      agent="$(fallback_next "$agent")"
      continue
    fi

    python3 "$APPLY" "$src" <"$LOG/${turn_id}.reply" >"$src.next" 2>"$apply_note" || {
      echo "apply failed" >"$apply_note"
      cp "$src" "$src.next"
    }
    mv "$src.next" "$src"
    echo "--- $turn_id ---" >>"$transcript"
    echo "apply: $(cat "$apply_note")" >>"$transcript"
    if ! cmp -s "$before" "$src"; then
      echo "diff:" >>"$transcript"
      diff -u "$before" "$src" | sed 's/^/  /' >>"$transcript" || true
    else
      echo "file unchanged" >>"$transcript"
    fi

    local chosen
    chosen="$(python3 "$APPLY" --next <"$LOG/${turn_id}.reply" || true)"
    local next=""
    local route="fallback"
    if [ "$chosen" = "DONE" ]; then
      route="DONE"
    elif valid_peer "$chosen" && [ "$chosen" != "$agent" ]; then
      next="$chosen"
      route="chose"
    fi
    if [ -z "$next" ]; then
      next="$(fallback_next "$agent")"
      [ "$route" = "DONE" ] || route="fallback"
    fi
    if [ "$route" = "chose" ]; then
      echo "next: $next (chose; reply=$chosen; listener shared turn over A2A)" >>"$transcript"
    else
      echo "next: $next ($route${chosen:+; reply=$chosen}; no A2A share)" >>"$transcript"
    fi
    last_share="$LOG/${turn_id}.reply"
    echo >>"$transcript"
    step "  $agent: $(cat "$apply_note"); next $next ($route)"

    run_tests "$dir" "$testlog" || true
    if grep -q "test result: ok" "$testlog"; then
      step "problem $name SOLVED after hop $hop ($agent)"
      echo "SOLVED $name after $turn_id" >>"$transcript"
      return 0
    fi

    # NEXT was already A2A-dispatched by the finishing listener (see
    # AGENTBRIDGE_A2A_FORWARD). Avatar only follows that choice for the
    # next coding delegate after apply/test.
    agent="$next"
  done
  step "problem $name — not solved after $max_hops hops"
  echo "UNSOLVED $name after $max_hops hops" >>"$transcript"
  return 1
}

GOALS_LRU="Implement Lru<K, V> so every unit test passes. items[0] is LRU; the last element is MRU. Scan the Vec only — no HashMap, BTreeMap, HashSet, BTreeSet, VecDeque, or LinkedList. get and put need more than two lines; leave remaining stubs for the next peer."
GOALS_FIFO="Implement Fifo<T> (new/push/pop/len/is_empty) as a real FIFO so every unit test passes."

STATUS=0
case "$PROBLEM" in
  lru) run_problem lru "$GOALS_LRU" || STATUS=1 ;;
  fifo) run_problem fifo "$GOALS_FIFO" || STATUS=1 ;;
  both)
    run_problem lru "$GOALS_LRU" || STATUS=1
    run_problem fifo "$GOALS_FIFO" || STATUS=1
    ;;
  *) echo "PROBLEM must be lru, fifo, or both"; STATUS=2 ;;
esac

for p in "${REGISTER_PIDS[@]}"; do kill -INT "$p" 2>/dev/null; wait "$p" 2>/dev/null; done
if [ -n "$NODE_PID" ]; then
  kill "$NODE_PID" 2>/dev/null
  wait "$NODE_PID" 2>/dev/null
fi

echo
echo "================ local listeners ================"
strip <"$LOG/list-local.log"
for name in lru fifo; do
  [ -f "$LOG/$name-turns.log" ] || continue
  echo
  echo "================ $name turns ================"
  cat "$LOG/$name-turns.log"
  echo
  echo "================ $name src/lib.rs (final) ================"
  [ -f "$WS/$name/src/lib.rs" ] && cat "$WS/$name/src/lib.rs"
  echo
  echo "================ $name cargo test (last) ================"
  if [ -f "$LOG/$name-test.log" ]; then
    strip <"$LOG/$name-test.log" | tail -n 20
  fi
done
echo
echo "logs: $LOG"
exit "$STATUS"
