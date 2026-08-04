#!/usr/bin/env bash
# End-to-end harness for the SHADI Desktop room admin surface
# (agntcy/shadi#118, #135, #138).
#
# Stands up a real SLIM node with DID auth and mTLS, derives a moderator and two
# agent identities (claude-code, codex) from a throwaway seed, starts the two
# agents listening for an invite, and runs the desktop crate's live test as the
# moderator: create a room, invite both, read the roster, reload after restart.
#
#   bash docs/content/demos/desktop-room-e2e.sh
#
# Everything lands in a scratch dir that is removed on exit. The seed is
# generated per run and is not any real key — SHADI derives agent DIDs from a
# human *secret* (HKDF, salt "shadi-agent-derive"), so a dedicated seed keeps
# long-term keys out of a throwaway test. SSH keys are not a supported source;
# `did-from-github` fetches a GPG *public* key, which cannot derive agents.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
cd "$REPO_ROOT"

E2E="${SHADI_E2E_DIR:-/tmp/shadi-desktop-room-e2e}"
mkdir -p "$E2E"
# Resolve to the real path: macOS /tmp is a symlink to /private/tmp, and a
# Seatbelt subpath rule generated for the canonical form does not match a path
# reached through the symlink.
E2E="$(cd "$E2E" && pwd -P)"

ROOM="agntcy/shadi/dev-room"
AGENTS=(claude-code codex)
PIDS=()

cleanup() {
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  [ -n "${SHADI_E2E_KEEP:-}" ] || rm -rf "$E2E"
}
trap cleanup EXIT

echo "==> scratch dir $E2E"

echo "==> building shadictl"
cargo build -q -p agntcy-shadi-cli --bin shadictl

echo "==> generating mTLS material"
bash tools/generate_slim_mtls_certs.sh "$E2E/shadi-slim-mtls" >"$E2E/certs.log" 2>&1

echo "==> deriving identities from a throwaway seed"
umask 077
# No trailing newline: the file bytes must equal the env value exactly, or
# derive-agent-identity and did_auth_from_env produce *different* DIDs and the
# allow-list silently fails to match.
printf %s "$(openssl rand -hex 32)" >"$E2E/human-seed.txt"
target/debug/shadictl derive-agent-identity --source seed --in "$E2E/human-seed.txt" \
  --name avatar --name "${AGENTS[0]}" --name "${AGENTS[1]}" \
  --out-dir "$E2E/identities" >"$E2E/derive.log" 2>&1

did_of() {
  python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['id'])" \
    "$E2E/identities/$1.did.json"
}
AVATAR_DID="$(did_of avatar)"
DIDS="$AVATAR_DID"
for a in "${AGENTS[@]}"; do DIDS="$DIDS,$(did_of "$a")"; done

export SHADI_SLIM_AUTH=did
export SLIM_HUMAN_SEED="$(cat "$E2E/human-seed.txt")"
export SHADI_TMP_DIR="$E2E"
export SLIM_ENDPOINT="${SLIM_ENDPOINT:-127.0.0.1:47610}"
export SLIM_TLS_CERT="$E2E/shadi-slim-mtls/client-avatar.crt"
export SLIM_TLS_KEY="$E2E/shadi-slim-mtls/client-avatar.key"
export SLIM_TLS_CA="$E2E/shadi-slim-mtls/ca.crt"
export SLIM_MEMBER_DIDS="$DIDS"
echo "    moderator $AVATAR_DID"

echo "==> starting SLIM node on $SLIM_ENDPOINT"
SHADI_AGENT_ID=avatar target/debug/shadictl slim start-node >"$E2E/node.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 30); do
  grep -q 'dataplane server started' "$E2E/node.log" 2>/dev/null && break
  sleep 1
done
grep -q 'dataplane server started' "$E2E/node.log" || { echo "node failed:"; cat "$E2E/node.log"; exit 1; }

echo "==> running the desktop room test as moderator"
# The test creates the room, then waits ~12s before inviting, which is the
# window the joiners below use to reach listen_for_session.
(
  cd apps/shadi_desktop/src-tauri
  SHADI_AGENT_ID=avatar \
  SHADI_E2E_ROOM="$ROOM" \
  SHADI_E2E_MEMBERS="agntcy/shadi/${AGENTS[0]},agntcy/shadi/${AGENTS[1]}" \
    cargo test --quiet live_moderator_creates_room_invites_two_agents_and_sees_the_roster \
      -- --ignored --nocapture
) >"$E2E/desktop-test.log" 2>&1 &
TEST_PID=$!

sleep 5
echo "==> starting agent joiners"
for a in "${AGENTS[@]}"; do
  # Keep stdin open after joining: exiting deletes the group session and breaks
  # the moderator's next invite.
  ( printf '/slim join %s --timeout 120\n' "$ROOM"; sleep 120 ) \
    | SHADI_AGENT_ID="$a" target/debug/shadictl shell >"$E2E/join-$a.log" 2>&1 &
  PIDS+=($!)
done

set +e
wait "$TEST_PID"
TEST_RC=$?
set -e

echo
echo "==> agent join results"
for a in "${AGENTS[@]}"; do
  printf '  %-13s ' "$a"
  grep -m1 'joined group session' "$E2E/join-$a.log" 2>/dev/null \
    || grep -m1 -iE 'error|timed out' "$E2E/join-$a.log" 2>/dev/null \
    || echo "(no result)"
done

echo
echo "==> desktop test output"
grep -vE '^\s*$' "$E2E/desktop-test.log" | tail -25

echo
if [ "$TEST_RC" -eq 0 ]; then
  echo "PASS — moderator created the room, both agents were invited and appeared"
  echo "       in the roster, and the roster survived a simulated restart."
else
  echo "FAIL — see $E2E (re-run with SHADI_E2E_KEEP=1 to keep the scratch dir)"
fi
exit "$TEST_RC"
