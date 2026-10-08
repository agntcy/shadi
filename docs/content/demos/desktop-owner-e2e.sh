#!/usr/bin/env bash
# End-to-end harness for the SHADI Desktop channel owner (agntcy/shadi#421).
#
# Stands up a real SLIM node with DID auth and mTLS and derives a moderator,
# its owner key and two agents (claude-code, codex) from a throwaway seed. The
# desktop crate's live test creates a room as moderator and serves the owner
# service with an allow-all policy. claude-code waits to be invited, and codex
# asks the owner over A2A (`agentbridge request-invite`) to let claude-code in.
# The test passes once claude-code is on the room's roster.
#
#   bash docs/content/demos/desktop-owner-e2e.sh
#
# Everything lands in a scratch dir that is removed on exit (keep it with
# SHADI_E2E_KEEP=1). See desktop-room-e2e.sh for why the seed is throwaway.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
cd "$REPO_ROOT"

E2E="${SHADI_E2E_DIR:-/tmp/shadi-desktop-owner-e2e}"
mkdir -p "$E2E"
E2E="$(cd "$E2E" && pwd -P)"

ROOM="agntcy/shadi/owner-room"
INVITEE=claude-code
REQUESTER=codex
PIDS=()

cleanup() {
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  [ -n "${SHADI_E2E_KEEP:-}" ] || rm -rf "$E2E"
}
trap cleanup EXIT

echo "==> scratch dir $E2E"

echo "==> building shadictl and agentbridge"
cargo build -q -p agntcy-shadi-cli --bin shadictl
cargo build -q -p agntcy-agentbridge-cli --bin agentbridge

echo "==> generating mTLS material"
bash tools/generate_slim_mtls_certs.sh "$E2E/shadi-slim-mtls" >"$E2E/certs.log" 2>&1

echo "==> deriving identities from a throwaway seed"
umask 077
printf %s "$(openssl rand -hex 32)" >"$E2E/human-seed.txt"
target/debug/shadictl derive-agent-identity --source seed --in "$E2E/human-seed.txt" \
  --name avatar --name owner --name "$INVITEE" --name "$REQUESTER" \
  --out-dir "$E2E/identities" >"$E2E/derive.log" 2>&1

did_of() {
  python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['id'])" \
    "$E2E/identities/$1.did.json"
}
INVITEE_DID="$(did_of "$INVITEE")"
DIDS="$(did_of avatar),$(did_of owner),$INVITEE_DID,$(did_of "$REQUESTER")"

export SHADI_SLIM_AUTH=did
export SLIM_HUMAN_SEED="$(cat "$E2E/human-seed.txt")"
export SHADI_TMP_DIR="$E2E"
export SLIM_ENDPOINT="${SLIM_ENDPOINT:-127.0.0.1:47611}"
export SLIM_TLS_CERT="$E2E/shadi-slim-mtls/client-avatar.crt"
export SLIM_TLS_KEY="$E2E/shadi-slim-mtls/client-avatar.key"
export SLIM_TLS_CA="$E2E/shadi-slim-mtls/ca.crt"
export SLIM_MEMBER_DIDS="$DIDS"
echo "    owner $(did_of owner)"

echo "==> starting SLIM node on $SLIM_ENDPOINT"
SHADI_AGENT_ID=avatar target/debug/shadictl slim start-node >"$E2E/node.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 30); do
  grep -q 'dataplane server started' "$E2E/node.log" 2>/dev/null && break
  sleep 1
done
grep -q 'dataplane server started' "$E2E/node.log" || { echo "node failed:"; cat "$E2E/node.log"; exit 1; }

echo "==> running the desktop owner test as moderator"
(
  cd apps/shadi_desktop/src-tauri
  SHADI_AGENT_ID=avatar \
  SHADI_E2E_ROOM="$ROOM" \
  SHADI_E2E_INVITEE="agntcy/shadi/$INVITEE" \
    cargo test --quiet live_owner_grants_an_agents_request_and_invites_the_invitee \
      -- --ignored --nocapture
) >"$E2E/desktop-test.log" 2>&1 &
TEST_PID=$!

echo "==> $INVITEE waits to be invited"
# Keep stdin open after joining: exiting deletes the group session.
( printf '/slim join %s --timeout 150\n' "$ROOM"; sleep 150 ) \
  | SHADI_AGENT_ID="$INVITEE" target/debug/shadictl shell >"$E2E/join-$INVITEE.log" 2>&1 &
PIDS+=($!)

for _ in $(seq 1 120); do
  grep -q 'owner service ready' "$E2E/desktop-test.log" 2>/dev/null && break
  kill -0 "$TEST_PID" 2>/dev/null || break
  sleep 1
done
grep -q 'owner service ready' "$E2E/desktop-test.log" || {
  echo "owner service never came up:"; tail -20 "$E2E/desktop-test.log"; exit 1;
}
sleep 2

echo "==> $REQUESTER asks the owner to let $INVITEE in"
set +e
SHADI_AGENT_ID="$REQUESTER" target/debug/agentbridge request-invite \
  --owner agntcy/shadi/avatar --channel "$ROOM" \
  --invitee-name "agntcy/shadi/$INVITEE" --invitee-did "$INVITEE_DID" \
  --agent-id "$REQUESTER" --endpoint "$SLIM_ENDPOINT" >"$E2E/request.log" 2>&1
REQUEST_RC=$?
wait "$TEST_PID"
TEST_RC=$?
set -e

echo
echo "==> owner's answer to $REQUESTER"
grep -vE '^\s*$|WARN' "$E2E/request.log" | tail -3
echo
echo "==> $INVITEE join result"
grep -m1 'joined group session' "$E2E/join-$INVITEE.log" 2>/dev/null \
  || grep -m1 -iE 'error|timed out' "$E2E/join-$INVITEE.log" 2>/dev/null \
  || echo "(no result)"
echo
echo "==> desktop test output"
grep -vE '^\s*$' "$E2E/desktop-test.log" | tail -15

echo
if [ "$TEST_RC" -eq 0 ] && [ "$REQUEST_RC" -eq 0 ]; then
  echo "PASS — the owner granted $REQUESTER's request and $INVITEE joined the room."
else
  echo "FAIL — see $E2E (re-run with SHADI_E2E_KEEP=1 to keep the scratch dir)"
  exit 1
fi
