#!/usr/bin/env bash
# End-to-end harness for Desktop rooms owned through a SLIM channel manager
# (agntcy/shadi#442).
#
# Stands up a SLIM node with DID auth and mTLS and derives the moderator, the
# owner key, two agents (claude-code, codex) and the channel manager's own key
# from a throwaway seed. The desktop crate's live test starts the channel
# manager, serves the owner service, and creates a room through the API as its
# owner. codex then asks the channel manager to add claude-code without a
# grant; the channel manager asks the owner, whose rules grant it, and
# claude-code joins. A request the rules block is refused.
#
#   bash docs/content/demos/desktop-channel-manager-e2e.sh
#
# Needs the channel manager 3.2 or later, which has the did:key identity:
#   cargo install agntcy-slim-channel-manager --locked
# Set SHADI_E2E_CHANNEL_MANAGER to use another binary, and SHADI_E2E_CM_RUST_LOG
# for its logs (e.g. `info,slim_session=debug`). The channel manager's
# trusted_keys must list its own did:key as well as its peers': MLS checks the
# group creator's own credential. Everything lands in a scratch dir that is
# removed on exit (keep it with SHADI_E2E_KEEP=1).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
cd "$REPO_ROOT"

E2E="${SHADI_E2E_DIR:-/tmp/shadi-desktop-cm-e2e}"
mkdir -p "$E2E"
E2E="$(cd "$E2E" && pwd -P)"

ROOM="agntcy/shadi/cm-room"
INVITEE=claude-code
CM_BIN="${SHADI_E2E_CHANNEL_MANAGER:-$(command -v channel-manager || true)}"
PIDS=()

cleanup() {
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  [ -n "${SHADI_E2E_KEEP:-}" ] || rm -rf "$E2E"
}
trap cleanup EXIT

[ -x "$CM_BIN" ] || { echo "no channel-manager binary; see the header"; exit 1; }
echo "==> scratch dir $E2E, channel manager $CM_BIN"

echo "==> building shadictl"
cargo build -q -p agntcy-shadi-cli --bin shadictl

echo "==> generating mTLS material"
bash tools/generate_slim_mtls_certs.sh "$E2E/shadi-slim-mtls" >"$E2E/certs.log" 2>&1

echo "==> deriving identities from a throwaway seed"
umask 077
printf %s "$(openssl rand -hex 32)" >"$E2E/human-seed.txt"
target/debug/shadictl derive-agent-identity --source seed --in "$E2E/human-seed.txt" \
  --name avatar --name owner --name "$INVITEE" --name codex --name channel-manager \
  --out-dir "$E2E/identities" --no-store >"$E2E/derive.log" 2>&1

did_of() {
  python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['id'])" \
    "$E2E/identities/$1.did.json"
}
# Everyone trusts the channel manager, which moderates the room and calls the
# owner service.
DIDS="$(did_of avatar),$(did_of owner),$(did_of "$INVITEE"),$(did_of codex),$(did_of channel-manager)"

export SHADI_SLIM_AUTH=did
SLIM_HUMAN_SEED="$(cat "$E2E/human-seed.txt")"
export SLIM_HUMAN_SEED
export SHADI_TMP_DIR="$E2E"
export SLIM_ENDPOINT="${SLIM_ENDPOINT:-127.0.0.1:47621}"
export SLIM_TLS_CERT="$E2E/shadi-slim-mtls/client-avatar.crt"
export SLIM_TLS_KEY="$E2E/shadi-slim-mtls/client-avatar.key"
export SLIM_TLS_CA="$E2E/shadi-slim-mtls/ca.crt"
export SLIM_MEMBER_DIDS="$DIDS"
echo "    channel manager $(did_of channel-manager)"

echo "==> starting SLIM node on $SLIM_ENDPOINT"
SHADI_AGENT_ID=avatar target/debug/shadictl slim start-node >"$E2E/node.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 30); do
  grep -q 'dataplane server started' "$E2E/node.log" 2>/dev/null && break
  sleep 1
done
grep -q 'dataplane server started' "$E2E/node.log" || { echo "node failed:"; cat "$E2E/node.log"; exit 1; }

echo "==> $INVITEE waits to be invited"
# Keep stdin open after joining: exiting deletes the group session.
( printf '/slim join %s --timeout 150\n' "$ROOM"; sleep 150 ) \
  | SHADI_AGENT_ID="$INVITEE" target/debug/shadictl shell >"$E2E/join-$INVITEE.log" 2>&1 &
PIDS+=($!)
sleep 2

echo "==> running the desktop channel-manager test"
set +e
(
  cd apps/shadi_desktop/src-tauri
  SHADI_AGENT_ID=avatar \
  SHADI_E2E_ROOM="$ROOM" \
  SHADI_E2E_CM_API="${SHADI_E2E_CM_API:-127.0.0.1:47622}" \
  SHADI_E2E_CM_CERT="$E2E/shadi-slim-mtls/client-secops-a.crt" \
  SHADI_E2E_CM_KEY="$E2E/shadi-slim-mtls/client-secops-a.key" \
  SHADI_E2E_CM_LOG="$E2E/channel-manager.log" \
  SHADI_E2E_CHANNEL_MANAGER="$CM_BIN" \
    cargo test --quiet live_channel_manager_asks_the_owner_and_adds_who_it_grants \
      -- --ignored --nocapture
) >"$E2E/desktop-test.log" 2>&1
TEST_RC=$?
set -e

echo
echo "==> channel manager"
grep -iE 'identity|error|denied|approval' "$E2E/channel-manager.log" 2>/dev/null | tail -6 || true
echo
echo "==> $INVITEE join result"
grep -m1 'joined group session' "$E2E/join-$INVITEE.log" 2>/dev/null \
  || grep -m1 -iE 'error|timed out' "$E2E/join-$INVITEE.log" 2>/dev/null \
  || echo "(no result)"
echo
echo "==> desktop test output"
grep -vE '^\s*$' "$E2E/desktop-test.log" | grep -vE 'INFO|DEBUG' | tail -15

echo
if [ "$TEST_RC" -eq 0 ]; then
  echo "PASS — the channel manager asked the owner, who granted codex's request for $INVITEE."
else
  echo "FAIL — see $E2E (re-run with SHADI_E2E_KEEP=1 to keep the scratch dir)"
  exit 1
fi
