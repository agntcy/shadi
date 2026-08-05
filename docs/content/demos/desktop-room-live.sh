#!/usr/bin/env bash
# Launch SHADI Desktop against a live SLIM room, for clicking through by hand
# (agntcy/shadi#118, #135, #138).
#
#   bash docs/content/demos/desktop-room-live.sh
#
# Stands up everything the Rooms panel needs — a SLIM node, mTLS material, DID
# auth, and two agents (claude-code, codex) waiting to be invited — then starts
# the app with that environment. Without it the panel cannot work: "Start node"
# reports missing mTLS material because SHADI_TMP_DIR is unset.
#
# Then, in the app:
#   1. Rooms tab -> Start node        (attaches to the node this script started)
#   2. New room channel: agntcy/shadi/dev-room  -> Create room
#   3. Invite  agntcy/shadi/claude-code   then  agntcy/shadi/codex
#   4. The roster shows both, tagged agent
#   5. Quit and re-run: the room comes back "not connected" with its roster
#
# Ctrl-C tears the whole thing down. The seed is generated per run and is not
# any real key: SHADI derives agent DIDs from a human *secret* (HKDF, salt
# "shadi-agent-derive"). SSH keys are not a supported source, and
# `did-from-github` fetches a GPG *public* key, which cannot derive agents.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
cd "$REPO_ROOT"

E2E="${SHADI_LIVE_DIR:-/tmp/shadi-desktop-room-live}"
mkdir -p "$E2E"
# macOS /tmp is a symlink to /private/tmp; resolve it so sandbox --read rules
# and the paths actually opened agree.
E2E="$(cd "$E2E" && pwd -P)"

ROOM="agntcy/shadi/dev-room"
AGENTS=(claude-code codex)
PIDS=()

cleanup() {
  echo
  echo "==> shutting down"
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  # `tauri dev` spawns vite as a child; killing only the parent orphans it and
  # it keeps holding port 1420, breaking the next run.
  lsof -tnP -iTCP:1420 -sTCP:LISTEN 2>/dev/null | xargs kill 2>/dev/null || true
  wait 2>/dev/null || true
  [ -n "${SHADI_LIVE_KEEP:-}" ] || rm -rf "$E2E"
}
trap cleanup EXIT INT TERM

echo "==> scratch dir $E2E"

# Vite's dev port. A `tauri dev` killed at the parent leaves its vite child
# holding 1420, and the next run dies with "Port 1420 is already in use" — so
# say what is holding it rather than leaving the user to hunt.
if lsof -nP -iTCP:1420 -sTCP:LISTEN >/dev/null 2>&1; then
  echo "    port 1420 is already in use by:"
  lsof -nP -iTCP:1420 -sTCP:LISTEN | tail -n +2 | sed 's/^/      /'
  if [ -n "${SHADI_LIVE_FREE_PORT:-}" ]; then
    echo "    SHADI_LIVE_FREE_PORT set — terminating it"
    lsof -tnP -iTCP:1420 -sTCP:LISTEN | xargs kill 2>/dev/null || true
    sleep 2
  else
    echo
    echo "    Usually a leftover vite from an earlier 'tauri dev'. Free it with:"
    echo "      lsof -tnP -iTCP:1420 -sTCP:LISTEN | xargs kill"
    echo "    or re-run with SHADI_LIVE_FREE_PORT=1 to do that automatically."
    exit 1
  fi
fi

cargo build -q -p agntcy-shadi-cli --bin shadictl

echo "==> generating mTLS material"
bash tools/generate_slim_mtls_certs.sh "$E2E/shadi-slim-mtls" >"$E2E/certs.log" 2>&1

echo "==> deriving identities from a throwaway seed"
umask 077
# No trailing newline: the file bytes must equal the env value exactly, or
# derive-agent-identity and did_auth_from_env yield *different* DIDs and the
# allow-list silently fails to match.
printf %s "$(openssl rand -hex 32)" >"$E2E/human-seed.txt"
target/debug/shadictl derive-agent-identity --source seed --in "$E2E/human-seed.txt" \
  --name avatar --name "${AGENTS[0]}" --name "${AGENTS[1]}" \
  --out-dir "$E2E/identities" >"$E2E/derive.log" 2>&1

did_of() {
  python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['id'])" \
    "$E2E/identities/$1.did.json"
}
DIDS="$(did_of avatar)"
for a in "${AGENTS[@]}"; do DIDS="$DIDS,$(did_of "$a")"; done

export SHADI_SLIM_AUTH=did
export SLIM_HUMAN_SEED="$(cat "$E2E/human-seed.txt")"
export SHADI_TMP_DIR="$E2E"
export SLIM_ENDPOINT="${SLIM_ENDPOINT:-127.0.0.1:47610}"
export SLIM_TLS_CERT="$E2E/shadi-slim-mtls/client-avatar.crt"
export SLIM_TLS_KEY="$E2E/shadi-slim-mtls/client-avatar.key"
export SLIM_TLS_CA="$E2E/shadi-slim-mtls/ca.crt"
export SLIM_MEMBER_DIDS="$DIDS"
export SHADI_AGENT_ID=avatar

echo "==> starting SLIM node on $SLIM_ENDPOINT"
target/debug/shadictl slim start-node >"$E2E/node.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 30); do
  grep -q 'dataplane server started' "$E2E/node.log" 2>/dev/null && break
  sleep 1
done
grep -q 'dataplane server started' "$E2E/node.log" \
  || { echo "node failed to start:"; cat "$E2E/node.log"; exit 1; }

echo "==> starting agents waiting for an invite to $ROOM"
for a in "${AGENTS[@]}"; do
  # Keep stdin open after joining: exiting deletes the shared group session and
  # breaks the moderator's next invite.
  ( printf '/slim join %s --timeout 1800\n' "$ROOM"; sleep 1800 ) \
    | SHADI_AGENT_ID="$a" target/debug/shadictl shell >"$E2E/join-$a.log" 2>&1 &
  PIDS+=($!)
  echo "    $a  -> $E2E/join-$a.log"
done

cat <<EOF

==> launching SHADI Desktop as moderator 'avatar'

  In the app (Rooms tab):
    1. Start node
    2. New room channel: $ROOM   -> Create room
    3. Invite  agntcy/shadi/${AGENTS[0]}   then  agntcy/shadi/${AGENTS[1]}
    4. Roster shows both, tagged 'agent'

  Note: the two agents above are already waiting, so invite them without
  restarting them — a participant that exits tears down the group session.

  Ctrl-C here tears everything down.

EOF

cd apps/shadi_desktop
pnpm tauri dev
