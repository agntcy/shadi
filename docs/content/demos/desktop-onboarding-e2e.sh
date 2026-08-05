#!/usr/bin/env bash
# Proves the SSH onboarding flow reaches a working room with no environment
# contract (agntcy/shadi#123).
#
#   bash docs/content/demos/desktop-onboarding-e2e.sh
#
# Generates a throwaway SSH key, then runs the desktop crate's bootstrap path:
# derive the human and agent DIDs from that key, generate mTLS material, and
# create a SLIM group — with SHADI_SLIM_AUTH, SLIM_HUMAN_SEED and
# SLIM_MEMBER_DIDS deliberately unset, which is the whole point.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
cd "$REPO_ROOT"

E2E="${SHADI_E2E_DIR:-/tmp/shadi-desktop-onboarding-e2e}"
mkdir -p "$E2E"
E2E="$(cd "$E2E" && pwd -P)"
ENDPOINT="${SLIM_ENDPOINT:-127.0.0.1:47620}"
ROOM="agntcy/shadi/onboarding-room"
PIDS=()

cleanup() {
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  [ -n "${SHADI_E2E_KEEP:-}" ] || rm -rf "$E2E"
}
trap cleanup EXIT

echo "==> scratch dir $E2E"
cargo build -q -p agntcy-shadi-cli --bin shadictl

echo "==> generating a throwaway SSH key (stands in for the user's own)"
umask 077
rm -f "$E2E/id_ed25519" "$E2E/id_ed25519.pub"
ssh-keygen -t ed25519 -N '' -C 'shadi-onboarding-e2e' -f "$E2E/id_ed25519" -q

# Generate mTLS with the app's own rcgen path, so the node under test runs on
# exactly the certificates onboarding mints — not openssl's.
echo "==> generating mTLS material (rcgen, via the app's own code)"
(
  cd apps/shadi_desktop/src-tauri
  SHADI_E2E_DIR="$E2E" cargo test --quiet live_generate_mtls_for_the_harness \
    -- --ignored --nocapture
) >"$E2E/mtls.log" 2>&1 || { echo "mTLS generation failed:"; cat "$E2E/mtls.log"; exit 1; }
grep -q 'generated' "$E2E/mtls.log" && sed -n 's/^\(generated .*\)$/    \1/p' "$E2E/mtls.log" | head -1

echo "==> starting a node on $ENDPOINT"
# The node itself authenticates with mTLS only, so it needs no DID env.
SHADI_TMP_DIR="$E2E" SLIM_ENDPOINT="$ENDPOINT" SHADI_AGENT_ID=avatar \
  target/debug/shadictl slim start-node >"$E2E/node.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 30); do
  grep -q 'dataplane server started' "$E2E/node.log" 2>/dev/null && break
  sleep 1
done
grep -q 'dataplane server started' "$E2E/node.log" \
  || { echo "node failed:"; cat "$E2E/node.log"; exit 1; }

echo "==> running the bootstrap test with no DID environment contract"
set +e
(
  cd apps/shadi_desktop/src-tauri
  env -u SHADI_SLIM_AUTH -u SLIM_HUMAN_SEED -u SLIM_MEMBER_DIDS \
    SHADI_E2E_SSH_KEY="$E2E/id_ed25519" \
    SHADI_E2E_DIR="$E2E" \
    SHADI_E2E_ENDPOINT="$ENDPOINT" \
    SHADI_E2E_ROOM="$ROOM" \
    cargo test --quiet live_bootstrap_creates_a_room_without_env_vars -- --ignored --nocapture
) 2>&1 | tee "$E2E/test.log" | grep -vE '^\s*$' | tail -20
RC=${PIPESTATUS[0]}
set -e

echo
if [ "$RC" -eq 0 ]; then
  echo "PASS — derived the identity from an SSH key, generated mTLS, and created"
  echo "       a room with SHADI_SLIM_AUTH/SLIM_HUMAN_SEED/SLIM_MEMBER_DIDS unset."
else
  echo "FAIL — see $E2E (re-run with SHADI_E2E_KEEP=1 to keep it)"
fi
exit "$RC"
