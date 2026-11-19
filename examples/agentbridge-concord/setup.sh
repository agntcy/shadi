#!/usr/bin/env bash
# One-time setup: the mTLS certificates SLIM and the agents use.
set -euo pipefail
cd "$(dirname "$0")"
source ./env.sh

if [[ -f "$SLIM_TLS_CERT" && -f "$SLIM_TLS_KEY" ]]; then
  echo "Certificates are already in $SHADI_TMP_DIR/shadi-slim-mtls"
else
  bash "$CONCORD_ROOT/tools/generate_slim_mtls_certs.sh" "$SHADI_TMP_DIR/shadi-slim-mtls"
fi
mkdir -p "$CONCORD_EXAMPLE/.run"
echo "Ready. Next: ./start-node.sh in a terminal of its own."
