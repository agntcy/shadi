#!/usr/bin/env bash
# The SLIM node every agent connects to. Stays in the foreground.
set -euo pipefail
cd "$(dirname "$0")"
source ./env.sh
export SHADI_AGENT_ID=coordinator
exec "$SHADICTL" slim start-node
