#!/usr/bin/env bash
# Shell 5 — Register Cursor Agent as a SLIM A2A service (DID + sandbox).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=agentbridge_env.sh
source "${SCRIPT_DIR}/agentbridge_env.sh"

ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOG_FILE="${LOG_DIR}/cursor-agent.log"
: > "${LOG_FILE}"

if [[ ! -x "${SHADICTL}" ]]; then
  echo "ERROR: ${SHADICTL} not found. Run: cargo build -p agntcy-shadi-cli"
  exit 1
fi
if ! command -v cursor-agent &>/dev/null; then
  echo "ERROR: 'cursor-agent' CLI not found in PATH."
  exit 1
fi

echo "Registering Cursor Agent on ${SLIM_ENDPOINT} as agntcy/shadi/cursor-agent-a2a ..."
echo "Log: ${LOG_FILE}"

cd "${ROOT_DIR}"
export SHADI_AGENT_ID=cursor-agent
exec "${SHADICTL}" --net-block --net-allow "${SLIM_ENDPOINT}" \
  --read "${SHADI_TMP_DIR}" --write "${SHADI_TMP_DIR}" \
  --read "${HOME}" --read /opt/homebrew -- \
  cargo run -p agntcy-agentbridge-cli -- register \
  --tool cursor-agent \
  --slim-endpoint "${SLIM_ENDPOINT}" \
  2>&1 | tee "${LOG_FILE}"
