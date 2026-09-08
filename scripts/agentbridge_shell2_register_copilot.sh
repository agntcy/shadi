#!/usr/bin/env bash
# Shell 2 — Register Copilot as a SLIM A2A service (DID + sandbox).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=agentbridge_env.sh
source "${SCRIPT_DIR}/agentbridge_env.sh"

ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOG_FILE="${LOG_DIR}/copilot.log"
: > "${LOG_FILE}"

if [[ ! -x "${SHADICTL}" ]]; then
  echo "ERROR: ${SHADICTL} not found. Run: cargo build -p agntcy-shadi-cli"
  exit 1
fi
if ! command -v copilot &>/dev/null; then
  echo "ERROR: 'copilot' CLI not found in PATH."
  exit 1
fi

echo "Registering Copilot on ${SLIM_ENDPOINT} as agntcy/shadi/copilot-a2a ..."
echo "Log: ${LOG_FILE}"

cd "${ROOT_DIR}"
export SHADI_AGENT_ID=copilot
exec "${SHADICTL}" --net-block --net-allow "${SLIM_ENDPOINT}" \
  --read "${SHADI_TMP_DIR}" --write "${SHADI_TMP_DIR}" \
  --read "${HOME}" --read /opt/homebrew -- \
  cargo run -p agntcy-agentbridge-cli -- register \
  --tool copilot \
  --slim-endpoint "${SLIM_ENDPOINT}" \
  2>&1 | tee "${LOG_FILE}"
