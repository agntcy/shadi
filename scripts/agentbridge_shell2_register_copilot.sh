#!/usr/bin/env bash
# Shell 2 — Register Copilot as a SLIM A2A service.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=agentbridge_env.sh
source "${SCRIPT_DIR}/agentbridge_env.sh"

ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOG_FILE="${LOG_DIR}/copilot.log"
: > "${LOG_FILE}"

if ! command -v copilot &>/dev/null; then
  echo "ERROR: 'copilot' CLI not found in PATH."
  exit 1
fi

echo "Registering Copilot on ${SLIM_ENDPOINT} as agntcy/shadi/copilot-a2a ..."
echo "Log: ${LOG_FILE}"

cd "${ROOT_DIR}"
exec cargo run -p agntcy-agentbridge-cli -- register \
  --tool copilot \
  --slim-endpoint "${SLIM_ENDPOINT}" \
  --slim-shared-secret "${SLIM_SHARED_SECRET}" \
  2>&1 | tee "${LOG_FILE}"
