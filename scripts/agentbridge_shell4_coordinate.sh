#!/usr/bin/env bash
# Shell 4 — Coordinate Copilot and Codex over SLIM.
# Run after Shells 2 and 3 both show:
#   [agentbridge] ready — listening on agntcy/shadi/<agent>-a2a
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=agentbridge_env.sh
source "${SCRIPT_DIR}/agentbridge_env.sh"

ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOG_FILE="${LOG_DIR}/coordinator.log"
ARTIFACT="${LOG_DIR}/winning_artifact.rs"
: > "${LOG_FILE}"

GOAL="${1:-implement a function that returns the nth Fibonacci number in Rust}"

echo "Coordinating Copilot + Codex over SLIM ..."
echo "Endpoint : ${SLIM_ENDPOINT}"
echo "Goal     : ${GOAL}"
echo "Log      : ${LOG_FILE}"
echo "Artifact : ${ARTIFACT}"
echo ""

cd "${ROOT_DIR}"
cargo run -p agntcy-agentbridge-cli -- coordinate \
  --goal "${GOAL}" \
  --agents slim:copilot,slim:codex \
  --quorum 1 \
  --max-rounds 2 \
  --output "${ARTIFACT}" \
  --slim-endpoint "${SLIM_ENDPOINT}" \
  --slim-shared-secret "${SLIM_SHARED_SECRET}" \
  2>&1 | tee "${LOG_FILE}"

echo ""
echo "=== Logs ==="
ls -lh "${LOG_DIR}"
