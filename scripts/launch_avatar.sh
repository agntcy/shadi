#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${SHADI_TMP_DIR:="${ROOT_DIR}/.tmp"}"
: "${SHADI_AGENT_ID:="avatar-1"}"
: "${SHADI_OPERATOR_PRESENTATION:="local-operator"}"
: "${SHADI_SECOPS_CONFIG:="${SHADI_TMP_DIR}/secops-a.toml"}"
: "${SHADI_POLICY_PATH:="${ROOT_DIR}/policies/demo/avatar.json"}"
: "${SHADI_PYTHON:="${ROOT_DIR}/.venv/bin/python"}"

export SHADI_TMP_DIR
export SHADI_AGENT_ID
export SHADI_OPERATOR_PRESENTATION
export SHADI_SECOPS_CONFIG
export SHADI_POLICY_PATH
export SHADI_PYTHON

# Optional: 1Password backend
if [[ -n "${SHADI_SECRET_BACKEND:-}" ]]; then
	export SHADI_SECRET_BACKEND
fi
if [[ -n "${SHADI_OP_VAULT:-}" ]]; then
	export SHADI_OP_VAULT
fi
if [[ -n "${SHADI_OP_ACCOUNT:-}" ]]; then
	export SHADI_OP_ACCOUNT
fi

: "${SLIM_TLS_CERT:="${SHADI_TMP_DIR}/shadi-slim-mtls/client-avatar.crt"}"
: "${SLIM_TLS_KEY:="${SHADI_TMP_DIR}/shadi-slim-mtls/client-avatar.key"}"
: "${SLIM_TLS_CA:="${SHADI_TMP_DIR}/shadi-slim-mtls/ca.crt"}"

export SLIM_TLS_CERT
export SLIM_TLS_KEY
export SLIM_TLS_CA

cd "${ROOT_DIR}"
uv run --no-project --python "${SHADI_PYTHON}" "${ROOT_DIR}/tools/run_sandboxed_agent.py" \
	--policy "${SHADI_POLICY_PATH}" \
	-- "${SHADI_PYTHON}" "${ROOT_DIR}/agents/avatar/adk_agent/run_shadi_memory.py"
