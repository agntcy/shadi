#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${SHADI_TMP_DIR:="${ROOT_DIR}/.tmp"}"
: "${SHADI_AGENT_ID:="secops-a"}"
: "${SHADI_OPERATOR_PRESENTATION:="local-operator"}"

export SHADI_TMP_DIR
export SHADI_AGENT_ID
export SHADI_OPERATOR_PRESENTATION

cd "${ROOT_DIR}"
uv run agents/secops/import_secops_secrets.py
