#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${SHADI_TMP_DIR:="${ROOT_DIR}/.tmp"}"
: "${SLIM_ENDPOINT:="127.0.0.1:47357"}"

CONFIG_PATH="${SHADI_TMP_DIR}/shadi-slim-mtls/server-config.yaml"

slimctl slim start --config "${CONFIG_PATH}"
