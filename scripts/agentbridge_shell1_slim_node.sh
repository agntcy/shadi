#!/usr/bin/env bash
# Shell 1 — Start the SLIM node.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=agentbridge_env.sh
source "${SCRIPT_DIR}/agentbridge_env.sh"

ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CERT_DIR="${ROOT_DIR}/.tmp/shadi-slim-mtls"
CONFIG_FILE="${ROOT_DIR}/.tmp/slim-agentbridge.yaml"
LOG_FILE="${LOG_DIR}/slim-node.log"
: > "${LOG_FILE}"

if [[ ! -f "${CERT_DIR}/server.crt" ]]; then
  echo "ERROR: server cert not found at ${CERT_DIR}/server.crt"
  echo "Run tools/generate_slim_mtls_certs.sh first."
  exit 1
fi

cat > "${CONFIG_FILE}" << YAML
services:
  slim/0:
    dataplane:
      servers:
        - endpoint: "${SLIM_ENDPOINT}"
          tls:
            source:
              type: file
              cert: "${CERT_DIR}/server.crt"
              key: "${CERT_DIR}/server.key"
            include_system_ca_certs_pool: false
YAML

echo "Starting SLIM node on ${SLIM_ENDPOINT} ..."
echo "Log: ${LOG_FILE}"
exec slimctl slim start -c "${CONFIG_FILE}" 2>&1 | tee "${LOG_FILE}"
