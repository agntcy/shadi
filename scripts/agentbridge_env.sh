#!/usr/bin/env bash
# Shared environment for all agentbridge demo scripts.
# Sourced by each shell script — values here OVERRIDE any existing env vars.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERT_DIR="${ROOT_DIR}/.tmp/shadi-slim-mtls"

export SLIM_ENDPOINT="127.0.0.1:47357"
export SLIM_SHARED_SECRET="my_shared_secret_for_testing_purposes_only"
export SLIM_TLS_CERT="${CERT_DIR}/client-avatar.crt"
export SLIM_TLS_KEY="${CERT_DIR}/client-avatar.key"
export SLIM_TLS_CA="${CERT_DIR}/ca.crt"

export LOG_DIR="${ROOT_DIR}/.tmp/agentbridge-logs"
mkdir -p "${LOG_DIR}"
