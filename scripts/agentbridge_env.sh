#!/usr/bin/env bash
# Shared environment for all agentbridge demo scripts.
# Sourced by each shell script. Uses DID admission (same contract as
# docs/content/demos/demo-env.sh). Shared secrets are not accepted by
# register / delegate / coordinate.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export SHADI_TMP_DIR="${SHADI_TMP_DIR:-${ROOT_DIR}/.tmp}"
mkdir -p "${SHADI_TMP_DIR}"
export SLIM_ENDPOINT="${SLIM_ENDPOINT:-127.0.0.1:47357}"

# shellcheck source=../docs/content/demos/demo-env.sh
source "${ROOT_DIR}/docs/content/demos/demo-env.sh"

export LOG_DIR="${ROOT_DIR}/.tmp/agentbridge-logs"
mkdir -p "${LOG_DIR}"

SHADICTL="${ROOT_DIR}/target/debug/shadictl"
