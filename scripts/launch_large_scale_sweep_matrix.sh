#!/usr/bin/env bash
# Copyright AGNTCY Contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# Submit a matrix of large-scale sweep jobs through mas_job_listener.
#
# Required runtime dependencies: curl, kubectl, python3

LISTENER_URL="${LISTENER_URL:-http://127.0.0.1:38189}"
LISTENER_NAMESPACE="${LISTENER_NAMESPACE:-mas-jobs}"
LISTENER_API_SECRET="${LISTENER_API_SECRET:-mas-job-listener-api}"
LISTENER_API_SECRET_KEY="${LISTENER_API_SECRET_KEY:-submit-api-key}"
EXPERIMENT_SECRET_NAME="${EXPERIMENT_SECRET_NAME:-shadi-mas-experiments-secrets}"
EXPERIMENT_SECRET_KEY="${EXPERIMENT_SECRET_KEY:-SLIM_SHARED_SECRET}"

LLM_MODEL="${LLM_MODEL:-gemma-4-26b-a4b-it-node5-h100}"
LIVE_ENDPOINT="${LIVE_ENDPOINT:-gls-admin:47357}"
PHASE_TIMEOUT_SECONDS="${PHASE_TIMEOUT_SECONDS:-2400}"
READY_TIMEOUT_SECONDS="${READY_TIMEOUT_SECONDS:-90}"
PEER_IDLE_GRACE_SECONDS="${PEER_IDLE_GRACE_SECONDS:-12}"
SLIM_PUBLISH_RETRY_ATTEMPTS="${SLIM_PUBLISH_RETRY_ATTEMPTS:-6}"
SLIM_PUBLISH_RETRY_BACKOFF_MS="${SLIM_PUBLISH_RETRY_BACKOFF_MS:-1200}"
A2A_RETRY_ATTEMPTS="${A2A_RETRY_ATTEMPTS:-6}"
A2A_RETRY_BACKOFF_MS="${A2A_RETRY_BACKOFF_MS:-1200}"
START_LOCAL_NODE="${START_LOCAL_NODE:-0}"

# Matrix format:
#   label=scales_csv;label=scales_csv;...
# Example:
#   MATRIX='mid=2,4,8,12,16;large=20,30,40,50;xlarge=60,80,100'
MATRIX="${MATRIX:-mid=2,4,8,12,16;large=20,30,40,50;xlarge=60,80,100}"
JOB_BASENAME_PREFIX="${JOB_BASENAME_PREFIX:-shadi-mas-sweep-large}"
POLL_ATTEMPTS="${POLL_ATTEMPTS:-40}"
POLL_SLEEP_SECONDS="${POLL_SLEEP_SECONDS:-2}"

DRY_RUN="${DRY_RUN:-0}"
MANIFEST_PATH="${MANIFEST_PATH:-/tmp/shadi_large_sweep_manifest_$(date +%Y%m%d_%H%M%S).tsv}"
ALLOW_LOCAL_LIVE_ENDPOINT="${ALLOW_LOCAL_LIVE_ENDPOINT:-0}"

required_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "ERROR: missing required command: $1" >&2
    exit 1
  fi
}

required_cmd curl
required_cmd kubectl
required_cmd python3

api_key="${LISTENER_API_KEY:-}"
if [[ -z "${api_key}" ]]; then
  api_key="$(kubectl -n "${LISTENER_NAMESPACE}" get secret "${LISTENER_API_SECRET}" -o jsonpath="{.data.${LISTENER_API_SECRET_KEY}}" | base64 -d)"
fi

slim_secret="${SLIM_SHARED_SECRET:-}"
if [[ -z "${slim_secret}" ]]; then
  slim_secret="$(kubectl -n "${LISTENER_NAMESPACE}" get secret "${EXPERIMENT_SECRET_NAME}" -o jsonpath="{.data.${EXPERIMENT_SECRET_KEY}}" | base64 -d)"
fi

if [[ -z "${api_key}" ]]; then
  echo "ERROR: listener API key is empty" >&2
  exit 1
fi
if [[ -z "${slim_secret}" ]]; then
  echo "ERROR: SLIM shared secret is empty" >&2
  exit 1
fi

if [[ "${ALLOW_LOCAL_LIVE_ENDPOINT}" != "1" ]]; then
  case "${LIVE_ENDPOINT}" in
    localhost:*|127.0.0.1:*|[::1]:*)
      echo "ERROR: LIVE_ENDPOINT=${LIVE_ENDPOINT} is local-only and not reachable from cluster jobs." >&2
      echo "Set LIVE_ENDPOINT to a cluster-reachable SLIM endpoint (example: gls-admin:47357)." >&2
      echo "If you intentionally run with a local endpoint, set ALLOW_LOCAL_LIVE_ENDPOINT=1." >&2
      exit 1
      ;;
  esac
fi

echo -e "label\tscales\ttask_id\tstatus\tjob_name" >"${MANIFEST_PATH}"
echo "Manifest: ${MANIFEST_PATH}"

submit_case() {
  local label="$1"
  local scales="$2"
  local basename="${JOB_BASENAME_PREFIX}-${label}"

  local payload
  payload="$(python3 - <<'PY' "${LLM_MODEL}" "${slim_secret}" "${LIVE_ENDPOINT}" "${PHASE_TIMEOUT_SECONDS}" "${READY_TIMEOUT_SECONDS}" "${PEER_IDLE_GRACE_SECONDS}" "${SLIM_PUBLISH_RETRY_ATTEMPTS}" "${SLIM_PUBLISH_RETRY_BACKOFF_MS}" "${A2A_RETRY_ATTEMPTS}" "${A2A_RETRY_BACKOFF_MS}" "${basename}" "${scales}" "${START_LOCAL_NODE}"
import json
import sys

llm_model = sys.argv[1]
slim_secret = sys.argv[2]
live_endpoint = sys.argv[3]
phase_timeout = sys.argv[4]
ready_timeout = sys.argv[5]
peer_grace = sys.argv[6]
slim_retry_attempts = sys.argv[7]
slim_retry_backoff = sys.argv[8]
a2a_retry_attempts = sys.argv[9]
a2a_retry_backoff = sys.argv[10]
basename = sys.argv[11]
scales = sys.argv[12]
start_local_node = sys.argv[13]

payload = {
    "mode": "sweep",
    "llm_model": llm_model,
    "slim_shared_secret": slim_secret,
    "env": {
        "SHADI_LIVE_ENDPOINT": live_endpoint,
        "SHADI_LIVE_PHASE_LISTEN_TIMEOUT_SECONDS": phase_timeout,
        "SHADI_LIVE_READY_TIMEOUT_SECONDS": ready_timeout,
        "SHADI_LIVE_PEER_IDLE_GRACE_SECONDS": peer_grace,
        "SHADI_LIVE_SLIM_PUBLISH_RETRY_ATTEMPTS": slim_retry_attempts,
        "SHADI_LIVE_SLIM_PUBLISH_RETRY_BACKOFF_MS": slim_retry_backoff,
        "SHADI_LIVE_A2A_RETRY_ATTEMPTS": a2a_retry_attempts,
        "SHADI_LIVE_A2A_RETRY_BACKOFF_MS": a2a_retry_backoff,
        "SHADI_LIVE_START_LOCAL_NODE": start_local_node,
        "SHADI_LIVE_SWEEP_SCALES": scales,
        "SHADI_MAS_JOB_BASENAME": basename,
    },
}
print(json.dumps(payload))
PY
  )"

  if [[ "${DRY_RUN}" == "1" ]]; then
    echo "[dry-run] label=${label} scales=${scales} payload=${payload}"
    echo -e "${label}\t${scales}\t-\tdry-run\t-" >>"${MANIFEST_PATH}"
    return 0
  fi

  local submit_json
  submit_json="$(curl -sS -X POST "${LISTENER_URL}/submit" \
    -H "Authorization: Bearer ${api_key}" \
    -H 'Content-Type: application/json' \
    --data "${payload}")"

  local task_id
  task_id="$(python3 - <<'PY' "${submit_json}"
import json
import sys
print(json.loads(sys.argv[1]).get("task_id", ""))
PY
  )"

  if [[ -z "${task_id}" ]]; then
    echo "ERROR: submit failed for label=${label}: ${submit_json}" >&2
    echo -e "${label}\t${scales}\t-\tsubmit-failed\t-" >>"${MANIFEST_PATH}"
    return 1
  fi

  local state="queued"
  local job_name=""
  local task_json
  for _ in $(seq 1 "${POLL_ATTEMPTS}"); do
    task_json="$(curl -sS "${LISTENER_URL}/tasks/${task_id}" -H "Authorization: Bearer ${api_key}")"
    state="$(python3 - <<'PY' "${task_json}"
import json
import sys
d = json.loads(sys.argv[1])
print(d.get("status", ""))
PY
    )"
    job_name="$(python3 - <<'PY' "${task_json}"
import json
import sys
d = json.loads(sys.argv[1])
print(d.get("job_name", ""))
PY
    )"
    if [[ "${state}" == "submitted" || "${state}" == "failed" ]]; then
      break
    fi
    sleep "${POLL_SLEEP_SECONDS}"
  done

  echo "label=${label} scales=${scales} task_id=${task_id} status=${state} job=${job_name}"
  echo -e "${label}\t${scales}\t${task_id}\t${state}\t${job_name}" >>"${MANIFEST_PATH}"
}

IFS=';' read -r -a entries <<<"${MATRIX}"
for entry in "${entries[@]}"; do
  if [[ -z "${entry}" ]]; then
    continue
  fi
  label="${entry%%=*}"
  scales="${entry#*=}"
  if [[ -z "${label}" || -z "${scales}" || "${label}" == "${scales}" ]]; then
    echo "ERROR: invalid MATRIX entry '${entry}' (expected label=scales)" >&2
    exit 1
  fi
  submit_case "${label}" "${scales}"
done

echo "Done. Submission manifest: ${MANIFEST_PATH}"
