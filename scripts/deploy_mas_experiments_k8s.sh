#!/usr/bin/env bash
# Deploy SHADI MAS experiments as a Kubernetes Job so runs execute in-cluster.
set -euo pipefail

MODE="${1:-spotcheck}" # suite | spotcheck | sweep

if [[ "${MODE}" != "suite" && "${MODE}" != "spotcheck" && "${MODE}" != "sweep" ]]; then
  echo "usage: $0 [suite|spotcheck|sweep]"
  exit 1
fi

if ! command -v kubectl >/dev/null 2>&1; then
  echo "ERROR: kubectl is required"
  exit 1
fi

NAMESPACE="${K8S_NAMESPACE:-shadi}"
SKIP_NAMESPACE_CREATE="${SHADI_SKIP_NAMESPACE_CREATE:-0}"
JOB_BASENAME="${SHADI_MAS_JOB_BASENAME:-shadi-mas-${MODE}}"
TIMESTAMP="$(date +%Y%m%d%H%M%S)"
JOB_NAME="${JOB_BASENAME}-${TIMESTAMP}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Source mode:
# - local (default): sync current local workspace into pod (no git clone).
# - git: clone SHADI_MAS_REPO_URL/SHADI_MAS_REPO_REF inside pod.
SOURCE_MODE="${SHADI_MAS_SOURCE_MODE:-local}"
if [[ "${SOURCE_MODE}" != "local" && "${SOURCE_MODE}" != "git" ]]; then
  echo "ERROR: SHADI_MAS_SOURCE_MODE must be 'local' or 'git'"
  exit 1
fi

# Git source fallback (used only when SHADI_MAS_SOURCE_MODE=git).
REPO_URL="${SHADI_MAS_REPO_URL:-https://github.com/agntcy/shadi.git}"
REPO_REF="${SHADI_MAS_REPO_REF:-feat/agentbridge}"
RUST_IMAGE="${SHADI_MAS_RUNNER_IMAGE:-rust:1.88-bookworm}"

# Live runs default to your requested remote endpoints.
LIVE_SLIM_ENDPOINT="${SHADI_LIVE_ENDPOINT:-gls-admin:47357}"
LIVE_LLM_BACKEND="${SHADI_LIVE_LLM_BACKEND:-vllm}"
LIVE_LLM_MODEL="${SHADI_LIVE_LLM_MODEL:-${SHADI_LIVE_VLLM_MODEL:-}}"
LIVE_VLLM_BASE_URL="${SHADI_LIVE_VLLM_BASE_URL:-https://vllm.outshift-gls.cisco.com/v1}"
LIVE_VLLM_ENDPOINT="${SHADI_LIVE_VLLM_ENDPOINT:-${LIVE_VLLM_BASE_URL%/}/chat/completions}"
LIVE_AGENT_ID="${SHADI_LIVE_AGENT_ID:-avatar}"
LIVE_PEER_AGENT_ID="${SHADI_LIVE_PEER_AGENT_ID:-secops-a}"
LIVE_SLIM_ENDPOINT_HOST="$(printf '%s' "${LIVE_SLIM_ENDPOINT}" | sed -E 's#^[a-zA-Z]+://##' | cut -d/ -f1 | cut -d: -f1)"

# Proxy configuration for in-cluster jobs.
# Explicit SHADI_MAS_* variables take precedence over inherited shell proxy vars.
PROXY_HTTP="${SHADI_MAS_HTTP_PROXY:-${HTTP_PROXY:-${http_proxy:-}}}"
PROXY_HTTPS="${SHADI_MAS_HTTPS_PROXY:-${HTTPS_PROXY:-${https_proxy:-}}}"
PROXY_ALL="${SHADI_MAS_ALL_PROXY:-${ALL_PROXY:-${all_proxy:-}}}"

DEFAULT_NO_PROXY="127.0.0.1,localhost,.svc,.svc.cluster.local,.cluster.local"
if [[ -n "${LIVE_SLIM_ENDPOINT_HOST}" ]]; then
  DEFAULT_NO_PROXY+="${DEFAULT_NO_PROXY:+,}${LIVE_SLIM_ENDPOINT_HOST}"
fi

RAW_NO_PROXY="${SHADI_MAS_NO_PROXY:-${NO_PROXY:-${no_proxy:-}}}"
if [[ -n "${RAW_NO_PROXY}" ]]; then
  PROXY_NO_PROXY="${RAW_NO_PROXY},${DEFAULT_NO_PROXY}"
else
  PROXY_NO_PROXY="${DEFAULT_NO_PROXY}"
fi

if [[ "${MODE}" != "suite" && "${LIVE_LLM_BACKEND}" == "vllm" && -z "${LIVE_LLM_MODEL}" ]]; then
  echo "ERROR: SHADI_LIVE_LLM_MODEL is required for vLLM live runs."
  echo "Set it explicitly to a model available in your cluster endpoint."
  echo "Example: SHADI_LIVE_LLM_MODEL='<your-model-id>' ./scripts/deploy_mas_experiments_k8s.sh ${MODE}"
  exit 1
fi

if [[ "${MODE}" != "suite" && "${LIVE_LLM_BACKEND}" == "vllm" ]]; then
  if [[ -z "${LIVE_VLLM_ENDPOINT}" ]]; then
    echo "ERROR: SHADI_LIVE_VLLM_ENDPOINT is required for vLLM live runs."
    exit 1
  fi

  endpoint_host="$(printf '%s' "${LIVE_VLLM_ENDPOINT}" | sed -E 's#^[a-zA-Z]+://##' | cut -d/ -f1 | cut -d: -f1)"
  if [[ "${endpoint_host}" == "localhost" || "${endpoint_host}" == "127.0.0.1" || "${endpoint_host}" == "::1" ]]; then
    echo "ERROR: SHADI_LIVE_VLLM_ENDPOINT points to a loopback host (${endpoint_host})."
    echo "Sweep jobs may run on non-GPU nodes; use the routed model service endpoint instead."
    echo "Example: SHADI_LIVE_VLLM_BASE_URL='https://vllm.outshift-gls.cisco.com/v1'"
    exit 1
  fi
fi

if [[ "${MODE}" != "suite" && "${LIVE_LLM_BACKEND}" == "vllm" && "${SHADI_SKIP_VLLM_PREFLIGHT:-0}" != "1" ]]; then
  if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 is required for vLLM model preflight"
    exit 1
  fi

  if [[ -n "${COPILOT_PROVIDER_API_KEY:-}" && -z "${OPENAI_API_KEY:-}" ]]; then
    export OPENAI_API_KEY="${COPILOT_PROVIDER_API_KEY}"
  fi

  SHADI_LIVE_VLLM_ENDPOINT="${LIVE_VLLM_ENDPOINT}" \
  SHADI_LIVE_LLM_MODEL="${LIVE_LLM_MODEL}" \
  OPENAI_API_KEY="${OPENAI_API_KEY:-}" \
  python3 - <<'PY'
import json
import os
import sys
import urllib.error
import urllib.request

endpoint = os.environ.get("SHADI_LIVE_VLLM_ENDPOINT", "").strip()
selected_model = os.environ.get("SHADI_LIVE_LLM_MODEL", "").strip()
api_key = os.environ.get("OPENAI_API_KEY", "").strip()

if not endpoint or not selected_model:
    sys.stderr.write("vLLM preflight missing endpoint or model\n")
    raise SystemExit(1)

models_url = endpoint
if models_url.endswith("/chat/completions"):
    models_url = models_url[: -len("/chat/completions")] + "/models"
elif models_url.endswith("/completions"):
    models_url = models_url[: -len("/completions")] + "/models"
elif models_url.endswith("/v1"):
    models_url = models_url + "/models"
else:
    models_url = models_url.rstrip("/") + "/models"

headers = {}
if api_key:
    headers["Authorization"] = f"Bearer {api_key}"

req = urllib.request.Request(models_url, headers=headers, method="GET")
try:
    with urllib.request.urlopen(req, timeout=30) as res:
        payload = json.loads(res.read().decode("utf-8"))
except urllib.error.HTTPError as err:
    detail = err.read().decode("utf-8", errors="replace")
    sys.stderr.write(f"vLLM model discovery failed ({err.code}) at {models_url}: {detail}\n")
    raise SystemExit(1)
except Exception as err:
    sys.stderr.write(f"vLLM model discovery failed at {models_url}: {err}\n")
    raise SystemExit(1)

available = []
for row in payload.get("data", []):
    if isinstance(row, dict) and isinstance(row.get("id"), str):
        available.append(row["id"])

if not available:
    sys.stderr.write(f"No models returned by vLLM endpoint {models_url}\n")
    raise SystemExit(1)

if selected_model not in available:
    sys.stderr.write(
        "Requested SHADI_LIVE_LLM_MODEL is not available.\n"
        f"requested: {selected_model}\n"
        f"available: {', '.join(available)}\n"
    )
    raise SystemExit(1)

print(f"Using vLLM model: {selected_model}")
PY
fi

# Secrets are read from an existing secret to avoid embedding sensitive values.
EXPERIMENT_SECRET_NAME="${SHADI_MAS_SECRET_NAME:-shadi-mas-experiments-secrets}"
# Required keys in secret:
#   SLIM_SHARED_SECRET
# Optional keys in secret:
#   OPENAI_API_KEY

EXAMPLE_NAME="mas_live_protocol_spotcheck"
OUTPUT_DIR="artifacts/experiments/mas_live_protocol_spotcheck"
if [[ "${MODE}" == "suite" ]]; then
  EXAMPLE_NAME="mas_experiment_suite"
  OUTPUT_DIR="artifacts/experiments/mas_suite"
elif [[ "${MODE}" == "sweep" ]]; then
  EXAMPLE_NAME="mas_live_protocol_sweep"
  OUTPUT_DIR="artifacts/experiments/mas_live_protocol_sweep"
fi

if [[ "${SKIP_NAMESPACE_CREATE}" == "1" ]]; then
  echo "Using namespace ${NAMESPACE} (namespace creation/check skipped) ..."
else
  echo "Creating namespace ${NAMESPACE} (if missing) ..."
  kubectl get namespace "${NAMESPACE}" >/dev/null 2>&1 || kubectl create namespace "${NAMESPACE}" >/dev/null
fi

if ! kubectl -n "${NAMESPACE}" get secret "${EXPERIMENT_SECRET_NAME}" >/dev/null 2>&1; then
  echo "ERROR: required secret ${EXPERIMENT_SECRET_NAME} is missing in namespace ${NAMESPACE}"
  exit 1
fi

SLIM_SECRET_LEN="$(kubectl -n "${NAMESPACE}" get secret "${EXPERIMENT_SECRET_NAME}" -o jsonpath='{.data.SLIM_SHARED_SECRET}' 2>/dev/null | base64 --decode | wc -c | tr -d ' ')"
if [[ -z "${SLIM_SECRET_LEN}" || "${SLIM_SECRET_LEN}" -lt 32 ]]; then
  echo "ERROR: ${EXPERIMENT_SECRET_NAME}.SLIM_SHARED_SECRET is missing or too short (${SLIM_SECRET_LEN:-0} bytes); expected >= 32 bytes"
  exit 1
fi

if [[ "${MODE}" != "suite" && "${LIVE_LLM_BACKEND}" == "vllm" ]]; then
  API_KEY_LEN="$(kubectl -n "${NAMESPACE}" get secret "${EXPERIMENT_SECRET_NAME}" -o jsonpath='{.data.OPENAI_API_KEY}' 2>/dev/null | base64 --decode | wc -c | tr -d ' ')"
  if [[ -z "${API_KEY_LEN}" || "${API_KEY_LEN}" -lt 16 ]]; then
    echo "ERROR: ${EXPERIMENT_SECRET_NAME}.OPENAI_API_KEY is missing or too short (${API_KEY_LEN:-0} bytes) for vLLM backend"
    exit 1
  fi
fi

echo "Submitting job ${JOB_NAME} in namespace ${NAMESPACE} ..."

PROXY_ENV_YAML=""
append_proxy_env() {
  local key="$1"
  local value="$2"
  if [[ -n "${value}" ]]; then
    PROXY_ENV_YAML+="            - name: ${key}"$'\n'
    PROXY_ENV_YAML+="              value: \"${value}\""$'\n'
  fi
}

append_proxy_env "HTTP_PROXY" "${PROXY_HTTP}"
append_proxy_env "HTTPS_PROXY" "${PROXY_HTTPS}"
append_proxy_env "NO_PROXY" "${PROXY_NO_PROXY}"
append_proxy_env "ALL_PROXY" "${PROXY_ALL}"
append_proxy_env "http_proxy" "${PROXY_HTTP}"
append_proxy_env "https_proxy" "${PROXY_HTTPS}"
append_proxy_env "no_proxy" "${PROXY_NO_PROXY}"
append_proxy_env "all_proxy" "${PROXY_ALL}"

MANIFEST_FILE="$(mktemp -t shadi-mas-k8s-XXXXXX.yaml)"
cat > "${MANIFEST_FILE}" <<YAML
apiVersion: batch/v1
kind: Job
metadata:
  name: ${JOB_NAME}
  namespace: ${NAMESPACE}
  labels:
    app.kubernetes.io/name: shadi-mas-experiments
    app.kubernetes.io/component: ${MODE}
spec:
  ttlSecondsAfterFinished: 86400
  backoffLimit: 0
  template:
    metadata:
      labels:
        app.kubernetes.io/name: shadi-mas-experiments
        app.kubernetes.io/component: ${MODE}
    spec:
      restartPolicy: Never
      containers:
        - name: runner
          image: ${RUST_IMAGE}
          imagePullPolicy: IfNotPresent
          env:
            - name: SHADI_MAS_REPO_URL
              value: "${REPO_URL}"
            - name: SHADI_MAS_REPO_REF
              value: "${REPO_REF}"
            - name: SHADI_MAS_SOURCE_MODE
              value: "${SOURCE_MODE}"
            - name: SHADI_LIVE_ENDPOINT
              value: "${LIVE_SLIM_ENDPOINT}"
            - name: SHADI_LIVE_LLM_BACKEND
              value: "${LIVE_LLM_BACKEND}"
            - name: SHADI_LIVE_LLM_MODEL
              value: "${LIVE_LLM_MODEL}"
            - name: SHADI_LIVE_VLLM_ENDPOINT
              value: "${LIVE_VLLM_ENDPOINT}"
            - name: SHADI_LIVE_AGENT_ID
              value: "${LIVE_AGENT_ID}"
            - name: SHADI_LIVE_PEER_AGENT_ID
              value: "${LIVE_PEER_AGENT_ID}"
            - name: SHADI_LIVE_VLLM_API_KEY_ENV
              value: "OPENAI_API_KEY"
            - name: SLIM_SHARED_SECRET
              valueFrom:
                secretKeyRef:
                  name: ${EXPERIMENT_SECRET_NAME}
                  key: SLIM_SHARED_SECRET
            - name: OPENAI_API_KEY
              valueFrom:
                secretKeyRef:
                  name: ${EXPERIMENT_SECRET_NAME}
                  key: OPENAI_API_KEY
                  optional: true
            - name: SLIM_TLS_CERT
              value: /secrets/slim/client.crt
            - name: SLIM_TLS_KEY
              value: /secrets/slim/client.key
            - name: SLIM_TLS_CA
              value: /secrets/slim/ca.crt
${PROXY_ENV_YAML}          volumeMounts:
            - name: slim-mtls
              mountPath: /secrets/slim
              readOnly: true
            - name: workspace
              mountPath: /workspace
          command:
            - /bin/bash
            - -lc
            - |
              set -euo pipefail
              mkdir -p /workspace/shadi

              if [[ "\$SHADI_MAS_SOURCE_MODE" == "local" ]]; then
                echo "Waiting for local source sync marker..."
                while [[ ! -f /workspace/shadi/.mas_source_ready ]]; do
                  sleep 2
                done
              else
                git clone --depth 1 --branch "\$SHADI_MAS_REPO_REF" "\$SHADI_MAS_REPO_URL" /workspace/shadi
              fi

              cd /workspace/shadi

              if ! command -v cargo >/dev/null 2>&1; then
                echo "cargo not found in runner image; installing Rust toolchain via rustup..."
                if command -v curl >/dev/null 2>&1; then
                  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
                elif command -v wget >/dev/null 2>&1; then
                  wget -qO- https://sh.rustup.rs | sh -s -- -y --profile minimal
                else
                  echo "ERROR: neither curl nor wget is available to bootstrap rustup"
                  exit 1
                fi

                # rustup location varies by image (e.g., /usr/local/cargo vs ~/.cargo).
                if [[ -n "\${CARGO_HOME:-}" && -f "\${CARGO_HOME}/env" ]]; then
                  . "\${CARGO_HOME}/env"
                elif [[ -f "\${HOME}/.cargo/env" ]]; then
                  . "\${HOME}/.cargo/env"
                elif [[ -f "/usr/local/cargo/env" ]]; then
                  . "/usr/local/cargo/env"
                fi

                export PATH="/usr/local/cargo/bin:\${HOME}/.cargo/bin:\${PATH}"
              fi

              if ! command -v cargo >/dev/null 2>&1; then
                echo "ERROR: cargo still unavailable after bootstrap"
                exit 1
              fi

              cargo build -p shadi_demo_bot
              cargo run --example ${EXAMPLE_NAME} -p agntcy-shadi-mas

              echo "Experiment outputs are under ${OUTPUT_DIR}"
              ls -lah "${OUTPUT_DIR}" || true
      volumes:
        - name: slim-mtls
          secret:
            secretName: shadi-slim-mtls
        - name: workspace
          emptyDir: {}
YAML

kubectl apply -f "${MANIFEST_FILE}" >/dev/null
rm -f "${MANIFEST_FILE}"

if [[ "${SOURCE_MODE}" == "local" ]]; then
  echo "Waiting for runner pod to be ready for local source sync..."
  POD_NAME=""
  for _ in $(seq 1 90); do
    POD_NAME="$(kubectl -n "${NAMESPACE}" get pods -l job-name="${JOB_NAME}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
    if [[ -n "${POD_NAME}" ]]; then
      break
    fi
    sleep 1
  done

  if [[ -z "${POD_NAME}" ]]; then
    echo "ERROR: failed to find pod for job ${JOB_NAME}"
    exit 1
  fi

  kubectl -n "${NAMESPACE}" wait --for=condition=Ready --timeout=5m "pod/${POD_NAME}" >/dev/null

  echo "Syncing local workspace into pod (excluding .git and target) ..."
  tar \
    --exclude='./.git' \
    --exclude='./target' \
    --exclude='./.tmp/agentbridge-logs' \
    -C "${ROOT_DIR}" -cf - . \
    | kubectl -n "${NAMESPACE}" exec -i "${POD_NAME}" -- tar -xf - -C /workspace/shadi

  kubectl -n "${NAMESPACE}" exec "${POD_NAME}" -- /bin/bash -lc 'touch /workspace/shadi/.mas_source_ready'
fi

echo "Job submitted: ${JOB_NAME}"
echo ""
echo "Watch progress:"
echo "  kubectl -n ${NAMESPACE} logs -f job/${JOB_NAME}"
echo ""
echo "When complete, copy artifacts from pod:"
echo "  POD=\$(kubectl -n ${NAMESPACE} get pods -l job-name=${JOB_NAME} -o jsonpath='{.items[0].metadata.name}')"
echo "  kubectl -n ${NAMESPACE} cp "\${POD}:/workspace/shadi/${OUTPUT_DIR}" ./artifacts_${JOB_NAME}"
