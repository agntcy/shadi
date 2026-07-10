# Launcher Scripts

## Quickstart

Start the SLIM message bus:

```bash
./scripts/launch_slim.sh
```

Start a local native SLIM shell demo on macOS:

```bash
./scripts/demo_slim_shell.sh
```

Print the manual demo commands without opening Terminal windows:

```bash
./scripts/demo_slim_shell.sh --print-only
```

Run the ignored live smoke test that exercises create/invite/join against local
mTLS assets and secret access:

```bash
./scripts/demo_slim_shell.sh --smoke-test
```

On Windows PowerShell:

```powershell
.\scripts\launch_slim.ps1
```

Run SHADI MAS experiments in Kubernetes instead of locally:

```bash
./scripts/deploy_mas_experiments_k8s.sh spotcheck
```

Other modes:

```bash
./scripts/deploy_mas_experiments_k8s.sh suite
./scripts/deploy_mas_experiments_k8s.sh sweep
```

Run a simple HTTP listener that manages vars/secrets and submits jobs:

```bash
python3 ./scripts/mas_job_listener.py --host 127.0.0.1 --port 8088
```

By default, the listener submits jobs in namespace `lumuscar-jobs` and reads both
SLIM and vLLM source secrets from that same namespace (namespace-scoped RBAC).

Submit a sweep through the listener:

```bash
export LISTENER_API_KEY='<listener-submit-api-key>'

curl -sS -X POST http://127.0.0.1:8088/submit \
	-H "Authorization: Bearer ${LISTENER_API_KEY}" \
	-H 'content-type: application/json' \
	-d '{
				"mode": "sweep",
				"llm_model": "gemma-4-26b-a4b-it-node5-h100"
			}'
```

Poll task status:

```bash
curl -sS -H "Authorization: Bearer ${LISTENER_API_KEY}" http://127.0.0.1:8088/tasks/<task_id>
```

Launch a large-scale sweep matrix from your laptop (submits multiple sweep jobs):

```bash
chmod +x ./scripts/launch_large_scale_sweep_matrix.sh

LISTENER_URL=http://127.0.0.1:38189 \
LIVE_ENDPOINT=gls-admin:47357 \
LLM_MODEL=gemma-4-26b-a4b-it-node5-h100 \
MATRIX='mid=2,4,8,12,16;large=20,30,40,50;xlarge=60,80,100' \
./scripts/launch_large_scale_sweep_matrix.sh
```

The script writes a TSV manifest with `label`, `scales`, `task_id`, `status`, and
`job_name` (default path `/tmp/shadi_large_sweep_manifest_<timestamp>.tsv`).
Use `DRY_RUN=1` to preview payloads without submitting.
`LISTENER_URL` can be localhost when using port-forward, but `LIVE_ENDPOINT`
must be reachable from inside cluster jobs.
For remote shared SLIM endpoints, keep `START_LOCAL_NODE=0` (default) so the
sweep harness does not try to bind a local node inside each job.

## Environment variables

These scripts default to local paths and can be overridden per terminal.
`scripts/agentbridge_env.sh` now keeps caller-provided values and only fills
in missing defaults.

### Shared
- SHADI_TMP_DIR: Base directory for per-agent data (default: ./\.tmp).
- SHADI_AGENT_ID: Agent-specific suffix used for isolation.
- SHADI_OPERATOR_PRESENTATION: Required to access secrets in SHADI.
- SHADI_SECRET_BACKEND: Secret store backend (`onepassword` or `keychain`, default: `keychain`).
- SHADI_OP_VAULT: 1Password vault name (default: `shadi`). Only used when backend is `onepassword`.
- SHADI_OP_ACCOUNT: 1Password account for multi-account setups. Only used when backend is `onepassword`.
- SLIM_TLS_CERT: Client cert (default: ${SHADI_TMP_DIR}/shadi-slim-mtls/client.crt).
- SLIM_TLS_KEY: Client key (default: ${SHADI_TMP_DIR}/shadi-slim-mtls/client.key).
- SLIM_TLS_CA: CA cert (default: ${SHADI_TMP_DIR}/shadi-slim-mtls/ca.crt).

### SLIM node
- SLIM_ENDPOINT: Host:port for the node (default: 127.0.0.1:47357).

### Kubernetes experiment runner
- K8S_NAMESPACE: Namespace for the Job (default: `shadi`).
- SHADI_MAS_REPO_URL: Git repo cloned by the job (default: `https://github.com/agntcy/shadi.git`).
- SHADI_MAS_REPO_REF: Branch/tag/sha cloned by the job (default: `feat/agentbridge`).
- SHADI_MAS_RUNNER_IMAGE: Base image for compiling/running experiments (default: `rust:1.88-bookworm`).
- SHADI_LIVE_ENDPOINT: Remote SLIM endpoint for live experiments (default: `gls-admin:47357`).
- SHADI_LIVE_LLM_BACKEND: LLM backend (`vllm` or `ollama`, default: `vllm`).
- SHADI_LIVE_LLM_MODEL: Model identifier for backend calls. Required for live runs when backend is `vllm`.
- SHADI_LIVE_VLLM_BASE_URL: OpenAI-compatible vLLM base URL (default: `https://vllm.outshift-gls.cisco.com/v1`).
- SHADI_LIVE_VLLM_ENDPOINT: Full chat completions endpoint. If omitted, it is derived as `${SHADI_LIVE_VLLM_BASE_URL}/chat/completions`.
- SHADI_MAS_SECRET_NAME: K8s secret with credentials (default: `shadi-mas-experiments-secrets`).

### MAS job listener
- SHADI_LISTENER_HOST: Listener bind host (default: `127.0.0.1`).
- SHADI_LISTENER_PORT: Listener bind port (default: `8088`).
- SHADI_LISTENER_DEPLOY_SCRIPT: Deploy script path (default: `scripts/deploy_mas_experiments_k8s.sh`).
- SHADI_LISTENER_DEST_NAMESPACE: Namespace where runtime secret + jobs are submitted (default: `lumuscar-jobs`).
- SHADI_LISTENER_DEST_SECRET_NAME: Runtime secret updated before submit (default: `shadi-mas-experiments-secrets`).
- SHADI_LISTENER_SLIM_SECRET_NAMESPACE: Namespace for SLIM shared-secret source (default: same as destination namespace).
- SHADI_LISTENER_SLIM_SECRET_NAME: Secret containing SLIM shared-secret source (default: destination secret name).
- SHADI_LISTENER_SLIM_SECRET_KEY: Key name for SLIM shared secret (default: `SLIM_SHARED_SECRET`).
- SHADI_LISTENER_VLLM_SECRET_NAMESPACE: Namespace containing vault-synced vLLM key map (default: destination namespace).
- SHADI_LISTENER_VLLM_SECRET_NAME: Vault-synced secret name (default: `gemma-vllm-api-keys`).
- SHADI_LISTENER_VLLM_SECRET_KEY: Key in vault-synced secret that stores the JSON map (default: `api-key`).
- SHADI_LISTENER_VLLM_USERNAME: Username lookup in JSON key map (default: `lumuscar@cisco.com`).
- SHADI_LISTENER_REQUIRE_AUTH: Require API token for `/submit` and `/tasks/*` (default: `1`).
- SHADI_LISTENER_AUTH_SECRET_NAMESPACE: Namespace containing listener API token secret (default: destination namespace).
- SHADI_LISTENER_AUTH_SECRET_NAME: Secret containing API token for submit/tasks (default: `mas-job-listener-api`).
- SHADI_LISTENER_AUTH_SECRET_KEY: Key in API token secret (default: `submit-api-key`).
- SHADI_LISTENER_API_KEY: Optional static fallback token (recommended only for local development).
- SHADI_LISTENER_HTTP_PROXY: HTTP proxy passed to submitted jobs (default: `http://proxy-wsa.esl.cisco.com:80`).
- SHADI_LISTENER_HTTPS_PROXY: HTTPS proxy passed to submitted jobs (default: `http://proxy-wsa.esl.cisco.com:80`).

Create the listener API secret before deploying:

```bash
kubectl -n lumuscar-jobs create secret generic mas-job-listener-api \
	--from-literal=submit-api-key='<strong-random-token>' \
	--dry-run=client -o yaml | kubectl apply -f -
```

If your vault sync currently writes `gemma-vllm-api-keys` in another namespace,
create an `ExternalSecret` in `lumuscar` (same remote key/property) so the
listener can run without cross-namespace permissions.

Important for cluster jobs: do not use `localhost` or `127.0.0.1` for
`SHADI_LIVE_VLLM_ENDPOINT`. The job may schedule on a non-GPU node, so model
calls must target the routed remote model service endpoint.

For `spotcheck` and `sweep`, the script validates `SHADI_LIVE_LLM_MODEL` against
the models returned by your vLLM endpoint (`/v1/models`) from inside the cluster.
If the model is not found, the job exits early and prints the available model IDs.

Known routed model ID examples on `vllm.outshift-gls.cisco.com`:
- `gemma-4-26b-a4b-it-node4-h100`
- `gemma-4-26b-a4b-it-node5-h100`
- `gemma-4-26b-a4b-it-node2-a100`
- `gemma-4-31b-it-node1-2a100`

Example live submission using a routed Gemma model:

```bash
SHADI_LIVE_LLM_BACKEND=vllm \
SHADI_LIVE_VLLM_BASE_URL=https://vllm.outshift-gls.cisco.com/v1 \
SHADI_LIVE_LLM_MODEL=gemma-4-26b-a4b-it-node5-h100 \
./scripts/deploy_mas_experiments_k8s.sh spotcheck
```

Required Kubernetes secrets for live modes (`spotcheck`, `sweep`):

```bash
kubectl -n shadi create secret generic shadi-mas-experiments-secrets \
	--from-literal=SLIM_SHARED_SECRET='<cluster-shared-secret>' \
	--from-literal=OPENAI_API_KEY='<vllm-api-key>' \
	--dry-run=client -o yaml | kubectl apply -f -

# mTLS bundle used by SLIM client auth
kubectl -n shadi create secret generic shadi-slim-mtls \
	--from-file=client.crt=/path/to/client.crt \
	--from-file=client.key=/path/to/client.key \
	--from-file=ca.crt=/path/to/ca.crt \
	--dry-run=client -o yaml | kubectl apply -f -
```

## Example per-terminal env

Terminal 1 (SLIM):

```bash
export SHADI_TMP_DIR="./.tmp"
export SLIM_ENDPOINT="127.0.0.1:47357"
./scripts/launch_slim.sh
```

Remote SLIM cluster (skip local launcher):

```bash
export SLIM_ENDPOINT="gls-admin:47357"
export SLIM_SHARED_SECRET="<cluster-shared-secret>"
export SLIM_TLS_CERT="/path/to/client.crt"
export SLIM_TLS_KEY="/path/to/client.key"
export SLIM_TLS_CA="/path/to/ca.crt"
./scripts/agentbridge_shell2_register_copilot.sh
./scripts/agentbridge_shell3_register_codex.sh
./scripts/agentbridge_shell4_coordinate.sh "implement fibonacci in rust"
```

Windows PowerShell:

```powershell
$env:SHADI_TMP_DIR = "./.tmp"
$env:SLIM_ENDPOINT = "127.0.0.1:47357"
.\scripts\launch_slim.ps1
```

## Using 1Password as the secret backend

To store and retrieve all secrets via a 1Password vault instead of the OS
keychain, export `SHADI_SECRET_BACKEND` before running the scripts:

```bash
export SHADI_SECRET_BACKEND=onepassword
export SHADI_OP_VAULT=shadi          # optional, default: shadi
```

The `op` CLI (1Password CLI v2) must be installed and authenticated. For CI,
set `OP_SERVICE_ACCOUNT_TOKEN`. Then run the scripts as usual — the import
script and all launchers will route secrets through 1Password automatically.

The PowerShell launchers support the same environment variables and also pre-read
1Password secrets before entering the sandbox so Windows Hello / app prompts do
not deadlock once the sandbox is active.
