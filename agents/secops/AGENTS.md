# SecOps Agent Guide

## Overview
The SecOps agent scans allowlisted repositories, generates reports, and can
operate as a standalone local agent or an A2A server behind SLIM.

## Key environment variables
- SHADI_OPERATOR_PRESENTATION: Required to access secrets in SHADI.
- SHADI_SECOPS_CONFIG: Path to a secops config TOML (default: secops.toml).
- SHADI_TMP_DIR: Base directory for workspace and memory defaults (default: ./.tmp).
- SHADI_AGENT_ID: Optional agent-specific suffix for isolation.
- SHADI_SECOPS_MEMORY_DB: Optional override for the SQLCipher memory DB.
- SHADI_MEMORY_DB: Optional global memory DB override.
- SHADI_ADK_MEMORY_DB: Optional override for ADK memory persistence.
- SLIM_TLS_CERT, SLIM_TLS_KEY, SLIM_TLS_CA: Client TLS material for SLIM.

## Common workflows

### Load secrets (token, workspace, LLM settings)
```bash
export SHADI_OPERATOR_PRESENTATION="local-operator"
export GITHUB_TOKEN="$(gh auth token)"
uv run agents/secops/import_secops_secrets.py
```

### Run the local SecOps agent
```bash
export SHADI_OPERATOR_PRESENTATION="local-operator"
uv run agents/secops/secops.py
```

### Run the SecOps A2A server
```bash
export SHADI_OPERATOR_PRESENTATION="local-operator"
export SHADI_SECOPS_CONFIG=./.tmp/secops-a.toml
export SHADI_POLICY_PATH=./policies/demo/secops-a.json
export SLIM_TLS_CERT=./.tmp/shadi-slim-mtls/client-secops-a.crt
export SLIM_TLS_KEY=./.tmp/shadi-slim-mtls/client-secops-a.key
export SLIM_TLS_CA=./.tmp/shadi-slim-mtls/ca.crt
./scripts/launch_secops_a2a.sh
```

### Run the ADK agent with SHADI-backed memory
```bash
export SHADI_OPERATOR_PRESENTATION="local-operator"
export SHADI_AGENT_ID="secops-a"
export SHADI_TMP_DIR="./.tmp"
uv run agents/secops/adk_agent/run_local.py
```

## Notes
- Workspace defaults to $SHADI_TMP_DIR/$SHADI_AGENT_ID/shadi-secops unless
  overridden in secops.toml or SHADI_SECOPS_CONFIG.
- Memory defaults to $SHADI_TMP_DIR/$SHADI_AGENT_ID/shadi-secops/secops_memory.db
  unless overridden by SHADI_SECOPS_MEMORY_DB or SHADI_MEMORY_DB.
