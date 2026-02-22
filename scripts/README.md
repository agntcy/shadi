# Launcher Scripts

## Quickstart

Open three terminals and run:

```bash
./scripts/launch_slim.sh
```

```bash
./scripts/import_secops_secrets.sh
```

```bash
./scripts/launch_secops_a2a.sh
```

```bash
./scripts/launch_avatar.sh
```

## Generic secure launcher

Use the new profile-based launcher to run any command through SHADI sandboxing:

```bash
./scripts/launch_secure.sh balanced -- /usr/bin/env python3 --version
```

Available profiles:
- `strict`: local-only policy, network blocked.
- `balanced`: local workspace and temp writes, network blocked.
- `connected`: like balanced, with network enabled.

Policy files live in `policies/launcher/`.

Common overrides:

```bash
SHADI_ALLOW_PATHS="./data:./logs" \
SHADI_INJECT_KEYCHAIN="secops/github_token=GITHUB_TOKEN" \
./scripts/launch_secure.sh strict -- uv run agents/secops/secops.py
```

Override profile and policy directory:

```bash
SHADI_POLICY_PROFILE=connected \
SHADI_POLICY_DIR="$(pwd)/policies/launcher" \
./scripts/launch_secure.sh -- /usr/bin/env echo hello
```

## Environment variables

These scripts default to local paths and can be overridden per terminal.

### Shared
- SHADI_TMP_DIR: Base directory for per-agent data (default: ./\.tmp).
- SHADI_AGENT_ID: Agent-specific suffix used for isolation.
- SHADI_OPERATOR_PRESENTATION: Required to access secrets in SHADI.

### SecOps A2A server
- SHADI_SECOPS_CONFIG: Path to secops TOML (default: ${SHADI_TMP_DIR}/secops-a.toml).
- SLIM_TLS_CERT: Client cert (default: ${SHADI_TMP_DIR}/shadi-slim-mtls/client-secops-a.crt).
- SLIM_TLS_KEY: Client key (default: ${SHADI_TMP_DIR}/shadi-slim-mtls/client-secops-a.key).
- SLIM_TLS_CA: CA cert (default: ${SHADI_TMP_DIR}/shadi-slim-mtls/ca.crt).

### Avatar agent
- SHADI_SECOPS_CONFIG: Path to secops TOML (default: ${SHADI_TMP_DIR}/secops-a.toml).
- SLIM_TLS_CERT: Client cert (default: ${SHADI_TMP_DIR}/shadi-slim-mtls/client-avatar.crt).
- SLIM_TLS_KEY: Client key (default: ${SHADI_TMP_DIR}/shadi-slim-mtls/client-avatar.key).
- SLIM_TLS_CA: CA cert (default: ${SHADI_TMP_DIR}/shadi-slim-mtls/ca.crt).

### SLIM node
- SLIM_ENDPOINT: Host:port for the node (default: 127.0.0.1:47357).

## Example per-terminal env

Terminal 1 (SLIM):

```bash
export SHADI_TMP_DIR="./.tmp"
export SLIM_ENDPOINT="127.0.0.1:47357"
./scripts/launch_slim.sh
```

Terminal 2 (SecOps A2A):

```bash
export SHADI_TMP_DIR="./.tmp"
export SHADI_AGENT_ID="secops-a"
export SHADI_OPERATOR_PRESENTATION="local-operator"
./scripts/import_secops_secrets.sh
./scripts/launch_secops_a2a.sh
```

Terminal 3 (Avatar):

```bash
export SHADI_TMP_DIR="./.tmp"
export SHADI_AGENT_ID="avatar-1"
export SHADI_OPERATOR_PRESENTATION="local-operator"
./scripts/launch_avatar.sh
```
