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
