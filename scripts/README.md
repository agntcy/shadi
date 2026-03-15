# Launcher Scripts

The project task runner now keeps the root [Justfile](../Justfile) as a thin
entrypoint that imports focused files from [just/core.just](../just/core.just),
[just/secops.just](../just/secops.just), and [just/demo.just](../just/demo.just).
Recipe names did not change, so existing commands such as `just launch-avatar`
and `just secops-run` still work as before.

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

On Windows PowerShell, use the `.ps1` equivalents:

```powershell
.\scripts\launch_slim.ps1
```

```powershell
.\scripts\import_secops_secrets.ps1
```

```powershell
.\scripts\launch_secops_a2a.ps1
```

```powershell
.\scripts\launch_avatar.ps1
```

## Environment variables

These scripts default to local paths and can be overridden per terminal.

### Shared
- SHADI_TMP_DIR: Base directory for per-agent data (default: ./\.tmp).
- SHADI_AGENT_ID: Agent-specific suffix used for isolation.
- SHADI_OPERATOR_PRESENTATION: Required to access secrets in SHADI.
- SHADI_SECRET_BACKEND: Secret store backend (`onepassword` or `keychain`, default: `keychain`).
- SHADI_OP_VAULT: 1Password vault name (default: `shadi`). Only used when backend is `onepassword`.
- SHADI_OP_ACCOUNT: 1Password account for multi-account setups. Only used when backend is `onepassword`.

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

Windows PowerShell:

```powershell
$env:SHADI_TMP_DIR = "./.tmp"
$env:SLIM_ENDPOINT = "127.0.0.1:47357"
.\scripts\launch_slim.ps1
```

Terminal 2 (SecOps A2A):

```bash
export SHADI_TMP_DIR="./.tmp"
export SHADI_AGENT_ID="secops-a"
export SHADI_OPERATOR_PRESENTATION="local-operator"
./scripts/import_secops_secrets.sh
./scripts/launch_secops_a2a.sh
```

Windows PowerShell:

```powershell
$env:SHADI_TMP_DIR = "./.tmp"
$env:SHADI_AGENT_ID = "secops-a"
$env:SHADI_OPERATOR_PRESENTATION = "local-operator"
.\scripts\import_secops_secrets.ps1
.\scripts\launch_secops_a2a.ps1
```

Terminal 3 (Avatar):

```bash
export SHADI_TMP_DIR="./.tmp"
export SHADI_AGENT_ID="avatar-1"
export SHADI_OPERATOR_PRESENTATION="local-operator"
./scripts/launch_avatar.sh
```

Windows PowerShell:

```powershell
$env:SHADI_TMP_DIR = "./.tmp"
$env:SHADI_AGENT_ID = "avatar-1"
$env:SHADI_OPERATOR_PRESENTATION = "local-operator"
.\scripts\launch_avatar.ps1
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
