# Launcher Scripts

## Quickstart

Start the SLIM message bus:

```bash
./scripts/launch_slim.sh
```

On Windows PowerShell:

```powershell
.\scripts\launch_slim.ps1
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
- SLIM_TLS_CERT: Client cert (default: ${SHADI_TMP_DIR}/shadi-slim-mtls/client.crt).
- SLIM_TLS_KEY: Client key (default: ${SHADI_TMP_DIR}/shadi-slim-mtls/client.key).
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
