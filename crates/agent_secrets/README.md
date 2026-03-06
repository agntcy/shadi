# agent_secrets

Secure secret storage and access primitives for autonomous agents.

## Goals
- Provide a stable Rust API to store and retrieve secrets.
- Support Windows, macOS, iOS, Android, and Linux using OS keystores.
- Minimize in-memory exposure through explicit secret wrappers.

## Backends

### OS Keychain (default)
On macOS the store uses Security Framework (Keychain Services). Other platforms
fall back to a no-op store until native backends are implemented.

### 1Password (optional)
Enable the `onepassword` Cargo feature and set environment variables to use
1Password as the secret backend. This is useful for team/shared vault workflows
and CI/CD pipelines where a service account token is available.

```bash
export SHADI_SECRET_BACKEND=onepassword   # select 1Password backend
export SHADI_OP_VAULT=shadi               # vault name (default: shadi)
export SHADI_OP_ACCOUNT=my-account        # optional, for multi-account setups
```

The backend requires the `op` CLI (1Password CLI v2) to be installed and
authenticated. For headless/CI use, set `OP_SERVICE_ACCOUNT_TOKEN`.

Items are stored as Secure Notes tagged `shadi` with base64-encoded content.

## Status
The macOS Keychain and 1Password backends are functional. Other platform
backends are stubbed and return `NotSupported` until implemented.
