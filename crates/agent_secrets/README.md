# agent_secrets

Secure secret storage and access primitives for autonomous agents.

## Goals
- Provide a stable Rust API to store and retrieve secrets.
- Support Windows, macOS, iOS, Android, and Linux using OS keystores.
- Minimize in-memory exposure through explicit secret wrappers.

## Backends

### OS Keychain (default)
On macOS the store uses Security Framework (Keychain Services). On Linux it is
an encrypted keyring file (below). Other platforms fall back to a no-op store
until native backends are implemented.

### Linux keyring file

An encrypted keyring file in libsecret's file format, read through `oo7`. It
needs no D-Bus, no daemon and no login session, so it also works headless and in
containers.

```bash
export SHADI_KEYRING_PASSWORD_FILE=/path/to/keyring-password  # required
export SHADI_KEYRING_PATH=/path/to/agent_secrets.keyring      # optional
```

- `SHADI_KEYRING_PASSWORD_FILE` names a file holding the keyring password (a
  trailing newline is ignored). Without it the store is unavailable and every
  call returns `NotSupported`, as the no-op store did.
- `SHADI_KEYRING_PATH` defaults to `~/.shadi/keyring/agent_secrets.keyring`,
  outside the home directories the Compatibility sandbox profile grants
  (`~/.config`, `~/.local`, `~/.cache`).
- Both must be absolute paths; a relative one makes the store unavailable.
- Only key provisioning (`shadictl derive-agent-identity` and
  `derive-agent-did`) creates the keyring, through `creating_store()`. Until
  it exists, the store is unavailable and calls return `StoreNotFound`.
- Writers hold an exclusive lock on `<keyring>.lock`; readers don't lock, so
  a keyring on a read-only mount can still be read.

Anyone who can read both the keyring file and its password file can decrypt
every item, so keep them out of every sandbox grant. Every profile grants the
working directory, so don't launch a sandbox from `$HOME` or a parent of the
keyring. See [Security](../../docs/content/security.md#linux-keyring-file-backend)
for the paths to avoid.

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
The macOS Keychain, Linux keyring file and 1Password backends are functional.
Other platform backends are stubbed and return `NotSupported` until implemented.
