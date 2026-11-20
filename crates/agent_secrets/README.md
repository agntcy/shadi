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

An encrypted keyring file: a SQLCipher database (SQLite with AES-256 page
encryption), unlocked with a password from a file. It needs no D-Bus, no daemon
and no login session, so it also works headless and in containers.

```bash
export SHADI_KEYRING_PASSWORD_FILE=/path/to/keyring-password  # required
export SHADI_KEYRING_PATH=/path/to/agent_secrets.db           # optional
```

- `SHADI_KEYRING_PASSWORD_FILE` names a file holding the keyring password (a
  trailing newline is ignored). Without it the store is unavailable and every
  call returns `NotSupported`, as the no-op store did.
- `SHADI_KEYRING_PATH` defaults to `~/.shadi/keyring/agent_secrets.db`,
  outside the home directories the Compatibility sandbox profile grants
  (`~/.config`, `~/.local`, `~/.cache`).
- With the password file set, `SHADI_KEYRING_PASSWORD_FILE`,
  `SHADI_KEYRING_PATH` and `HOME` must be absolute paths; a relative one makes
  every call fail with `StorageFailure`. Without it nothing else is looked at,
  so a relative `HOME` alone still gives `NotSupported`.
- `secrets backend` in `shadictl shell` shows whether the keyring is
  configured and where its files are.
- Only key provisioning (`shadictl derive-agent-identity` and
  `derive-agent-did`) creates the keyring, through `creating_store()`. Until
  it exists, calls return `StoreNotFound`.
- The store counts as available whenever `SHADI_KEYRING_PASSWORD_FILE` is set,
  even where the files can't be read. The credential vault picks the keyring
  from that, in the sandbox as on the host; an agent whose sandbox denies the
  password file then fails to read its credentials instead of opening an empty
  SQLCipher vault. To keep the vault in SQLCipher, set
  `SHADI_CREDENTIAL_BACKEND=sqlcipher` for both.
- The password is checked whenever the keyring is opened, even with no keys
  in it. The password file must be UTF-8 without NUL bytes. An empty keyring
  file is never written to; remove it and provision again.
- Concurrent processes are ordered by SQLite's file locks. A write gives up
  after 10 seconds if another process holds the lock, and reports
  `StoreNotFound` if the keyring is removed or replaced meanwhile. Reads open
  the file read-only, so a keyring on a read-only mount can still be read;
  only rolling back an interrupted write needs write access.
- Every call opens the keyring and derives the key from the password (about
  80 ms); nothing stays unlocked between calls.
- If the keyring can't be decrypted, the error names both causes: a wrong
  password or a damaged file. Check the password file, and restore a damaged
  keyring from a backup rather than provisioning it again. SQLCipher prints
  its own `hmac check failed` lines on stderr before this message.
- The keyring directory must support hard links: new keyrings are written to a
  temporary file and linked into place.

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
