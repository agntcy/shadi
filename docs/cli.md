# CLI Reference

This page documents the command-line tools shipped with SHADI:

- `shadictl` (binary name `shadi`): sandbox runner, key management, memory, and MAS helpers.

Most agents use the Python bindings (`shadi` module) for secrets, SQLCipher
memory, and sandbox execution. The CLI remains useful for ops and debugging.

## shadictl (`shadi`)

`shadictl` is the main CLI for running sandboxed commands, printing policy, and
managing OpenPGP keys and DIDs. In development, run it with:

```bash
cargo run -p agntcy-shadi-cli -- [FLAGS] -- [COMMAND]
```

### Global flags

- `--policy FILE`: JSON policy file to load before flags are applied.
- `--allow PATH`: Allow read+write under PATH (can be repeated).
- `--read PATH`: Allow read-only access under PATH (can be repeated).
- `--write PATH`: Allow write access under PATH (can be repeated).
- `--net-block`: Block network access.
- `--allow-command CMD`: Allow a command that is blocked by default (repeatable).
- `--inject-keychain KEY=ENV`: Read a secret and inject it as an env var before launch (repeatable).
- `--trusted-secret KEY=NAME`: Configure a direct trusted-secret delivery mapping (advanced compatibility/testing path).
- `--trusted-secret-exec NAME=PROGRAM`: Bind a trusted-secret mapping to an exact executable path.
- `--trusted-secret-fd-env NAME=ENV`: Set the endpoint env name for a trusted-secret mapping.
- `--list-keychain`: List secrets in the SHADI store.
- `--list-prefix PREFIX`: Optional prefix filter for `--list-keychain`.
- `--print-policy`: Print the resolved policy and exit.
- `--git-snapshot`: Capture Git state before and after the sandboxed run.
- `--git-snapshot-dir DIR`: Write snapshot artifacts under DIR instead of `${SHADI_TMP_DIR:-./.tmp}/git-snapshots`.
- `--git-snapshot-untracked`: Include an explicit untracked-file inventory in the snapshot artifact.

### Secret backend selection

By default `shadictl` uses the OS keychain. To use 1Password instead, set:

| Env var | Description | Default |
|---------|-------------|---------|
| `SHADI_SECRET_BACKEND` | Backend selection (`onepassword` or `keychain`) | `keychain` |
| `SHADI_OP_VAULT` | 1Password vault name | `shadi` |
| `SHADI_OP_ACCOUNT` | 1Password account (for multi-account setups) | auto |

The 1Password backend requires the `op` CLI to be installed and authenticated.
For CI, export `OP_SERVICE_ACCOUNT_TOKEN`.

### Config and policy introspection

Inspect effective runtime config (profile, policy source, backend metadata, and
effective policy):

```bash
cargo run -p agntcy-shadi-cli -- config show --format json
```

Explain resolved policy with source inputs (profile defaults, policy file, and
CLI overrides):

```bash
cargo run -p agntcy-shadi-cli -- policy explain --format json
```

Diff effective policy against a baseline profile:

```bash
cargo run -p agntcy-shadi-cli -- policy diff --against profile:strict --format json
```

Diff effective policy against another policy file:

```bash
cargo run -p agntcy-shadi-cli -- policy diff --against file:./sandbox.json --format json
```

Supported formats for these commands: `json` (default) and `text`.

#### Practical examples

Show effective config with explicit overrides:

```bash
cargo run -p agntcy-shadi-cli -- \
  config show \
  --profile connected \
  --policy ./sandbox.json \
  --allow . \
  --read /tmp \
  --allow-command curl \
  --format json
```

Expected JSON fields include:

```json
{
  "profile": "connected",
  "policy_file": "./sandbox.json",
  "secret_backend": {
    "selected": "keychain"
  },
  "overrides": {
    "allow_command": ["curl"]
  },
  "effective_policy": {
    "net_block": false
  }
}
```

Explain policy source inputs and inspect only the source section:

```bash
cargo run -p agntcy-shadi-cli -- \
  policy explain \
  --profile balanced \
  --policy ./sandbox.json \
  --allow . \
  --format json
```

```bash
cargo run -q -p agntcy-shadi-cli -- \
  policy explain --policy ./sandbox.json --format json \
  | jq '.sources'
```

Diff current effective policy against a baseline policy file:

```bash
cargo run -p agntcy-shadi-cli -- \
  policy diff \
  --policy ./sandbox.json \
  --allow . \
  --against file:./policies/demo/secops-a.json \
  --format json
```

Inspect only changed fields from the diff payload:

```bash
cargo run -q -p agntcy-shadi-cli -- \
  policy diff --against profile:strict --format json \
  | jq '.diff.changed_fields'
```

Invalid baseline targets return exit code `2` with an error message. Accepted
`--against` values are:

- `profile:strict`
- `profile:balanced`
- `profile:connected`
- `file:<path>`

### Sandbox execution

Run a command inside the sandbox after flags:

```bash
cargo run -p agntcy-shadi-cli -- \
  --allow . \
  --read / \
  --net-block \
  -- \
  ./your-agent --arg value
```

Print the effective policy after merging JSON and flags:

```bash
cargo run -p agntcy-shadi-cli -- --policy ./sandbox.json --print-policy
```

On macOS, the built-in `balanced` and `connected` profiles no longer imply a
root read allowlist. Their resolved policy uses the minimal platform profile by
default, and `--print-policy` / `config show` / `policy explain` now surface
that as `platform_profile: "minimal"`.

Policy files can scope secrets to exact launched executables instead of
treating them as ambient runtime configuration. The current secret policy
framework has three rule types:

- `process_inject_keychain`: array of `{ "program", "key", "env" }`
- `process_trusted_secret`: array of `{ "program", "key", "name", "fd_env", "exec_sha256?" }`
- `process_secret_policy`: array of `{ "program", "secret", "actions", ... }`

Example:

```json
{
  "allow": ["."],
  "process_inject_keychain": [
    {
      "program": "/Users/example/bin/secops-agent",
      "key": "secops/api-token",
      "env": "SECOPS_TOKEN"
    }
  ],
  "process_trusted_secret": [
    {
      "program": "/Users/example/bin/avatar-agent",
      "key": "avatar/session-key",
      "name": "avatar-session",
      "fd_env": "AVATAR_SESSION_FD",
      "exec_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }
  ],
  "process_secret_policy": [
    {
      "program": "/Users/example/bin/secops-agent",
      "secret": "secops/github_token",
      "actions": ["delegate-to-child"],
      "children": ["/usr/bin/curl"],
      "child_sha256": ["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"],
      "name": "github-token",
      "fd_env": "GITHUB_TOKEN_FD"
    }
  ]
}
```

These rules are matched against the exact resolved executable path for the
launched command. Unmatched rules are ignored for that run.

Meaning of the rule types:

- `process_inject_keychain`: explicit env disclosure to the launched process.
- `process_trusted_secret`: process-scoped direct trusted-secret delivery to the launched process.
- `process_secret_policy`: action-based delivery semantics. On Unix/macOS, `delegate-to-child` is implemented as final-consumer delivery to a verified child process without disclosing the secret to the parent.

For `process_trusted_secret`, the `fd_env` field is now a protocol-specific
endpoint environment variable rather than a hard promise that the value is a raw
file descriptor. On Unix/macOS the current protocol is a parent-mediated one-shot
fetch flow bound to the launched process identity, so the direct child can fetch
the secret but a later exec into a different executable does not retain that
fetch capability.

`process_trusted_secret` now also supports optional `exec_sha256` pinning. When
present, SHADI hashes the resolved launched executable and rejects the launch if
the digest does not match. This adds a second trust check beyond path matching
for direct trusted-secret delivery (including Windows compatibility mode).

For `process_secret_policy`, delegated child delivery on Unix/macOS adds two
important checks beyond executable-path matching:

- SHADI can require an optional `child_sha256` per authorized child executable.
- the child must present the launch-scoped nonce exposed via `<fd_env>_NONCE`
  before the broker releases the secret.

Current platform notes:

- Unix/macOS: `process_trusted_secret` and `delegate-to-child` use a one-shot broker endpoint with process verification and nonce binding.
- Windows: direct trusted-secret delivery currently uses a compatibility handle protocol (`consume-close-v1`).

Inject a secret into the command environment (explicit disclosure mode):

```bash
cargo run -p agntcy-shadi-cli -- \
  --inject-keychain app/config=APP_CONFIG \
  -- \
  ./your-agent
```

Low-level trusted-secret flags are also available for testing or explicit
compatibility wiring when you are not using a JSON policy file:

```bash
cargo run -p agntcy-shadi-cli -- \
  --trusted-secret secops/github_token=github-token \
  --trusted-secret-exec github-token=/usr/bin/curl \
  --trusted-secret-fd-env github-token=GITHUB_TOKEN_FD \
  -- \
  /usr/bin/curl https://api.github.com/
```

Capture a read-only Git snapshot around a sandboxed run:

```bash
cargo run -p agntcy-shadi-cli -- \
  --allow . \
  --git-snapshot \
  --git-snapshot-untracked \
  -- \
  ./your-agent
```

When enabled, `shadictl` checks whether the working directory is inside a Git
repository and writes a JSON artifact with command metadata, resolved policy,
timestamps, `HEAD`, `git status --porcelain`, `git diff --binary`, and optional
untracked inventory. By default artifacts are written to
`${SHADI_TMP_DIR:-./.tmp}/git-snapshots`.

If the working tree contains nested Git repositories, the snapshot artifact now
records them separately under `git.repositories`. The top-level `git.before`,
`git.after`, and `git.comparison` fields remain pinned to the primary repo at
the sandbox working directory for backward compatibility, while
`git.changed_repositories` and `git.any_repo_changed` summarize whether any
tracked repo changed during the sandboxed run.

The layout is stable for downstream tooling:

- `${SHADI_TMP_DIR:-./.tmp}/git-snapshots/runs/<artifact_id>/snapshot.json`: canonical per-run artifact.
- `${SHADI_TMP_DIR:-./.tmp}/git-snapshots/latest.json`: copy of the most recent snapshot.

Each repo state in the artifact now includes SHA-256 hashes for `HEAD`, the
porcelain status payload, the raw binary diff payload, optional untracked
inventory, and a combined state hash. The artifact also includes a comparison
section with `head_changed`, `status_changed`, `diff_changed`,
`untracked_changed`, and `overall_changed` so other systems can tell whether
the sandboxed command changed the working tree without reprocessing Git output.

For nested repos, each entry under `git.repositories` includes:

- `repo_root`: absolute path to the tracked repo root.
- `relative_path`: path relative to the sandbox working directory (`.` for the primary repo).
- `before` and `after` Git state for that specific repo.
- `diff_summary` and `comparison` for that repo.

This matters for agent workflows that operate on multiple repositories from one
workspace, such as a SecOps agent cloning or updating remediation targets under
its current working folder. A nested repo commit can leave the outer repo
unchanged while still appearing as `head_changed: true` and
`overall_changed: true` on that nested repo entry.

### Key, DID, and identity provenance

#### Cryptographic derivation model

Agent identities are deterministically derived from human identity material using
an HKDF-based pipeline:

- KDF: `HKDF-SHA256`
- Salt: `"shadi-agent-derive"`
- Input keying material (IKM): bytes from the selected human identity source
  (`gpg` secret material or `seed` bytes)
- Info: `agent_name` bytes
- Output key bytes: 32-byte Ed25519 private key seed

The derived Ed25519 public key is converted into a `did:key` DID document.
This is the same derivation path used by `derive-agent-did` and
`derive-agent-identity`.

Create a DID document from an OpenPGP public key file:

```bash
cargo run -p agntcy-shadi-cli -- \
  did-from-gpg \
  --in /path/to/human-public.asc \
  --out human.did.json
```

Fetch an OpenPGP key from GitHub and create a DID document:

```bash
cargo run -p agntcy-shadi-cli -- \
  did-from-github \
  --user octocat \
  --out github.did.json
```

Store an OpenPGP secret key in the SHADI secret store:

```bash
cargo run -p agntcy-shadi-cli -- \
  put-key \
  --key human/gpg \
  --in /path/to/human-secret.asc
```

Derive an agent DID and keypair from a human OpenPGP secret key:

```bash
cargo run -p agntcy-shadi-cli -- \
  derive-agent-did \
  --secret human/gpg \
  --name agent-a \
  --prefix agents \
  --out agent-a.did.json
```

Automate identity creation for one or more agents from a human identity source
(`gpg` or generic `seed`) using the same deterministic local-key to `did:key`
derivation pipeline:

```bash
cargo run -p agntcy-shadi-cli -- \
  derive-agent-identity \
  --source gpg \
  --human-secret human/gpg \
  --name agent-a \
  --name agent-b \
  --prefix agents \
  --out-dir ./agent-dids
```

For non-GPG identities, store source material in SHADI and use `--source seed`:

```bash
cargo run -p agntcy-shadi-cli -- \
  derive-agent-identity \
  --source seed \
  --human-secret human/seed \
  --name agent-c \
  --prefix agents
```

If you already store the human DID, bind derived identities to it:

```bash
cargo run -p agntcy-shadi-cli -- \
  derive-agent-identity \
  --source gpg \
  --human-secret human/gpg \
  --human-did-key humans/alice/did \
  --name agent-a \
  --prefix agents
```

Verify that a stored agent identity belongs to a human source by recomputing
the key and DID from the same derivation pipeline:

```bash
cargo run -p agntcy-shadi-cli -- \
  verify-agent-identity \
  --source gpg \
  --human-secret human/gpg \
  --name agent-a \
  --prefix agents
```

Require verification of stored human binding:

```bash
cargo run -p agntcy-shadi-cli -- \
  verify-agent-identity \
  --source gpg \
  --human-secret human/gpg \
  --name agent-a \
  --prefix agents \
  --human-did-key humans/alice/did \
  --require-human-binding
```

Avoid printing secret values. Use `--list-keychain` for inventory and pass key
names to commands that resolve secrets inside SHADI.

### Key storage layout

`derive-agent-did` writes the following entries under the prefix:

- `{prefix}/{agent}/private` (base64-encoded Ed25519 private key)
- `{prefix}/{agent}/public` (base64-encoded Ed25519 public key)
- `{prefix}/{agent}/did` (DID string)
- `{prefix}/{agent}/diddoc` (DID document JSON)

`derive-agent-identity` writes the same entries for each `--name` and also
stores `{prefix}/{agent}/human_did` when `--human-did-key` is provided.

## shadictl memory (`shadictl memory`)

`shadictl memory` proxies SQLCipher memory access while resolving the key from
the SHADI secret store (no key material is printed).

### Commands

Initialize a store:

```bash
cargo run -p agntcy-shadi-cli -- memory init \
  --db "${SHADI_TMP_DIR:-./.tmp}/shadi-memory.db" \
  --key-name shadi/memory/sqlcipher_key
```

Put a memory entry from inline payload or file:

```bash
cargo run -p agntcy-shadi-cli -- memory put \
  --db "${SHADI_TMP_DIR:-./.tmp}/shadi-memory.db" \
  --key-name shadi/memory/sqlcipher_key \
  --scope app --entry-key state --payload '{"status":"ok"}'
```

```bash
cargo run -p agntcy-shadi-cli -- memory put \
  --db "${SHADI_TMP_DIR:-./.tmp}/shadi-memory.db" \
  --key-name shadi/memory/sqlcipher_key \
  --scope app --entry-key state --payload-file ./state.json
```

Get the latest entry:

```bash
cargo run -p agntcy-shadi-cli -- memory get \
  --db "${SHADI_TMP_DIR:-./.tmp}/shadi-memory.db" \
  --key-name shadi/memory/sqlcipher_key \
  --scope app --entry-key state
```

Search entries:

```bash
cargo run -p agntcy-shadi-cli -- memory search \
  --db "${SHADI_TMP_DIR:-./.tmp}/shadi-memory.db" \
  --key-name shadi/memory/sqlcipher_key \
  --scope app --query policy --limit 10
```

List entries:

```bash
cargo run -p agntcy-shadi-cli -- memory list \
  --db "${SHADI_TMP_DIR:-./.tmp}/shadi-memory.db" \
  --key-name shadi/memory/sqlcipher_key \
  --scope app --limit 50
```

Delete an entry:

```bash
cargo run -p agntcy-shadi-cli -- memory delete \
  --db "${SHADI_TMP_DIR:-./.tmp}/shadi-memory.db" \
  --key-name shadi/memory/sqlcipher_key \
  --scope app --entry-key state
```

## shadictl slim-mas (`shadictl slim-mas`)

`shadictl slim-mas` evaluates SLIM multi-agent membership rules from a TOML config.

### Global flags

- `--config FILE`: Path to the MAS config (default `mas.toml`).

### Commands

List available groups:

```bash
cargo run -p agntcy-shadi-cli -- slim-mas list-groups
```

List members for a group:

```bash
cargo run -p agntcy-shadi-cli -- slim-mas list-members --group team-a
```

Validate config (ensures a default group exists):

```bash
cargo run -p agntcy-shadi-cli -- slim-mas validate
```

Admit or deny a member:

```bash
cargo run -p agntcy-shadi-cli -- slim-mas admit --group team-a --did did:key:human --role human
```

Exit codes:

- `0`: allow / success
- `3`: deny (member not allowed)
- `2`: error
