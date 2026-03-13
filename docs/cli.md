# CLI Reference

This page documents the command-line tools shipped with SHADI:

- `shadictl` (binary name `shadi`): sandbox runner, key management, memory, and MAS helpers.

Most agents use the Python bindings (`shadi` module) for secrets, SQLCipher
memory, and sandbox execution. The CLI remains useful for ops and debugging.

## shadictl (`shadi`)

`shadictl` is the main CLI for running sandboxed commands, printing policy, and
managing OpenPGP keys and DIDs. In development, run it with:

```bash
cargo run -p shadictl -- [FLAGS] -- [COMMAND]
```

### Global flags

- `--policy FILE`: JSON policy file to load before flags are applied.
- `--allow PATH`: Allow read+write under PATH (can be repeated).
- `--read PATH`: Allow read-only access under PATH (can be repeated).
- `--write PATH`: Allow write access under PATH (can be repeated).
- `--net-block`: Block network access.
- `--allow-command CMD`: Allow a command that is blocked by default (repeatable).
- `--inject-keychain KEY=ENV`: Read a secret and inject it as an env var before launch (repeatable).
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

### Sandbox execution

Run a command inside the sandbox after flags:

```bash
cargo run -p shadictl -- \
  --allow . \
  --read / \
  --net-block \
  -- \
  ./your-agent --arg value
```

Print the effective policy after merging JSON and flags:

```bash
cargo run -p shadictl -- --policy ./sandbox.json --print-policy
```

Inject a secret into the command environment (brokered secrets):

```bash
cargo run -p shadictl -- \
  --inject-keychain app/config=APP_CONFIG \
  -- \
  ./your-agent
```

Capture a read-only Git snapshot around a sandboxed run:

```bash
cargo run -p shadictl -- \
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
cargo run -p shadictl -- \
  did-from-gpg \
  --in /path/to/human-public.asc \
  --out human.did.json
```

Fetch an OpenPGP key from GitHub and create a DID document:

```bash
cargo run -p shadictl -- \
  did-from-github \
  --user octocat \
  --out github.did.json
```

Store an OpenPGP secret key in the SHADI secret store:

```bash
cargo run -p shadictl -- \
  put-key \
  --key human/gpg \
  --in /path/to/human-secret.asc
```

Derive an agent DID and keypair from a human OpenPGP secret key:

```bash
cargo run -p shadictl -- \
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
cargo run -p shadictl -- \
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
cargo run -p shadictl -- \
  derive-agent-identity \
  --source seed \
  --human-secret human/seed \
  --name agent-c \
  --prefix agents
```

If you already store the human DID, bind derived identities to it:

```bash
cargo run -p shadictl -- \
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
cargo run -p shadictl -- \
  verify-agent-identity \
  --source gpg \
  --human-secret human/gpg \
  --name agent-a \
  --prefix agents
```

Require verification of stored human binding:

```bash
cargo run -p shadictl -- \
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
cargo run -p shadictl -- memory init \
  --db "${SHADI_TMP_DIR:-./.tmp}/shadi-memory.db" \
  --key-name shadi/memory/sqlcipher_key
```

Put a memory entry from inline payload or file:

```bash
cargo run -p shadictl -- memory put \
  --db "${SHADI_TMP_DIR:-./.tmp}/shadi-memory.db" \
  --key-name shadi/memory/sqlcipher_key \
  --scope app --entry-key state --payload '{"status":"ok"}'
```

```bash
cargo run -p shadictl -- memory put \
  --db "${SHADI_TMP_DIR:-./.tmp}/shadi-memory.db" \
  --key-name shadi/memory/sqlcipher_key \
  --scope app --entry-key state --payload-file ./state.json
```

Get the latest entry:

```bash
cargo run -p shadictl -- memory get \
  --db "${SHADI_TMP_DIR:-./.tmp}/shadi-memory.db" \
  --key-name shadi/memory/sqlcipher_key \
  --scope app --entry-key state
```

Search entries:

```bash
cargo run -p shadictl -- memory search \
  --db "${SHADI_TMP_DIR:-./.tmp}/shadi-memory.db" \
  --key-name shadi/memory/sqlcipher_key \
  --scope app --query policy --limit 10
```

List entries:

```bash
cargo run -p shadictl -- memory list \
  --db "${SHADI_TMP_DIR:-./.tmp}/shadi-memory.db" \
  --key-name shadi/memory/sqlcipher_key \
  --scope app --limit 50
```

Delete an entry:

```bash
cargo run -p shadictl -- memory delete \
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
cargo run -p shadictl -- slim-mas list-groups
```

List members for a group:

```bash
cargo run -p shadictl -- slim-mas list-members --group team-a
```

Validate config (ensures a default group exists):

```bash
cargo run -p shadictl -- slim-mas validate
```

Admit or deny a member:

```bash
cargo run -p shadictl -- slim-mas admit --group team-a --did did:key:human --role human
```

Exit codes:

- `0`: allow / success
- `3`: deny (member not allowed)
- `2`: error
