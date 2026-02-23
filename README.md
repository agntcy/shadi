# SHADI

Secure Host for Agentic AI Dynamic Instantiation (SHADI) is a secure host runtime for autonomous, multi-agent systems.

SHADI is designed for environments where agents are long-lived, hold real credentials, and run close to sensitive data. It combines identity verification, keychain-backed secrets, OS sandboxing, and encrypted local memory to reduce blast radius and make agent behavior auditable.

## What SHADI provides

- Verified secret access gates (`agent_secrets`) with OS keychain backends.
- Deterministic human -> agent identity derivation (`did:key`) and provenance verification.
- Kernel-enforced sandbox execution policies (`shadi_sandbox`) with portable profile defaults.
- SQLCipher-backed encrypted local memory (`shadi_memory`).
- Python bindings (`shadi_py`) for secrets, memory, and sandboxed execution.
- SLIM transport integration for secure agent-to-agent messaging.
- A practical SecOps agent demo and launch scripts.

## Repository layout

- `crates/shadictl`: main CLI (`shadi`) for policy, sandbox execution, key management, and identity derivation/verification.
- `crates/shadi_sandbox`: sandbox policy model and platform enforcement.
- `crates/agent_secrets`: keychain-backed secret storage + verification-gated access.
- `crates/shadi_memory`: SQLCipher memory library and CLI (`shadi-memory`).
- `crates/shadi_py`: Python extension module `shadi`.
- `crates/agent_transport_slim` + `crates/slim_mas`: secure transport and moderation helpers.
- `agents/secops`: SecOps agent, A2A server, and skill implementation.
- `docs`: architecture, security, CLI, demos, and integration docs.
- `scripts`: local launch helpers for SLIM + agent demos.

## Architecture at a glance

SHADI runtime flow:

1. Ingest human identity material (`gpg` secret material or generic seed).
2. Derive deterministic Ed25519 local keys and `did:key` identities per agent.
3. Optionally bind agent identities to a stored human DID and verify provenance.
4. Apply sandbox policy (filesystem/network/command controls).
5. Gate secret access on verified sessions.
6. Persist agent memory encrypted at rest.

For full details, see `docs/architecture.md` and `docs/security.md`.

## Prerequisites

- Rust toolchain (stable) with Cargo
- Python 3.12 (for `shadi_py` and Python demos)
- `just` (recommended task runner)
- Optional for docs: `mkdocs` (and related theme/plugins used by this repo)

## Quick start

Build all crates:

```bash
cargo build --workspace
```

Run all tests:

```bash
cargo test --workspace
```

If you use `just`, common tasks are available:

```bash
just build
just test
just lint
```

## Core CLI workflows

### 1) Print a baseline secure policy profile

```bash
cargo run -p shadictl -- --profile balanced --print-policy
```

Available built-in profiles:

- `strict`: local-only policy with network blocked
- `balanced`: practical local default with network blocked
- `connected`: balanced + network enabled

### 2) Run a command in the sandbox

```bash
cargo run -p shadictl -- \
	--allow . \
	--read / \
	--net-block \
	-- \
	/usr/bin/env echo "hello from sandbox"
```

### 3) Derive agent identities from a human source

```bash
cargo run -p shadictl -- \
	derive-agent-identity \
	--source gpg \
	--human-secret human/gpg \
	--name secops-a \
	--name avatar-1 \
	--prefix agents \
	--out-dir ./agent-dids
```

### 4) Verify agent provenance

```bash
cargo run -p shadictl -- \
	verify-agent-identity \
	--source gpg \
	--human-secret human/gpg \
	--name secops-a \
	--prefix agents
```

### 5) Use encrypted memory through `shadictl`

```bash
cargo run -p shadictl -- -- memory init \
	--db "${SHADI_TMP_DIR:-./.tmp}/shadi-memory.db" \
	--key-name shadi/memory/sqlcipher_key
```

## Python module (`shadi_py`)

Build the Python extension crate:

```bash
cargo build -p shadi_py
```

The module exposes bindings for:

- secret store operations and session verification hooks
- SQLCipher memory operations
- sandbox policy handles and sandboxed process execution

## SecOps demo and launch scripts

The repo includes runnable examples under `agents/secops` and helper scripts in `scripts/`.

Common local flow:

```bash
./scripts/launch_slim.sh
./scripts/import_secops_secrets.sh
./scripts/launch_secops_a2a.sh
./scripts/launch_avatar.sh
```

See `scripts/README.md` and `docs/demo.md` for full setup details.

## Documentation

Primary docs live in `docs/`:

- `docs/index.md`: project overview
- `docs/architecture.md`: runtime and control planes
- `docs/security.md`: threat model and security notes
- `docs/cli.md`: complete CLI reference
- `docs/sandbox.md`: policy model and profile behavior
- `docs/demo.md`: demo walkthrough

Build/serve docs locally:

```bash
mkdocs build
mkdocs serve
```

## Development notes

- Keep changes focused and platform-safe (macOS, Windows, Linux where applicable).
- Prefer policy/profile-based secure defaults instead of ad-hoc shell wrappers.
- Use deterministic identity derivation and `verify-agent-identity` for provenance checks.
- Run `cargo test --workspace` before opening a PR.

## Contributing

See:

- `CONTRIBUTING.md`
- `CODE_OF_CONDUCT.md`
- `SECURITY.md`

## License

See `LICENSE.md`.
