# SHADI

[![Docs](https://github.com/agntcy/shadi/actions/workflows/docs-pages.yml/badge.svg?branch=main)](https://github.com/agntcy/shadi/actions/workflows/docs-pages.yml)
[![Docs Site](https://img.shields.io/badge/docs-agntcy.github.io%2Fshadi-blue)](https://agntcy.github.io/shadi)
[![codecov](https://codecov.io/gh/agntcy/shadi/branch/main/graph/badge.svg)](https://codecov.io/gh/agntcy/shadi)
[![CI](https://github.com/agntcy/shadi/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/agntcy/shadi/actions/workflows/ci.yml)

Secure Host for Agentic AI Dynamic Instantiation (SHADI) is a secure host runtime for autonomous, multi-agent systems.

SHADI is designed for environments where agents are long-lived, hold real credentials, and run close to sensitive data. It combines identity verification, keychain-backed secrets, OS sandboxing, and encrypted local memory to reduce blast radius and make agent behavior auditable.

## What SHADI provides

- Verified secret access gates (`agent_secrets`) with OS keychain backends.
- Deterministic human -> agent identity derivation (`did:key`) and provenance verification.
- Kernel-enforced sandbox execution policies (`shadi_sandbox`) with portable profile defaults.
- Process-scoped secret delivery policy with exact executable matching, explicit disclosure paths, and trusted child-delivery on Unix/macOS.
- Opt-in Git-backed sandbox snapshots for before/after working-tree capture and audit trails.
- SQLCipher-backed encrypted local memory (`shadi_memory`).
- Python bindings (`shadi_py`) for secrets, memory, and sandboxed execution.
- SLIM transport integration for secure agent-to-agent messaging.
- Interactive shell (`shadictl shell`) for live attach/detach, policy inspection, and trace review.

## Repository layout

- `crates/shadictl`: main CLI (`shadi`) for policy, sandbox execution, key management, and identity derivation/verification.
- `crates/shadi_sandbox`: sandbox policy model and platform enforcement.
- `crates/agent_secrets`: keychain-backed secret storage + verification-gated access.
- `crates/shadi_memory`: SQLCipher memory library (accessed via `shadictl memory`).
- `crates/shadi_py`: Python extension module `shadi`.
- `crates/agent_transport_slim` + `crates/slim_mas`: secure transport, stdio bridge, and moderation helpers (with `shadictl slim-mas`).
- `docs`: architecture, security, CLI, and integration docs.
- `scripts`: local launch helpers for SLIM.
- `examples/shell_demo`: interactive shell demo walkthrough.

## Architecture at a glance

SHADI runtime flow:

1. Ingest human identity material (`gpg` secret material or generic seed).
2. Derive deterministic Ed25519 local keys and `did:key` identities per agent.
3. Optionally bind agent identities to a stored human DID and verify provenance.
4. Resolve sandbox and secret-delivery policy for the exact launched executable.
5. Gate secret access on verified sessions and deliver secrets through the allowed disclosure or trusted-delivery path.
6. Persist agent memory encrypted at rest.

Current secret-delivery modes:

- `--inject-keychain` and `process_inject_keychain`: explicit env disclosure to the launched process.
- `process_trusted_secret`: process-scoped direct trusted-secret delivery; on Unix/macOS this is a one-shot broker fetch with a nonce-bound endpoint, and on Windows it remains a compatibility handle path.
- `process_secret_policy`: action-based policy rules. `delegate-to-child` is implemented for Unix/macOS final-consumer delivery; `use` is modeled in policy for narrower future mediation patterns.

Platform presentation layers:

1. **Experience and control**: operators define profiles, policies, and launch intent.
2. **Secure runtime**: identity, secret control, trusted delivery, sandboxing, transport, and encrypted memory enforce the launch contract.
3. **Protected workloads**: agents and tools run inside the approved runtime boundary.
4. **External systems**: GitHub, model providers, and SLIM/A2A peers are reached only after policy and trust checks pass.

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

Use `just --list` or `just --groups` to browse tasks by area.

## SLIM stdio bridge

When SHADI owns node startup, channel creation, and participant invites, a sandboxed workload can still publish into a real SLIM session by piping stdout into the Rust bridge:

```bash
shadictl --policy ./sandbox.json -- /path/to/agent \
	| cargo run -p agent_transport_slim --bin slim-stdio-bridge -- \
			--channel agntcy/shadi/secops-room
```

Group mode waits for SHADI to invite the bridge into the named channel session; point-to-point mode is also available with `--destination organization/namespace/application`. The bridge reads UTF-8 lines from stdin and publishes each line as one SLIM message.

## Core CLI workflows

### 1) Print a baseline secure policy profile

```bash
cargo run -p shadictl -- --profile balanced --print-policy
```

Available built-in profiles:

- `strict`: local-only policy with network blocked
- `balanced`: practical local default with network blocked
- `connected`: balanced + network enabled

Inspect effective configuration and policy provenance:

```bash
cargo run -p shadictl -- config show --format json
cargo run -p shadictl -- policy explain --format json
cargo run -p shadictl -- policy diff --against profile:strict --format json
```

With explicit policy file and CLI overrides:

```bash
cargo run -p shadictl -- \
	config show \
	--profile connected \
	--policy ./sandbox.json \
	--allow . \
	--allow-command curl \
	--format json
```

Quickly inspect policy source attribution:

```bash
cargo run -q -p shadictl -- policy explain --policy ./sandbox.json --format json | jq '.sources'
```

### 2) Run a command in the sandbox

```bash
cargo run -p shadictl -- \
	--allow . \
	--read / \
	--net-block \
	-- \
	/usr/bin/env echo "hello from sandbox"
```

### 3) Capture a Git-backed sandbox snapshot

Use this when you want a stable artifact describing what a sandboxed command
changed inside a Git working tree:

```bash
cargo run -p shadictl -- \
	--allow . \
	--git-snapshot \
	--git-snapshot-untracked \
	-- \
	./your-agent
```

Artifacts are opt-in and written by default to
`${SHADI_TMP_DIR:-./.tmp}/git-snapshots`, with a stable layout:

- `runs/<artifact_id>/snapshot.json`: canonical per-run artifact
- `latest.json`: copy of the most recent snapshot

Each artifact includes resolved policy, timestamps, before/after Git state,
SHA-256 hashes for captured Git payloads, and comparison fields such as
`status_changed` and `overall_changed`.

If the workspace contains nested Git repos, the artifact also includes a
`git.repositories` array with per-repo before/after state and comparison
metadata. This is important for agent workflows where
the agent may clone or update another repo under the current working folder:
the outer repo can stay unchanged while the nested repo entry still reports the
change.

### 4) Derive agent identities from a human source

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

### 5) Verify agent provenance

```bash
cargo run -p shadictl -- \
	verify-agent-identity \
	--source gpg \
	--human-secret human/gpg \
	--name secops-a \
	--prefix agents
```

### 6) Use encrypted memory through `shadictl`

```bash
cargo run -p shadictl -- memory init \
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

## Documentation

Primary docs live in `docs/`:

- `docs/index.md`: project overview
- `docs/architecture.md`: runtime and control planes
- `docs/security.md`: threat model and security notes
- `docs/cli.md`: complete CLI reference
- `docs/sandbox.md`: policy model and profile behavior
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
