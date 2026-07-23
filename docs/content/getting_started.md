# Getting Started

This guide is the fastest path from a fresh checkout to a working SHADI run.
It focuses on one outcome: confirm that the workspace builds, the sandbox
launcher works, and the runtime is ready for a real agent workflow.

## Overview

By the end of this guide, you will have:

- built the workspace
- inspected the effective sandbox policy
- run a command through `shadictl`
- prepared the identity and secret flow used by the rest of the docs

## Before You Begin

If you only need the released CLI on Linux, install it with the hosted bash
installer:

```bash
curl -fsSL https://agntcy.github.io/shadi/install.sh | bash
```

For version pinning or install path overrides, see [Install the CLI](install.md).

If you only need the released CLI on macOS, install it with Homebrew:

```bash
brew tap agntcy/shadi https://github.com/agntcy/shadi
brew install agntcy/shadi/shadictl
```

Use the source-build path below if you are developing SHADI or need unreleased
changes from the workspace.

Install the local tooling SHADI expects:

- Rust stable with Cargo
- Python 3.12
- `uv` for Python workflows
- `just` for the common repo tasks
- `mkdocs` if you want to preview the docs site locally

!!! note

  If you only want to validate the launcher and CLI path, you do not need to
  configure the full SecOps demo yet. That comes later in [Operations](operations.md).

## Build the Workspace

Build the workspace with either Cargo directly or the repo task runner.

=== "Cargo"

  ```bash
  cargo build --workspace
  ```

=== "Just"

  ```bash
  just build
  ```

## Inspect the Launcher Policy

SHADI resolves sandbox policy before process start. That is the key runtime
property to keep in mind while reading the rest of the documentation.

```bash
cargo run -p agntcy-shadi-cli -- --profile balanced --print-policy
```

Use these defaults as your baseline:

- `strict`: local workspace only, network blocked
- `balanced`: workspace access, network blocked (on macOS/Linux, the minimal
  platform profile supplies only the runtime reads needed to start common
  tooling — no implicit root read allowlist)
- `connected`: balanced plus network access

!!! info

  For the full policy model, profile merge rules, and platform-specific
  behavior, continue to [Sandbox and Policies](sandbox.md).

## Run Your First Sandboxed Command

Launch a trivial command with explicit local access:

```bash
cargo run -p agntcy-shadi-cli -- \
  --allow . \
  --read / \
  --net-block \
  -- \
  /usr/bin/env echo "hello from shadi"
```

This confirms three things:

- the CLI is resolving policy correctly
- the sandbox launcher is functional on your host
- the runtime path is ready for a real agent command

## Understand Secret Delivery Policy

SHADI now resolves secret-delivery policy at launch time in addition to the
filesystem and network sandbox.

The current secret-delivery model has three distinct paths:

- `--inject-keychain` and `process_inject_keychain`: explicit env disclosure to the launched process.
- `process_trusted_secret`: process-scoped trusted delivery to the launched process.
- `process_secret_policy`: action-based rules such as `delegate-to-child`, where SHADI delivers the secret directly to a verified child tool on Unix/macOS without disclosing it to the parent.

For the full model, including exact-program matching, nonce-bound trusted-secret
protocols, and policy-file examples, continue to [Sandbox and Policies](sandbox.md)
and [CLI Reference](cli.md).

## Prepare Identity and Secrets

SHADI is most useful when the runtime can derive agent identity and gate secret
access on verified sessions.

=== "Store Human Identity Material"

    ```bash
    cargo run -p agntcy-shadi-cli -- \
      put-key --key human/gpg --in /path/to/human-secret.asc
    ```

=== "Derive an Agent Identity"

    ```bash
    cargo run -p agntcy-shadi-cli -- \
      derive-agent-identity \
      --source gpg \
      --human-secret human/gpg \
      --name agent-a \
      --prefix agents
    ```

!!! note

    If you need the full identity lifecycle, DID verification flow, or Python
    integration surface, continue to [API Guide](api_integration.md).

## Next Steps

After the first successful sandboxed command, choose the track that matches your goal.

- Run the end-to-end local demo: [Operations](operations.md)
- Integrate SHADI into an agent or app: [API Guide](api_integration.md)
- Review the system model before deploying: [Architecture](architecture.md)

## Recommended Reading Order

If you want a practical progression through the docs, use this sequence:

1. [Getting Started](getting_started.md)
2. [Sandbox and Policies](sandbox.md)
3. [Operations](operations.md)
4. [Security Notes](security.md)
5. [CLI Reference](cli.md)