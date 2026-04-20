# SHADI

[![Docs](https://github.com/agntcy/shadi/actions/workflows/docs-pages.yml/badge.svg?branch=main)](https://github.com/agntcy/shadi/actions/workflows/docs-pages.yml)
[![Docs Site](https://img.shields.io/badge/docs-agntcy.github.io%2Fshadi-blue)](https://agntcy.github.io/shadi)
[![codecov](https://codecov.io/gh/agntcy/shadi/branch/main/graph/badge.svg)](https://codecov.io/gh/agntcy/shadi)
[![CI](https://github.com/agntcy/shadi/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/agntcy/shadi/actions/workflows/ci.yml)
[![Crates](https://github.com/agntcy/shadi/actions/workflows/release-rust.yml/badge.svg?branch=main)](https://github.com/agntcy/shadi/actions/workflows/release-rust.yml)

Secure Host for Agentic AI Dynamic Instantiation (SHADI) is a secure runtime for AI agents.

It gives agents a safer place to run by combining identity verification, gated secret access, OS-level sandboxing, encrypted local memory, and secure messaging.

## Why SHADI

SHADI is for teams that want agents to work with real tools and real credentials without treating the host machine as a fully trusted environment.

- Verify who an agent is before releasing secrets.
- Constrain what a process can read, write, execute, and reach on the network.
- Keep local memory encrypted at rest.
- Connect agents over authenticated SLIM messaging.
- Audit changes with snapshots and runtime inspection tools.

## What You Get

- [`shadictl`](docs/cli.md#shadictl-shadi): the main CLI for policy, sandbox execution, identity, secrets, memory, and shell control.
- [`shadi_sandbox`](docs/architecture.md#2-sandbox-layer): OS-enforced sandbox policy.
- [`agent_secrets`](docs/architecture.md#1-secrets-layer): keychain-backed secret storage and verification gates.
- [`shadi_memory`](docs/architecture.md#3-memory-layer): SQLCipher-backed local memory.
- [`agent_transport_slim`](docs/architecture.md#4-transport-layer): secure transport and stdio bridge support.
- [`examples/shadi_demo_bot`](examples/shadi_demo_bot/README.md): a Rust demo bot that exercises the main SHADI features, including SLIM messaging.

## Install the CLI

On macOS, you can install the latest released `shadictl` formula with Homebrew:

```bash
brew tap agntcy/shadi https://github.com/agntcy/shadi
brew install agntcy/shadi/shadictl
```

On Windows, once the matching WinGet manifest has landed in the default source,
you can install or upgrade `shadictl` with:

```powershell
winget install --id AGNTCY.shadictl -e
winget upgrade --id AGNTCY.shadictl -e
```

The Homebrew formula builds from the published `agntcy-shadi-cli` release tag.
Published `agntcy-shadi-cli` releases also include prebuilt archives for Linux
(`x86_64` and `aarch64`), macOS (`arm64` and `x86_64`), and Windows (`x86_64`).
For unreleased changes or any other host, use the source build flow below.

## Quick Start

```bash
cargo build --workspace
cargo test --workspace
cargo run -p shadi_demo_bot -- feature-bot
```

The demo bot runs a compact end-to-end check across secrets, memory, sandboxing, and local SLIM messaging.

## Learn More

- Start here: [docs/getting_started.md](docs/getting_started.md)
- System model: [docs/architecture.md](docs/architecture.md)
- Security model: [docs/security.md](docs/security.md)
- CLI reference: [docs/cli.md](docs/cli.md)
- Sandbox and policy details: [docs/sandbox.md](docs/sandbox.md)
- Shell and demo workflows: [examples/shell_demo/README.md](examples/shell_demo/README.md) and [examples/shadi_demo_bot/README.md](examples/shadi_demo_bot/README.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), and [SECURITY.md](SECURITY.md).

## License

See [LICENSE.md](LICENSE.md).
