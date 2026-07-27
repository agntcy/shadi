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

- [`shadictl`](https://agntcy.github.io/shadi/cli/#shadictl-shadi): the main CLI for policy, sandbox execution, identity, secrets, memory, and shell control.
- [`shadi_sandbox`](https://agntcy.github.io/shadi/architecture/#2-sandbox-layer): OS-enforced sandbox policy.
- [`agent_secrets`](https://agntcy.github.io/shadi/architecture/#1-secrets-layer): keychain-backed secret storage and verification gates.
- [`shadi_memory`](https://agntcy.github.io/shadi/architecture/#3-memory-layer): SQLCipher-backed local memory.
- [`agent_transport_slim`](https://agntcy.github.io/shadi/architecture/#4-transport-layer): secure transport and stdio bridge support.
- [`examples/shadi_demo_bot`](examples/shadi_demo_bot/README.md): a Rust demo bot that exercises the main SHADI features, including SLIM messaging.

## Install the CLI

On Linux, install the latest released `shadictl` with:

```bash
curl -fsSL https://agntcy.github.io/shadi/install.sh | bash
```

For pinned versions, custom install paths, and installer environment overrides,
see [Install the CLI](https://agntcy.github.io/shadi/install/).

On macOS, you can install the latest released `shadictl` or `agentbridge`
formula with Homebrew:

```bash
brew tap agntcy/shadi https://github.com/agntcy/shadi
brew install agntcy/shadi/shadictl
brew install agntcy/shadi/agentbridge
```

On Windows, once the matching WinGet manifest has landed in the default source,
you can install or upgrade either CLI with:

```powershell
winget install --id AGNTCY.shadictl -e
winget install --id AGNTCY.agentbridge -e
winget upgrade --id AGNTCY.shadictl -e
winget upgrade --id AGNTCY.agentbridge -e
```

Each Homebrew formula builds from its own published release tag
(`agntcy-shadi-cli` for `shadictl`, `agntcy-agentbridge-cli` for `agentbridge`).
Both releases also include prebuilt archives for Linux (`x86_64` and
`aarch64`), macOS (`arm64` and `x86_64`), and Windows (`x86_64`).
For unreleased changes or any other host, use the source build flow below.

## Quick Start

```bash
cargo build --workspace
cargo test --workspace
cargo run -p shadi_demo_bot -- feature-bot
```

The demo bot runs a compact end-to-end check across secrets, memory, sandboxing, and local SLIM messaging.

## Learn More

- Start here: [Getting Started](https://agntcy.github.io/shadi/getting_started/)
- System model: [Architecture](https://agntcy.github.io/shadi/architecture/)
- Security model: [Security Notes](https://agntcy.github.io/shadi/security/)
- CLI reference: [CLI Reference](https://agntcy.github.io/shadi/cli/)
- Sandbox and policy details: [Sandbox and Policies](https://agntcy.github.io/shadi/sandbox/)
- Shell and demo workflows: [examples/shell_demo/README.md](examples/shell_demo/README.md) and [examples/shadi_demo_bot/README.md](examples/shadi_demo_bot/README.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), and [SECURITY.md](SECURITY.md).

## License

See [LICENSE.md](LICENSE.md).
