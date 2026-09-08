# SHADI and AgentBridge

[![Docs](https://github.com/agntcy/shadi/actions/workflows/docs-pages.yml/badge.svg?branch=main)](https://github.com/agntcy/shadi/actions/workflows/docs-pages.yml)
[![Docs Site](https://img.shields.io/badge/docs-agntcy.github.io%2Fshadi-blue)](https://agntcy.github.io/shadi)
[![codecov](https://codecov.io/gh/agntcy/shadi/branch/main/graph/badge.svg)](https://codecov.io/gh/agntcy/shadi)
[![CI](https://github.com/agntcy/shadi/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/agntcy/shadi/actions/workflows/ci.yml)
[![Crates](https://github.com/agntcy/shadi/actions/workflows/release-rust.yml/badge.svg?branch=main)](https://github.com/agntcy/shadi/actions/workflows/release-rust.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/agntcy/shadi/badge)](https://scorecard.dev/viewer/?uri=github.com/agntcy/shadi)

**SHADI** (Secure Host for Agentic AI Dynamic Instantiation) hardens *this*
machine. **AgentBridge** connects agents that may live on this host or on
other hosts.

SHADI is the local security boundary: identity verification, gated secret
access, OS-level sandboxing, encrypted local memory, and the SLIM node this
host admits. It does not control a remote agent's process, files, or
sandbox — only what runs here.

AgentBridge is the A2A interconnect across that gap. It wraps Claude Code,
Copilot, Codex, Cursor Agent, or any `CliAdapter` as a DID-signed listener
and talks to peers over SLIM, wherever they are registered. `list --local`
shows listeners on this host; `delegate`, `handoff`, and `coordinate` reach
a `slim://` peer on this machine or another.

## Why this repo

For teams that want a locked-down host for the agents they run locally, and
a way to pass work to agents that are not on that host.

- Verify who a local agent is before releasing secrets on this machine.
- Constrain what a local process can read, write, execute, and reach.
- Keep this host's memory encrypted at rest.
- Admit only authenticated SLIM peers onto this host's node.
- Reach agents on other hosts over A2A (`agentbridge`), not ad-hoc pipes.
- Audit local changes with snapshots and runtime inspection tools.

## What You Get

- [`shadictl`](https://agntcy.github.io/shadi/cli/#shadictl-shadi): the main CLI for policy, sandbox execution, identity, secrets, memory, and shell control.
- [`agentbridge`](https://agntcy.github.io/shadi/agentbridge/): the A2A interconnect across hosts — coding CLIs (Claude Code, Copilot, Codex, Cursor Agent) are the flagship peers.
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
cargo build
cargo test
cargo run -p shadi_demo_bot -- feature-bot
```

The demo bot runs a compact end-to-end check across secrets, memory, sandboxing, and local SLIM messaging.

## Learn More

- Start here: [Getting Started](https://agntcy.github.io/shadi/getting_started/)
- Agent interconnect: [AgentBridge](https://agntcy.github.io/shadi/agentbridge/)
- Token-passing coding demo: [Round-robin Rust](https://agntcy.github.io/shadi/demos/collab-rust/)
- System model: [Architecture](https://agntcy.github.io/shadi/architecture/)
- Security model: [Security Notes](https://agntcy.github.io/shadi/security/)
- CLI reference: [CLI Reference](https://agntcy.github.io/shadi/cli/)
- Sandbox and policy details: [Sandbox and Policies](https://agntcy.github.io/shadi/sandbox/)
- Shell and demo workflows: [examples/shell_demo/README.md](examples/shell_demo/README.md) and [examples/shadi_demo_bot/README.md](examples/shadi_demo_bot/README.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), and [SECURITY.md](SECURITY.md).

## License

See [LICENSE.md](LICENSE.md).
