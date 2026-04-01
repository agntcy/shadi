# SHADI

[![Docs](https://github.com/agntcy/shadi/actions/workflows/docs-pages.yml/badge.svg?branch=main)](https://github.com/agntcy/shadi/actions/workflows/docs-pages.yml)
[![Docs Site](https://img.shields.io/badge/docs-agntcy.github.io%2Fshadi-blue)](https://agntcy.github.io/shadi)
[![codecov](https://codecov.io/gh/agntcy/shadi/branch/main/graph/badge.svg)](https://codecov.io/gh/agntcy/shadi)
[![CI](https://github.com/agntcy/shadi/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/agntcy/shadi/actions/workflows/ci.yml)

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

- `shadictl`: the main CLI for policy, sandbox execution, identity, secrets, memory, and shell control.
- `shadi_sandbox`: OS-enforced sandbox policy.
- `agent_secrets`: keychain-backed secret storage and verification gates.
- `shadi_memory`: SQLCipher-backed local memory.
- `agent_transport_slim`: secure transport and stdio bridge support.
- `examples/shadi_demo_bot`: a Rust demo bot that exercises the main SHADI features, including SLIM messaging.

## Quick Start

```bash
cargo build --workspace
cargo test --workspace
cargo run -p shadi_demo_bot -- feature-bot
```

The demo bot runs a compact end-to-end check across secrets, memory, sandboxing, and local SLIM messaging.

## Learn More

- Start here: `docs/getting_started.md`
- System model: `docs/architecture.md`
- Security model: `docs/security.md`
- CLI reference: `docs/cli.md`
- Sandbox and policy details: `docs/sandbox.md`
- Shell and demo workflows: `examples/shell_demo/README.md` and `examples/shadi_demo_bot/README.md`

## Contributing

See `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, and `SECURITY.md`.

## License

See `LICENSE.md`.
