# SHADI Rust Demo Bot

This example keeps the interactive shell walkthrough simple while adding a real
Rust bot that exercises the main SHADI libraries directly.

It has three roles behind one binary:

- `feature-bot`: runs a full self-check across secrets, memory, sandboxing, and SLIM messaging
- `shell-ticker`: tiny long-running ticker for the shell walkthrough
- `slim-echo-peer`: helper used by the feature bot for the local SLIM echo flow

## Build

```bash
cargo build -p shadi_demo_bot
```

## Run The Full Feature Check

```bash
cargo run -p shadi_demo_bot -- feature-bot
```

On macOS and Linux this will:

- verify session-gated secret access with `agent_secrets`
- write, search, list, and delete an encrypted memory entry with `shadi_memory`
- spawn a sandboxed child probe with `shadi_sandbox` and confirm blocked reads plus blocked network
- generate local SLIM demo certs if needed, start a local echo peer, and exchange a point-to-point message with `agent_transport_slim`

If you only want the non-SLIM checks:

```bash
cargo run -p shadi_demo_bot -- feature-bot --no-slim
```

## Use The Rust Shell Ticker

Standalone:

```bash
cargo run -p shadi_demo_bot -- shell-ticker
```

Under `shadictl shell` / policy-watch flow:

```bash
cargo build -p shadi_demo_bot
cargo run -p agntcy-shadi-cli -- \
    --policy examples/shell_demo/policy.json \
    --watch-policy \
    -- ./target/debug/shadi_demo_bot shell-ticker
```

The existing bash demo in `examples/shell_demo/demo_agent.sh` remains the best
walkthrough for live policy patching because it visibly hits blocked command,
network, and file-read paths on every tick.