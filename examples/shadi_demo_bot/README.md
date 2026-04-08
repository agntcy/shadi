# SHADI Rust Demo Bot

This example keeps the interactive shell walkthrough simple while adding a real
Rust bot that exercises the main SHADI libraries directly.

It has three roles behind one binary:

- `feature-bot`: runs a full self-check across secrets, memory, sandboxing, and SLIM messaging
- `shell-ticker`: tiny long-running ticker for the shell walkthrough
- `slim-echo-peer`: helper used by the feature bot for the local SLIM echo flow
- `a2a-echo-peer`: helper that exposes a task-backed A2A handler over SLIMRPC
- `a2a-send`: client that uses `shadi_a2a::A2AChannel` to send unary or streaming A2A requests

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
- start a local A2A peer and verify both task and streaming A2A responses over SLIMRPC using `shadi_a2a`

If you only want the non-SLIM checks:

```bash
cargo run -p shadi_demo_bot -- feature-bot --no-slim
```

## Run The A2A Example Manually

Start the peer in one terminal:

```bash
cargo run -p shadi_demo_bot -- \
    a2a-echo-peer \
    --endpoint 127.0.0.1:47357 \
    --agent-id secops-a \
    --start-local-node
```

Send a task-style request from another terminal:

```bash
cargo run -p shadi_demo_bot -- \
    a2a-send \
    --endpoint 127.0.0.1:47357 \
    --agent-id avatar \
    --peer-agent-id secops-a \
    --message "hello from avatar"
```

Send a streaming request:

```bash
cargo run -p shadi_demo_bot -- \
    a2a-send \
    --endpoint 127.0.0.1:47357 \
    --agent-id avatar \
    --peer-agent-id secops-a \
    --stream \
    --message "hello from avatar"
```

The peer exposes a `SlimRpcHandler` backed by the A2A server task model, so the
unary path returns a completed task and the streaming path emits a working
status followed by a completed task. The client side uses
`shadi_a2a::A2AChannelBuilder`, which gates the outbound A2A call through
SHADI's `AgentVerifier` before it sends protocol traffic.

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