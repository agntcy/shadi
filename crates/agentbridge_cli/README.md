# agentbridge CLI

`agentbridge` is the command-line interface for the agentbridge coding-agent
interconnect. It lets you register CLI coding tools (Claude Code, Copilot, Codex,
or any subprocess that speaks the agentbridge JSON protocol), list them via DIR
discovery, and exchange context between them.

## Install

```bash
cargo install --path crates/agentbridge_cli
```

## Commands

### `register` — start an adapter server

Wrap a CLI tool as a agentbridge adapter and keep it running.

```bash
# Wrap any subprocess that speaks the agentbridge JSON protocol
agentbridge register --tool generic-stdio --command my-tool --arg --agentbridge-mode
```

**Phase 2+ will add native adapters for:**
- `--tool claude-code` — Claude Code via MCP stdio
- `--tool copilot` — GitHub Copilot CLI
- `--tool codex` — OpenAI Codex CLI

### `list` — discover registered adapters

```bash
# Query DIR for registered adapters
agentbridge list

# Query the running local SLIM node only
agentbridge list --local
```

### `handoff` — transfer context from one tool to another

Snapshot the current session from a source tool and inject it into a destination
tool. Both tools must be running and speaking the agentbridge JSON protocol.

```bash
# Basic handoff using subprocess commands directly
agentbridge handoff \
    --from ./my-source-tool \
    --to ./my-dest-tool

# Save the captured ContextPacket for recovery
agentbridge handoff \
    --from ./my-source-tool \
    --to ./my-dest-tool \
    --save /tmp/context.json

# Resume from a previously saved ContextPacket
agentbridge handoff \
    --from-file /tmp/context.json \
    --to ./my-dest-tool
```

## Subprocess protocol

Any process can participate in a handoff if it reads JSON from stdin and writes
JSON to stdout:

```
stdin:   {"cmd":"snapshot"}
stdout:  {"ok":true,"data":{... ContextPacket JSON ...}}

stdin:   {"cmd":"inject","context":{... ContextPacket JSON ...}}
stdout:  {"ok":true}

stdin:   {"cmd":"execute","prompt":"write a parser"}
stdout:  {"ok":true,"data":"fn parse(...) { ... }"}
```

## Roadmap

| Phase | Feature |
|-------|---------|
| ✅ 1 | `ContextPacket` · `CliAdapter` · `GenericStdioAdapter` · `handoff` |
| 🔜 2 | `claude-code` adapter · `delegate` (A2A) · DIR registration |
| 🔜 3 | `copilot` / `codex` adapters · `coordinate` (autonomous) · SLIM relay |

## Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `SLIM_ENDPOINT` | `127.0.0.1:47357` | SLIM node address |
| `SLIM_SHARED_SECRET` | — | SLIM authentication |
| `SHADI_AGENT_ID` | — | Agent identity for SLIM/DIR |
| `SLIM_TLS_CERT` / `SLIM_TLS_KEY` | — | mTLS client certificate paths |
| `SLIM_TLS_CA` | — | CA certificate for server verification |
