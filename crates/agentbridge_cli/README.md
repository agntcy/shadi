# agentbridge CLI

`agentbridge` is the command-line interface for the agentbridge general-purpose
agent interconnect. It registers agents (CLI coding tools like Claude Code,
Copilot, Codex, Cursor Agent, or any subprocess that speaks the agentbridge
JSON protocol) as live A2A services, lists them via DIR discovery, hands off
context between them, and coordinates them autonomously toward a shared goal.

## Install

```bash
cargo install --path crates/agentbridge_cli
```

## Commands

### `register` — start an adapter server

Wrap a CLI tool as an agentbridge adapter and keep it running as a SLIM A2A
service so remote callers can reach it.

> **Security:** `register --slim-endpoint` refuses to start unless it's running
> under a SHADI sandbox with network blocked by default — wrap it in `shadictl`,
> as shown below, and `--read` the directory holding the SLIM mTLS client
> certificate (`$SHADI_TMP_DIR/shadi-slim-mtls` in the demos) so the listener
> can still read its own cert under the sandbox. On macOS, resolve
> `$SHADI_TMP_DIR` to its real path first (`cd "$SHADI_TMP_DIR" && pwd -P`) —
> `/tmp` is a symlink to `/private/tmp`, and Seatbelt's sandbox rules don't
> match a path reached through the symlink if the rule was generated for the
> canonicalized form. See [Environment variables](#environment-variables).

```bash
# Wrap any subprocess that speaks the agentbridge JSON protocol
shadictl --net-block --net-allow 127.0.0.1:47357 --read "$SHADI_TMP_DIR" -- \
  agentbridge register \
  --tool generic-stdio \
  --command my-tool \
  --arg --agentbridge-mode \
  --slim-endpoint 127.0.0.1:47357

# Start a Claude Code adapter
shadictl --net-block --net-allow 127.0.0.1:47357 --read "$SHADI_TMP_DIR" -- \
  agentbridge register --tool claude-code --slim-endpoint 127.0.0.1:47357

# Start a Copilot adapter
shadictl --net-block --net-allow 127.0.0.1:47357 --read "$SHADI_TMP_DIR" -- \
  agentbridge register --tool copilot --slim-endpoint 127.0.0.1:47357

# Start a Codex adapter
shadictl --net-block --net-allow 127.0.0.1:47357 --read "$SHADI_TMP_DIR" -- \
  agentbridge register --tool codex --slim-endpoint 127.0.0.1:47357

# Publish an OASF record to the Agent Directory after registering
agentbridge register --tool claude-code --dir-publish
```

Supported `--tool` values: `generic-stdio`, `claude-code`, `copilot`, `codex`.

> **Note:** `cursor-agent` is available as a spec in `coordinate --agents`
> but does not have a standalone `register` listener yet.

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

### `delegate` — send a single task to a remote adapter

Dispatch one prompt to a remote agentbridge adapter over A2A/SLIM and print
the response.

```bash
agentbridge delegate "write unit tests for src/parser.rs" \
  --to codex \
  --agent-id avatar \
  --endpoint 127.0.0.1:47357
```

### `coordinate` — autonomous multi-round coordination

Run `MasRuntime<DevelopmentEngine>` across a set of agents until a winning code
artifact is produced. Agents propose, vote, and converge without human mediation.

```bash
# Local agents (in-process subprocess adapters)
agentbridge coordinate \
  --goal "implement a JSON parser in Rust" \
  --agents claude-code,copilot,codex,cursor-agent \
  --quorum 3 \
  --max-rounds 5 \
  --output result.rs

# Remote agents over SLIM A2A (register each in a separate terminal first)
agentbridge coordinate \
  --goal "implement a JSON parser in Rust" \
  --agents slim:copilot,slim:codex \
  --quorum 1 \
  --max-rounds 2 \
  --output result.rs \
  --slim-endpoint 127.0.0.1:47357

# Require explicit human approval before accepting the result
agentbridge coordinate \
  --goal "refactor auth module" \
  --agents claude-code,copilot \
  --quorum 2 \
  --require-human
```

**Agent spec formats for `--agents`:**

| Format | Meaning |
|--------|---------|
| `claude-code` | Local Claude Code adapter |
| `copilot` | Local Copilot CLI adapter |
| `codex` | Local Codex CLI adapter |
| `cursor-agent` | Local Cursor Agent adapter |
| `generic-stdio:<cmd>` | Local subprocess adapter |
| `slim:<agent-id>` | Remote adapter over SLIM (uses `--slim-endpoint`) |
| `slim:<agent-id>@<host:port>` | Remote adapter at explicit endpoint |

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

## Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `SLIM_ENDPOINT` | `127.0.0.1:47357` | SLIM node address |
| `SHADI_AGENT_ID` | `avatar` | Agent identity for SLIM/DIR |
| `SHADI_SLIM_AUTH` | — | Must be `did` — see below |
| `SLIM_HUMAN_SEED` | — | Human root secret DID keys are derived from |
| `SLIM_MEMBER_DIDS` | — | Comma-separated `did:key` allow-list |
| `SLIM_TLS_CERT` / `SLIM_TLS_KEY` | — | mTLS client certificate paths |
| `SLIM_TLS_CA` | — | CA certificate for server verification |

> ⚠️ **Security:** `register`, `delegate`, and `coordinate` (for `slim:` agent
> specs) authenticate to the SLIM mesh via DID/keys only — set
> `SHADI_SLIM_AUTH=did`, `SLIM_HUMAN_SEED`, and `SLIM_MEMBER_DIDS` (see
> [`docs/content/demos/demo-env.sh`](../../docs/content/demos/demo-env.sh)). Shared secrets are
> not supported: a `register` listener forwards incoming A2A tasks to the local
> CLI tool, so admission must be cryptographic, not a symmetric secret compiled
> into every demo script.
>
> That decides *who* may send a task. It doesn't constrain *what* the task can
> do once it runs, so `register --slim-endpoint` separately refuses to start
> unless it's running under a SHADI sandbox with network blocked by default —
> wrap it in `shadictl --net-block --net-allow <slim-endpoint> --`. Kernel
> sandboxes (Seatbelt/Landlock/AppContainer) are inherited by child processes,
> so this confines whatever CLI tool the adapter spawns with no extra code in
> agentbridge itself.

## Live SLIM demo (4 terminals)

See [scripts/agentbridge_shell*.sh](../../scripts/) for a ready-made 4-terminal
demo that starts a SLIM node, registers Copilot and Codex as A2A services, and
runs `coordinate` against them.
