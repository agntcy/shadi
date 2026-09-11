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

Wrap a CLI tool as an agentbridge adapter and keep it running as an A2A
service so remote callers can reach it over SLIMRPC and/or official A2A
unicast (gRPC, JSON-RPC, or HTTP+JSON).

> **Security:** `register --slim-endpoint` and `register --a2a-listen` refuse
> to start unless they're running under a SHADI sandbox with network blocked
> by default — wrap them in `shadictl`, as shown below, and `--read` the
> directory holding certificates (`$SHADI_TMP_DIR/shadi-slim-mtls` for SLIM,
> `$SHADI_TMP_DIR/shadi-a2a-tls` for non-loopback unicast) so the listener can
> still read its own cert under the sandbox. On macOS, resolve
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

# Goose / OpenCode use the operator's existing CLI config. Host
# GOOSE_PROVIDER / GOOSE_MODEL are passed as goose run --provider / --model.
# Host GOOSE_*, OPENAI_*, and *_API_KEY env vars are forwarded to goose.
shadictl --net-block --net-allow 127.0.0.1:47357 --read "$SHADI_TMP_DIR" -- \
  agentbridge register --tool goose --slim-endpoint 127.0.0.1:47357
shadictl --net-block --net-allow 127.0.0.1:47357 --read "$SHADI_TMP_DIR" -- \
  agentbridge register --tool opencode --slim-endpoint 127.0.0.1:47357

# Publish an OASF record to the Agent Directory after registering
agentbridge register --tool claude-code --dir-publish
```

Supported `--tool` values: `generic-stdio`, `claude-code`, `copilot`, `codex`,
`cursor-agent`, `goose`, `opencode`.

### `list` — discover registered adapters

```bash
# Query DIR for registered adapters
agentbridge list

# List listeners this machine started with register --slim-endpoint / --a2a-listen
agentbridge list --local
```

### `handoff` — transfer context from one tool to another

Snapshot the current session from a source tool and inject it into a destination
tool. Bare names (`claude-code`, `copilot`, …) open local adapters (JSON
protocol / native CLI). `slim:<id>` is A2A over SLIM: the process proves as
`SHADI_AGENT_ID` and `SendMessage`s to the peer. When `SHADI_AGENT_ID`
matches `--from slim:<id>`, that agent is the A2A client — snapshot stays
local so it does not call its own listener.

```bash
# Native tools (same specs as coordinate)
agentbridge handoff --from claude-code --to copilot

# Finishing agent hands off as an A2A client (collab demo)
SHADI_AGENT_ID=claude-code agentbridge handoff \
  --from slim:claude-code --to slim:copilot --slim-endpoint 127.0.0.1:47591

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

Dispatch one prompt to a remote agentbridge adapter over A2A and print
the response. `--to` is a DID (`did:key:…`) or a local alias from
`list --local`. The URL is a locator: `delegate` looks it up from the
current lease (or DIR). `--a2a-url` overrides the locator only and must
be paired with `--to did:key:…`. Locator URIs (`jsonrpc://host:port`)
carry the binding; a bare `http://` still means gRPC unless
`--a2a-binding` is set. `https://` gRPC client TLS is not wired yet.

```bash
agentbridge delegate "write unit tests for src/parser.rs" \
  --to did:key:z6Mk… \
  --agent-id avatar

# Constrained unicast without a SLIM node (loopback plaintext)
shadictl --net-block --net-allow 127.0.0.1:50051 -- \
  agentbridge register --tool copilot --a2a-listen 127.0.0.1:50051
# JSON-RPC / HTTP+JSON: add --a2a-binding jsonrpc or --a2a-binding http+json

agentbridge list --local
agentbridge delegate "write unit tests for src/parser.rs" \
  --to did:key:z6Mk… \
  --agent-id avatar
```

### `coordinate` — autonomous multi-round coordination

Default `--pattern development` is CONVERGE on `DevelopmentEngine` until a
winning code artifact is produced. `--pattern preference|cascade|resource`
uses the scalar paper CONVERGE driver. `--assembly` asks the team to model
the problem first and infer the class. The group protocol is documented in
[ASSEMBLY and CONVERGE](../../docs/content/assembly-converge.md).

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
| `goose` | Local Goose CLI adapter (uses `~/.config/goose`) |
| `opencode` | Local OpenCode CLI adapter (uses `~/.config/opencode`) |
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
| `SHADI_AUTH_REQUIRED_POLICY` | `reprove` | `reprove` / `ask` / `deny` when a remote task parks |
| `SLIM_TLS_CERT` / `SLIM_TLS_KEY` | — | SLIM mTLS client certificate paths (not used for gRPC) |
| `SLIM_TLS_CA` | — | CA certificate for SLIM server verification |
| `A2A_TLS_CERT` / `A2A_TLS_KEY` | `$SHADI_TMP_DIR/shadi-a2a-tls/server.{crt,key}` | TLS 1.3 for non-loopback `--a2a-listen`. Do not reuse `SLIM_TLS_*`. Verify with `openssl x509 -text -noout`. |

> ⚠️ **Security:** `register`, `delegate`, and `coordinate` (for `slim:` agent
> specs) authenticate to the SLIM mesh via DID/keys only — set
> `SHADI_SLIM_AUTH=did`, `SLIM_HUMAN_SEED`, and `SLIM_MEMBER_DIDS` (see
> [`docs/content/demos/demo-env.sh`](../../docs/content/demos/demo-env.sh)). Shared secrets are
> not supported: a `register` listener forwards incoming A2A tasks to the local
> CLI tool, so admission must be cryptographic, not a symmetric secret compiled
> into every demo script.
>
> That decides *who* may send a task. It doesn't constrain *what* the task can
> do once it runs, so `register --slim-endpoint` and `register --a2a-listen`
> separately refuse to start unless they're running under a SHADI sandbox
> with network blocked by default — wrap them in
> `shadictl --net-block --net-allow <listen-addr> --`. Kernel
> sandboxes (Seatbelt/Landlock/AppContainer) are inherited by child processes,
> so this confines whatever CLI tool the adapter spawns with no extra code in
> agentbridge itself.

## Live SLIM demo

See [scripts/agentbridge_shell*.sh](../../scripts/) (DID admission, sandbox,
`list --local`), the one-command walkthrough in
[docs/content/demos/did-agent-group.md](../../docs/content/demos/did-agent-group.md),
or the two-lines-per-turn coding loop in
[docs/content/demos/collab-rust.md](../../docs/content/demos/collab-rust.md).
A harness should load
[skills/agentbridge](../../skills/agentbridge/SKILL.md) and call these
commands rather than a new per-CLI adapter.
