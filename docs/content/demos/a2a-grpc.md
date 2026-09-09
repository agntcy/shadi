# Demo: A2A unicast (same outcome as SLIM)

Constrained unicast does not need a SLIM node. This demo speaks an official
A2A binding (gRPC by default; `TRANSPORT=jsonrpc` or `http+json`), addresses
peers by **DID**, and treats `{binding, url}` as a locator that can change.
Token-passing `NEXT` and the fifo `cargo test` outcome are the same as the
[round-robin Rust demo](collab-rust.md) on SLIM.

It does **not** use paid coding CLIs. `copilot` and `codex` are the same
demo-env DIDs as the SLIM run; the profile `bin` is a scripted
[`a2a-grpc-stdio.py`](a2a-grpc-stdio.py)
that emits one two-line `REPLACE` per hop.

## One command

From the repo root:

```bash
bash docs/content/demos/run-a2a-grpc-demo.sh
TRANSPORT=jsonrpc bash docs/content/demos/run-a2a-grpc-demo.sh
TRANSPORT=http+json bash docs/content/demos/run-a2a-grpc-demo.sh
```

That script:

1. Registers `copilot` and `codex` with `--a2a-listen` and `--a2a-binding` (loopback HTTP, DID proof on the message).
2. `delegate --to did:key:…` a `PING` and expects `PONG` (lease URL lookup).
3. Sends a task to a **different** DID at copilot's URL and expects a reject — two agents can share a locator; `a2a-dst-did` selects who runs.
4. Moves copilot to a new port, same DID, and `PING`s again by DID.
5. Token-passes fifo (`REPLACE` + `NEXT`) until `cargo test` passes — the same finishing condition as SLIM collab.

Paid CLIs, same unicast path:

```bash
TRANSPORT=grpc PROBLEM=fifo bash docs/content/demos/run-collab-demo.sh
TRANSPORT=jsonrpc PROBLEM=fifo bash docs/content/demos/run-collab-demo.sh
```

## What this shows

- **No SLIM node** — `register --a2a-listen 127.0.0.1:<port> --a2a-binding grpc|jsonrpc|http+json`. Identity is still `SHADI_SLIM_AUTH=did` / `SLIM_HUMAN_SEED` / `SLIM_MEMBER_DIDS` from [demo-env.sh](demo-env.sh).
- **DID is the name** — `list --local` prints `did=did:key:…` and a locator URI (`grpc://…`, `jsonrpc://…`, `http+json://…`). `delegate --to did:key:…` looks up the current locator. `--a2a-url` is a locator override only (`jsonrpc://host:port` or a bare `http://` plus `--a2a-binding`).
- **NEXT over the same binding** — with `AGENTBRIDGE_A2A_FORWARD=1` the finishing listener dispatches `HANDOFF` to the peer named in `NEXT`, using that peer's lease locator and DID. Avatar only starts hop 1 and follows the choice for the next coding `delegate`.
- **Sandbox** — `register --a2a-listen` still requires `shadictl --net-block` plus `--net-allow` on each listen port (and the peer ports, so NEXT can connect).

Loopback may be plaintext HTTP. Any other bind needs `A2A_TLS_CERT` / `A2A_TLS_KEY` (not `SLIM_TLS_*`). `https://` **gRPC** client TLS is not wired; JSON-RPC and HTTP+JSON can use HTTPS.

## After a run

The summary prints the echo / dest-DID / URL-move checks, each fifo turn, the final `src/lib.rs`, and the last `cargo test`. Logs live under `/tmp/shadi-a2a-grpc-demo.*/logs`.

A live trio (gRPC, JSON-RPC, HTTP+JSON) with the same four-hop fifo
solve is in [Sample run: A2A unicast](a2a-grpc-sample.md). The scripted
`REPLACE`/`NEXT` lines do not vary; only the locator scheme and port
do.

## Next steps

- SLIM mesh, MLS, and `/slim create|invite|join`: [Secure Agent Group Demo](did-agent-group.md).
- Paid-CLI token-passing on either binding: [Round-robin Rust Demo](collab-rust.md).
- Protocol notes: [SLIM and A2A](../slim_a2a.md), [AgentBridge](../agentbridge.md).
