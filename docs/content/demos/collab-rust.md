# Demo: round-robin Rust, two lines per turn

Five coding-agent CLIs — **claude-code**, **copilot**, **codex**,
**cursor-agent**, **goose** — write a small Rust library. The moderator (`avatar`) owns
the file and starts the first hop. Each turn an agent may output **at most two
lines of code**; a third line is discarded by the orchestrator, even if the
model dumps a whole file. The same reply names the **next peer** (`NEXT
<id>` or `DONE`). That finishing agent is the A2A *client* for the handoff —
`avatar` does not pick the order.

The default problem is a Vec-backed LRU cache with many stubs. `get` and
`put` cannot finish in one two-line hop, so a live run typically needs
on the order of **twenty turns** (default cap: `MAX_CYCLES × N` = 40 hops
for five agents). Optional `fifo` is a shorter queue if you only want to
smoke-test the token path.

| Problem | Goal | Starting stub |
|---|---|---|
| `lru` (default) | `Lru<K, V>` — `items[0]` is LRU, last is MRU; scan the `Vec` only | `None` / `0` / `false` / empty `put` |
| `fifo` | `Fifo<T>` with `push` / `pop` / `len` / `is_empty` | no-op methods |

## One command

From the repo root:

```bash
bash docs/content/demos/run-collab-demo.sh
```

In a second terminal:

```bash
bash docs/content/demos/watch-collab-demo.sh
```

Only one problem, or a shorter agent set:

```bash
PROBLEM=lru bash docs/content/demos/run-collab-demo.sh
PROBLEM=fifo MAX_CYCLES=6 bash docs/content/demos/run-collab-demo.sh
PROBLEM=both MAX_CYCLES=10 bash docs/content/demos/run-collab-demo.sh
COLLAB_AGENTS=goose,claude-code PROBLEM=lru MAX_CYCLES=12 bash docs/content/demos/run-collab-demo.sh
```

`--net-allow` includes `cisco.com` and `*.cisco.com`. Add more hosts with
`COLLAB_NET_ALLOW=host.example.com` (comma-separated).

The script starts a SLIM node, registers the adapters under
`shadictl --net-block` (DID-signed A2A, `list --local` leases), then
token-passes: `avatar` `delegate`s the coding prompt → the finishing
listener A2A-dispatches `NEXT` to the chosen peer → apply-capped-edit →
`cargo test` → `avatar` follows that choice for the next coding hop.

## What this shows

- **Token-passing collaboration** — the same listeners as the
  [DID agent-group demo](did-agent-group.md), plus **goose**. `avatar`
  starts hop 1; each agent chooses who codes next. A missing or invalid
  `NEXT` falls back to the next name in the list. `MAX_CYCLES` (default 8)
  caps hops at `MAX_CYCLES × N` (N is the agent count). Narrow the set
  with `COLLAB_AGENTS=goose,claude-code`.
- **Agents are A2A servers and clients** — the coding prompt is an A2A
  `SendMessage` from `avatar` to `agntcy/shadi/<tool>-a2a`. After the CLI
  replies with `NEXT <peer>`, that same `register` process sends the
  **turn** (last `REPLACE`/`NEXT`, goal, `src/lib.rs`, last `cargo test`)
  as `HANDOFF from …` (`…/<tool>-a2a-client` → `…/<peer>-a2a`). The
  receiver stores that packet and does not run the coding CLI on it.
  `avatar` does not run `handoff`. The client name is distinct so the
  listener does not `SendMessage` to itself.
- **Hard two-line cap** — `collab-apply.py` accepts `REPLACE` / `INSERT` /
  `APPEND` plus at most two Rust lines. `NEXT` / `DONE` are routing and are
  not written into the crate.
- **Host still owns the file** — apply and `cargo test` stay in the
  orchestrator. The prompt forbids replacing signatures or tests. The LRU
  crate asserts the impl does not use `HashMap`, `BTreeMap`, `HashSet`,
  `BTreeSet`, `VecDeque`, or `LinkedList`.
- **DID + sandbox** — same admission and `register --slim-endpoint` rules as
  the other live demos (`--write` on `$SHADI_TMP_DIR` so leases and the
  workspace can be written, plus `~/.cursor`, `~/.codex`, `~/.claude`, and
  the login keychain so Claude/Copilot/Codex/Cursor can refresh tokens
  and bind app-server sockets, plus Goose's existing config and state
  dirs). Goose keeps its own provider settings; this demo does not set a
  model or endpoint. Host `GOOSE_PROVIDER` / `GOOSE_MODEL` are passed as
  `goose run --provider` / `--model`. Host `GOOSE_*`, `OPENAI_*`,
  `*_API_KEY`, and Goose provider `api_key_env` names are forwarded.
  `--net-allow` includes `cisco.com`
  and `*.cisco.com` (plus any `COLLAB_NET_ALLOW` overrides). A hop only
  produces Rust if that CLI already works on the host. Network or tool
  errors are not applied to the file.

## Turn protocol

The prompt forbids markdown and explanation. A legal reply is:

```text
REPLACE 22
        self.cap
NEXT copilot
```

or

```text
INSERT 48
        self.items.push((key, value));
NEXT cursor-agent
```

or

```text
APPEND
    pub fn is_empty(&self) -> bool { self.items.is_empty() }
DONE
```

`REPLACE n` swaps the single line `n` for one or two lines (it does not
eat the neighbor). `INSERT n` splices before that line. `APPEND` adds at
the end. In every case the apply step keeps **two code lines max**.
`NEXT` / `DONE` are stripped before the file is written.

## Prerequisites

Same as the DID demo: build `shadictl` and `agentbridge`, have the CLIs
on `PATH` and authenticated (`claude` OAuth, `cursor-agent login` /
`CURSOR_API_KEY`, Copilot/Codex already signed in, Goose already
configured). A failed `delegate` is
logged and that turn is skipped — no `handoff` is attempted, so a dead CLI
does not stall the cycle. The apply cap only runs on a successful reply.

## After a run

The summary prints each turn's apply note and `diff`, the final `src/lib.rs`,
and the last `cargo test`. Logs live under `/tmp/shadi-collab-demo.*/logs`
(`lru-turns.log`, `fifo-turns.log`, per-turn `.prompt` / `.reply` / `.apply`).

A live 17-hop `PROBLEM=lru` transcript (and a shorter fifo run) is in
[Sample run: round-robin Rust](collab-rust-sample.md). Hop counts and
peer choices vary on every live run.

## Next steps

- The identity and roll-call that precede this loop:
  [Secure Agent Group Demo](did-agent-group.md).
- Autonomous propose/vote (no two-line cap): `agentbridge coordinate`.
- Flags: [CLI Reference](../cli.md), [AgentBridge](../agentbridge.md).
- Call the same CLI from inside a harness (no new Rust): the
  [agentbridge skill](https://github.com/agntcy/shadi/tree/main/skills/agentbridge)
  (`list --local` / `delegate` / `handoff`). See
  [Use from a harness](../agentbridge.md#use-from-a-harness).
