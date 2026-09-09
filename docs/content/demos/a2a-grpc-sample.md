# Sample run: A2A unicast

Two scripted listeners — **copilot** and **codex** — take the same
demo-env DIDs as the SLIM collab run, but no SLIM node and no paid
coding CLI. The profile `bin` is
[`a2a-grpc-stdio.py`](a2a-grpc-stdio.py): `PING` → `PONG`, and one
stub `REPLACE` per hop. `avatar` owns the file and starts hop 1 with
`delegate --to did:key:…`. The finishing listener is the A2A client
for `NEXT`.

This page is one live trio from 9 September 2026. The same script was
run three times (`TRANSPORT=grpc`, `jsonrpc`, `http+json`). The
locator scheme and listen port changed; the DIDs, dest-DID reject,
URL move, token path, and fifo `cargo test` did not. How to start the
script is in the [A2A unicast demo](a2a-grpc.md).

| | |
|---|---|
| Problem | `fifo` — **SOLVED** after hop 4 on every binding |
| Tests | 2 / 2 (`empty_new`, `push_pop_order`) |
| Who wrote | copilot ×2 · codex ×2 |
| Failed delegates | 0 (coding hops); dest-DID override rejected as designed |
| Bindings | gRPC · JSON-RPC · HTTP+JSON |

## Listeners

`list --local` after register (DIDs truncated; they match
[`demo-env.sh`](demo-env.sh)). Copilot later moves to the second
port; the DID stays.

```text
# gRPC
copilot  did=did:key:z6MkmJUc…MnwT  grpc://127.0.0.1:50151
codex    did=did:key:z6MkmaFF…uGr6  grpc://127.0.0.1:50152

# JSON-RPC
copilot  did=did:key:z6MkmJUc…MnwT  jsonrpc://127.0.0.1:51151
codex    did=did:key:z6MkmaFF…uGr6  jsonrpc://127.0.0.1:51152

# HTTP+JSON
copilot  did=did:key:z6MkmJUc…MnwT  http+json://127.0.0.1:52151
codex    did=did:key:z6MkmaFF…uGr6  http+json://127.0.0.1:52152
```

`avatar` only `delegate`s the coding prompt (and the three locator
checks). After `NEXT <peer>`, that same `register` process shares the
turn. `DONE` does not send a listener handoff.

## Locator checks (before fifo)

These three checks ran on every binding. The gRPC transcript is
below; JSON-RPC and HTTP+JSON printed the same text with
`jsonrpc://127.0.0.1:51151` / `:51161` or
`http+json://127.0.0.1:52151` / `:52161`.

### Echo by DID

`delegate --to did:key:z6MkmJUc…` with no `--a2a-url`. The lease
locator is looked up.

```text
Delegating task … to 'copilot' (did=did:key:z6MkmJUc…MnwT) via grpc://127.0.0.1:50151...
Response from 'copilot' (34ms):
PONG
```

### Dest DID mismatch

Same URL, a DID that is not the listener. The task must not run.

```text
Delegating task … to 'did:key:zWrongDestinationDid…' via grpc://127.0.0.1:50151...
Response from 'did:key:zWrongDestinationDid…' (3ms):
destination DID did:key:zWrongDestinationDid… is not this agent
(did:key:z6MkmJUc…MnwT); URL is only a locator
```

No `PONG`. Two agents can share a locator; `a2a-dst-did` selects who
runs.

### Same DID after URL change

Copilot is stopped and re-registered on `:50161` (`:51161` /
`:52161` on the other bindings). `list --local` then shows the new
URI. `delegate --to` the **same** DID, still without `--a2a-url`:

```text
copilot moved grpc://127.0.0.1:50151 → grpc://127.0.0.1:50161
Delegating task … to 'copilot' (did=did:key:z6MkmJUc…MnwT) via grpc://127.0.0.1:50161...
Response from 'copilot' (29ms):
PONG
```

## fifo — 4 hops

The crate is the same stub as
[`run-a2a-grpc-demo.sh`](run-a2a-grpc-demo.sh): `push` / `pop` /
`len` / `is_empty` are no-ops. Each hop replaces one stub. The
scripted binary always names the other peer (or `DONE` on
`is_empty`).

| Hop | Agent | What landed | A2A next |
|---|---|---|---|
| 1 | copilot | `push` → `self.items.push(item)` | codex |
| 2 | codex | `pop` → `drain(0..len.min(1)).next()` | copilot |
| 3 | copilot | `len` → `self.items.len()` | codex |
| 4 | codex | `is_empty` → `self.items.is_empty()` | `DONE` · **SOLVED** |

Token path (identical on all three bindings):

```text
avatar ──delegate──► copilot ──NEXT──► codex
                                   ──NEXT──► copilot
                                   ──NEXT──► codex ──DONE · SOLVED
```

### Hop 1 — copilot

```text
REPLACE 11
    pub fn push(&mut self, item: T) { self.items.push(item); }
NEXT codex
```

```diff
-    pub fn push(&mut self, _item: T) {}
+    pub fn push(&mut self, item: T) { self.items.push(item); }
```

### Hop 2 — codex

```text
REPLACE 14
        self.items.drain(0..self.items.len().min(1)).next()
NEXT copilot
```

```diff
     pub fn pop(&mut self) -> Option<T> {
-        None
+        self.items.drain(0..self.items.len().min(1)).next()
     }
```

### Hop 3 — copilot

```text
REPLACE 18
        self.items.len()
NEXT codex
```

```diff
     pub fn len(&self) -> usize {
-        0
+        self.items.len()
     }
```

### Hop 4 — codex

```text
REPLACE 22
        self.items.is_empty()
DONE
```

```diff
     pub fn is_empty(&self) -> bool {
-        false
+        self.items.is_empty()
     }
```

`cargo test` for `fifo`: 2 passed.

Impl after hop 4 (tests unchanged):

```rust
    pub fn push(&mut self, item: T) { self.items.push(item); }

    pub fn pop(&mut self) -> Option<T> {
        self.items.drain(0..self.items.len().min(1)).next()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
```

## What these runs showed

- Register and `list --local` print a locator URI whose scheme is the
  binding (`grpc://`, `jsonrpc://`, `http+json://`).
- `delegate --to did:key:…` looks up that locator. `--a2a-url` is an
  override only.
- A task aimed at another DID on the same URL is rejected; the
  listener does not run it.
- Moving the listen port keeps the DID. The next `delegate --to` that
  DID follows the new URI.
- The two-line cap still applies (`REPLACE` + one body line). The
  scripted hops stay inside it.
- `DONE` with a green `cargo test` ends the problem on hop 4.

The paid-CLI token path on the same bindings is
`TRANSPORT=grpc|jsonrpc|http+json PROBLEM=fifo` on the
[round-robin Rust demo](collab-rust.md). That run was not repeated
for this page.

## Reproduce

```bash
cargo build -p agntcy-shadi-cli -p agntcy-agentbridge-cli
bash docs/content/demos/run-a2a-grpc-demo.sh
TRANSPORT=jsonrpc bash docs/content/demos/run-a2a-grpc-demo.sh
TRANSPORT=http+json bash docs/content/demos/run-a2a-grpc-demo.sh
```

No paid CLI is required. Unset `SLIM_ENDPOINT` (the script does)
so `register` does not dual-listen. Raw per-turn files from a live
run land under `/tmp/shadi-a2a-grpc-demo.*/logs` (`fifo-turns.log`,
`echo.raw`, `mismatch.raw`, `moved.raw`, `*.reply`).
