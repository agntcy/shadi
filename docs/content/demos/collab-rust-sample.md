# Sample run: round-robin Rust

Five coding-agent CLIs — **claude-code**, **copilot**, **codex**,
**cursor-agent**, **goose** — take turns writing a small Rust crate. The
moderator (`avatar`) owns the file and starts hop 1 with `delegate`.
Each turn may change **at most two lines of Rust**; `collab-apply.py`
drops a third line even if the model dumps a whole file. The same reply
names the next peer (`NEXT <id>`) or ends the problem (`DONE`). The
finishing listener is the A2A client for that handoff — `avatar` does
not pick the order.

The default problem is `Lru<K, V>`. The scaffold ships many stubs on
purpose: accessors such as `cap` / `len` / `contains` fit a two-line hop,
but `get` and `put` (lookup, promote, insert, evict) do not. A live
five-agent run is meant to take on the order of **twenty hops** before
`cargo test` is green. Optional `fifo` is a shorter smoke test of the
same protocol.

This page describes that LRU crate and keeps one real fifo transcript
as a protocol illustration. It does **not** invent an LRU hop-by-hop
log — peer choices and exact two-line edits change every run. How to
start the script is in the [round-robin Rust demo](collab-rust.md).
`--net-allow` includes `cisco.com` and `*.cisco.com`. Goose uses the
operator's existing config; this sample does not describe that setup.

| | |
|---|---|
| Default problem | `lru` — Vec-backed cache, 10 tests (9 fail on the stub) |
| Optional problem | `fifo` — four no-op methods |
| Hop budget | `MAX_CYCLES × N` (default 8 × 5 = 40) |
| Endpoint | `slim://127.0.0.1:47591` |

## Listeners

`list --local` after register (DIDs truncated; they match
[`demo-env.sh`](demo-env.sh)):

```text
Local agentbridge adapters:
claude-code   did:key:z6MkhRuJ…PZa1  slim://127.0.0.1:47591
codex         did:key:z6MkmaFF…uGr6  slim://127.0.0.1:47591
copilot       did:key:z6MkmJUc…MnwT  slim://127.0.0.1:47591
cursor-agent  did:key:z6MktdzQ…qS5Q  slim://127.0.0.1:47591
goose         did:key:z6MkjiDF…aEKD  slim://127.0.0.1:47591
```

`avatar` only `delegate`s the coding prompt. After `NEXT <peer>`, that
same `register` process shares the turn (`…/<tool>-a2a-client` →
`…/<peer>-a2a`). `DONE` does not send a listener handoff. If tests still
fail after `DONE`, the orchestrator falls through to the next name in
the list.

## lru — the default problem

The crate is copied from
[`scaffolds/collab_lru`](scaffolds/collab_lru/src/lib.rs) into
`/tmp/shadi-collab-demo.*/workspace/lru`. Storage is a single
`Vec<(K, V)>`: index `0` is least recently used, the last element is
most recently used. Tests read `src/lib.rs` from disk and fail if the
impl mentions `HashMap`, `BTreeMap`, `HashSet`, `BTreeSet`, `VecDeque`,
or `LinkedList`.

| Method | Stub | Why it needs the token |
|---|---|---|
| `cap` / `len` / `is_empty` | `0` / `false` | one-line each |
| `contains` / `peek` | `false` / `None` | scan, no reorder |
| `recent` / `oldest` / `keys_*` | `None` / empty `Vec` | order views |
| `pop_lru` / `pop_mru` / `clear` / `touch` | `None` / no-op / `false` | ends and promote |
| `get` | `None` | find **and** move to MRU |
| `put` | empty | insert, update, or evict LRU |

Nine of the ten tests fail on the scaffold (`no_std_maps_or_deques`
already passes). Early hops typically fill `cap` / `len` / `is_empty`.
Later hops have to leave `get` and `put` unfinished so the next peer
can add the missing scan or eviction. A one-hop `DONE` (what the old
`sort_i32` identity stub allowed) cannot turn this crate green.

After a live run, inspect `/tmp/shadi-collab-demo.*/logs/lru-turns.log`
for the apply notes and diffs. Hop count, who wrote `get`, and whether
goose landed a `REPLACE` all vary with the operator's CLIs and network.

## fifo — optional shorter problem

`PROBLEM=fifo` (or `PROBLEM=both`) still ships the four-method queue.
The transcript below is one real six-hop solve: four CLIs wrote Rust,
goose was chosen after a premature `DONE`, that hop was an empty/error
reply, and claude-code restored the closing `}`.

| Hop | Agent | What landed | A2A next | File |
|---|---|---|---|---|
| 1 | claude-code | `push` body (`self.items.push(_item)`) | copilot | changed |
| 2 | copilot | one-line `pop` (`remove(0)`); leftover `None` stub remains | codex | changed |
| 3 | codex | `len` → `self.items.len()` | cursor-agent | changed |
| 4 | cursor-agent | `is_empty` → `self.items.is_empty()`; dropped `}` | `DONE` (tests fail) | changed |
| 5 | goose | empty/error reply | fallback claude-code | unchanged |
| 6 | claude-code | restore closing `}` | codex | changed; **SOLVED** |

Token path:

```text
avatar ──delegate──► claude-code ──NEXT──► copilot
                                         ──NEXT──► codex
                                         ──NEXT──► cursor-agent ──DONE (tests fail)
                                         ──fallback──► goose     (no apply)
                                         ──fallback──► claude-code ──SOLVED
```

### Hop 1 — claude-code

```text
REPLACE 11
    pub fn push(&mut self, _item: T) { self.items.push(_item); }
NEXT copilot
```

```diff
-    pub fn push(&mut self, _item: T) {}
+    pub fn push(&mut self, _item: T) { self.items.push(_item); }
```

### Hop 2 — copilot

```text
REPLACE 13
    pub fn pop(&mut self) -> Option<T> { if self.items.is_empty() { None } else { Some(self.items.remove(0)) } }
NEXT codex
```

```diff
-    pub fn pop(&mut self) -> Option<T> {
+    pub fn pop(&mut self) -> Option<T> { if self.items.is_empty() { None } else { Some(self.items.remove(0)) } }
         None
```

### Hop 3 — codex

```text
REPLACE 18
        self.items.len()
NEXT cursor-agent
```

```diff
     pub fn len(&self) -> usize {
-        0
+        self.items.len()
     }
```

### Hop 4 — cursor-agent

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
-}
+        self.items.is_empty()
```

`DONE` ran while the crate still did not compile, so the orchestrator
continued.

### Hop 5 — goose

Empty or error reply. `collab-apply.py` left `src/lib.rs` unchanged.
The token fell back to claude-code.

### Hop 6 — claude-code

```text
REPLACE 22
}
NEXT codex
```

```diff
     pub fn is_empty(&self) -> bool {
         self.items.is_empty()
     }
-        self.items.is_empty()
+}
```

`cargo test` for `fifo`: 2 passed (`empty_new`, `push_pop_order`).

## What a run shows

- Register and `list --local` bring all five adapters up, including
  goose.
- The two-line cap is the point of `lru`: one hop cannot finish `get`
  or `put`.
- `DONE` with failing tests still advances the token.
- A failed goose hop does not write tool errors into the crate.
- Indentation and leftover stubs are not cleaned up — the orchestrator
  only applies the two-line edit and runs tests.

## Reproduce

```bash
cargo build -p agntcy-shadi-cli -p agntcy-agentbridge-cli
bash docs/content/demos/run-collab-demo.sh
```

Optional shorter queue, or both problems:

```bash
PROBLEM=fifo MAX_CYCLES=6 bash docs/content/demos/run-collab-demo.sh
PROBLEM=both MAX_CYCLES=10 bash docs/content/demos/run-collab-demo.sh
```

The five CLIs must be on `PATH` and signed in. Goose keeps its own
provider settings. Raw per-turn files from a live run land under
`/tmp/shadi-collab-demo.*/logs` (`lru-turns.log`, `fifo-turns.log`,
`*.reply`).
