# Sample run: round-robin Rust

Four coding-agent CLIs — **claude-code**, **copilot**, **codex**,
**cursor-agent** — take turns writing a small Rust crate. The moderator
(`avatar`) owns the file and starts hop 1 with `delegate`. Each turn may
change **at most two lines of Rust**; `collab-apply.py` drops a third
line even if the model dumps a whole file. The same reply names the next
peer (`NEXT <id>`) or ends the problem (`DONE`). The finishing listener
is the A2A client for that handoff — `avatar` does not pick the order.

The script runs two stubs back to back: `sort_i32` (stable ascending,
no pre-built `sort`) and `Fifo<T>` (`push` / `pop` / `len` /
`is_empty`). After each apply, the host runs `cargo test` and follows
the chosen peer until the tests pass.

This page is one curated transcript of that loop. The next live run may
choose different peers or write different two-line edits. How to start
the script is in the [round-robin Rust demo](collab-rust.md).

| | |
|---|---|
| Problems | `sort` and `fifo`, both **SOLVED** |
| Hops | 7 coding delegates (1 + 6) |
| Tests | `sort` 5/5 · `fifo` 2/2 |
| Failed delegates | none |
| Endpoint | `slim://127.0.0.1:47591` |

## Listeners

`list --local` after register (DIDs truncated; they match
[`demo-env.sh`](demo-env.sh)):

```text
Local agentbridge adapters:
claude-code   did:key:z6MkhRuJ…PZa1  slim://127.0.0.1:47591
copilot       did:key:z6MkmJUc…MnwT  slim://127.0.0.1:47591
codex         did:key:z6MkmaFF…uGr6  slim://127.0.0.1:47591
cursor-agent  did:key:z6MktdzQ…qS5Q  slim://127.0.0.1:47591
```

`avatar` only `delegate`s the coding prompt. After `NEXT <peer>`, that
same `register` process shares the turn (`…/<tool>-a2a-client` →
`…/<peer>-a2a`). `DONE` does not send a listener handoff.

## sort — 1 hop

Claude replaced the identity stub with a two-line insertion sort and
wrote `DONE`. `no_prebuilt_sort` reads `src/lib.rs` from disk and
confirmed there is no `.sort(`.

| Hop | Agent | Apply | Route | Tests |
|---|---|---|---|---|
| 1 | claude-code | `REPLACE` 2 lines at 5 | `DONE` | 5 / 5 |

Reply:

```text
REPLACE 5
let mut items = items;
for i in 1..items.len() { let mut j = i; while j > 0 && items[j-1] > items[j] { items.swap(j-1, j); j -= 1; } } items
DONE
```

Applied:

```diff
 pub fn sort_i32(items: Vec<i32>) -> Vec<i32> {
-    items
+let mut items = items;
+for i in 1..items.len() { let mut j = i; while j > 0 && items[j-1] > items[j] { items.swap(j-1, j); j -= 1; } } items
 }
```

## fifo — 6 hops

Every registered CLI took a coding turn. The two-line cap is why hop 1
could only replace `push`; the leftover `pop` stub stayed `None` until
Copilot used both allowed lines on hop 2.

| Hop | Agent | What landed | A2A next | File |
|---|---|---|---|---|
| 1 | claude-code | `push` body only (`self.items.push(_item)`) | copilot | changed |
| 2 | copilot | full `push` + `pop` (`remove(0)`); old `pop` stub remains | cursor-agent | changed |
| 3 | cursor-agent | `REPLACE 11` restated `push` — apply no-op | codex | unchanged |
| 4 | codex | `len` → `self.items.len()` | cursor-agent | changed |
| 5 | cursor-agent | `#[cfg(false)]` above leftover `pop` stub | copilot | changed |
| 6 | copilot | `is_empty` → `self.items.is_empty()` | `DONE` | changed |

Token path:

```text
avatar ──delegate──► claude-code ──NEXT──► copilot
                                         ──NEXT──► cursor-agent   (no-op apply)
                                         ──NEXT──► codex
                                         ──NEXT──► cursor-agent   (cfg(false))
                                         ──NEXT──► copilot ──DONE
```

### Hop 1 — claude-code

```text
REPLACE 11
self.items.push(_item);
NEXT copilot
```

```diff
-    pub fn push(&mut self, _item: T) {}
+self.items.push(_item);
```

### Hop 2 — copilot

```text
REPLACE 11
    pub fn push(&mut self, item: T) { self.items.push(item); }
    pub fn pop(&mut self) -> Option<T> { if self.items.is_empty() { None } else { Some(self.items.remove(0)) } }
NEXT cursor-agent
```

```diff
-self.items.push(_item);
+    pub fn push(&mut self, item: T) { self.items.push(item); }
+    pub fn pop(&mut self) -> Option<T> { if self.items.is_empty() { None } else { Some(self.items.remove(0)) } }
     pub fn pop(&mut self) -> Option<T> {
         None
```

### Hop 3 — cursor-agent

Legal `NEXT`, no file change. Reply restated `push` at line 11, which
already matched.

```text
REPLACE 11
    pub fn push(&mut self, item: T) { self.items.push(item); }
NEXT codex
```

### Hop 4 — codex

```text
REPLACE 19
        self.items.len()
NEXT cursor-agent
```

```diff
     pub fn len(&self) -> usize {
-        0
+        self.items.len()
     }
```

### Hop 5 — cursor-agent

Hid the leftover stub instead of deleting it. Tests still compile because
the second `pop` is not built.

```text
REPLACE 13
#[cfg(false)]
NEXT copilot
```

```diff
     pub fn pop(&mut self) -> Option<T> { … }
+#[cfg(false)]
     pub fn pop(&mut self) -> Option<T> {
         None
```

### Hop 6 — copilot

```text
REPLACE 23
self.items.is_empty()
DONE
```

```diff
     pub fn is_empty(&self) -> bool {
-        false
+self.items.is_empty()
     }
```

`cargo test` for `fifo`: 2 passed (`empty_new`, `push_pop_order`).

## What this run showed

- Register and `list --local` brought all four adapters up in two seconds.
- The two-line cap is visible: hop 1 could not finish `Fifo`; hop 2 used
  both lines and still left a stub that later hops had to deal with.
- A `NEXT` with a no-op apply (hop 3) still advances the token.
- `DONE` stops the loop without a listener handoff.
- Indentation and leftover stubs are not cleaned up — the orchestrator
  only applies the two-line edit and runs tests.

## Reproduce

```bash
cargo build -p agntcy-shadi-cli -p agntcy-agentbridge-cli
PROBLEM=both MAX_CYCLES=10 bash docs/content/demos/run-collab-demo.sh
```

The four CLIs must be on `PATH` and signed in. Raw per-turn files from a
live run land under `/tmp/shadi-collab-demo.*/logs`
(`sort-turns.log`, `fifo-turns.log`, `*.reply`).
