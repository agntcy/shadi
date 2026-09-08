# Sample run: round-robin Rust

Five coding-agent CLIs — **claude-code**, **copilot**, **codex**,
**cursor-agent**, **goose** — take turns writing a small Rust crate. The
moderator (`avatar`) owns the file and starts hop 1 with `delegate`.
Each turn may change **at most two lines of Rust**; `collab-apply.py`
drops a third line even if the model dumps a whole file. The same reply
names the next peer (`NEXT <id>`) or ends the problem (`DONE`). The
finishing listener is the A2A client for that handoff — `avatar` does
not pick the order.

This page is one live `PROBLEM=lru` transcript (17 hops, **SOLVED**).
The next run may choose different peers or write different two-line
edits. How to start the script is in the
[round-robin Rust demo](collab-rust.md). `--net-allow` includes
`cisco.com` and `*.cisco.com`. Goose uses the operator's existing
config; this sample does not describe that setup.

| | |
|---|---|
| Problem | `lru` — **SOLVED** after hop 17 |
| Tests | 10 / 10 |
| Who wrote | claude-code ×2 · codex ×8 · cursor-agent ×6 · goose ×1 |
| Not chosen | `copilot` (registered; nobody sent `NEXT copilot`) |
| Failed delegates | 0 |
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

## lru — 17 hops

The crate is copied from
[`scaffolds/collab_lru`](scaffolds/collab_lru/src/lib.rs). Storage is a
single `Vec<(K, V)>`: index `0` is least recently used, the last
element is most recently used. Tests fail if the impl mentions
`HashMap`, `BTreeMap`, `HashSet`, `BTreeSet`, `VecDeque`, or
`LinkedList`.

Early hops fill one-line accessors. `put` and `get` take two hops
each. Goose's hop dropped the `clear` signature; the next peer put it
back. Codex wrote `touch` and `DONE`; tests were already green.

| Hop | Agent | What landed | A2A next |
|---|---|---|---|
| 1 | claude-code | `cap` → `self.cap` | codex |
| 2 | codex | `len` → `self.items.len()` | cursor-agent |
| 3 | cursor-agent | `is_empty` → `self.items.is_empty()` | codex |
| 4 | codex | `contains` — scan | cursor-agent |
| 5 | cursor-agent | `put` — open + insert/evict (2 lines) | codex |
| 6 | codex | `put` — update existing, then return | cursor-agent |
| 7 | cursor-agent | `peek` — scan, no reorder | codex |
| 8 | codex | `pop_lru` — `remove(0)` | cursor-agent |
| 9 | cursor-agent | `get` — promote to MRU; leftover `None` | codex |
| 10 | codex | `pop_mru` — `pop()` | **goose** |
| 11 | goose | `clear` body only (dropped the `fn`) | claude-code |
| 12 | claude-code | restore `pub fn clear` | codex |
| 13 | codex | `keys_mru` — reverse collect | cursor-agent |
| 14 | cursor-agent | `keys_lru` — collect | codex |
| 15 | codex | `recent` — `last` | cursor-agent |
| 16 | cursor-agent | `oldest` — `first` | codex |
| 17 | codex | `touch` — promote or `false` | `DONE` · **SOLVED** |

Token path:

```text
avatar ──delegate──► claude-code ──NEXT──► codex
                                       ──NEXT──► cursor-agent
                                       ──NEXT──► codex
                                       ──NEXT──► cursor-agent   (put, 2 lines)
                                       ──NEXT──► codex          (put update)
                                       ──NEXT──► cursor-agent
                                       ──NEXT──► codex
                                       ──NEXT──► cursor-agent   (get)
                                       ──NEXT──► codex ──NEXT──► goose
                                       ──NEXT──► claude-code    (repair clear)
                                       ──NEXT──► codex
                                       ──NEXT──► cursor-agent
                                       ──NEXT──► codex
                                       ──NEXT──► cursor-agent
                                       ──NEXT──► codex ──DONE · SOLVED
```

### Hop 1 — claude-code

```text
REPLACE 22
        self.cap
NEXT codex
```

```diff
     pub fn cap(&self) -> usize {
-        0
+        self.cap
     }
```

### Hop 2 — codex

```text
REPLACE 26
        self.items.len()
NEXT cursor-agent
```

```diff
     pub fn len(&self) -> usize {
-        0
+        self.items.len()
     }
```

### Hop 3 — cursor-agent

```text
REPLACE 30
        self.items.is_empty()
NEXT codex
```

```diff
     pub fn is_empty(&self) -> bool {
-        false
+        self.items.is_empty()
     }
```

### Hop 4 — codex

```text
REPLACE 34
        self.items.iter().any(|(k, _)| k == _key)
NEXT cursor-agent
```

```diff
     pub fn contains(&self, _key: &K) -> bool {
-        false
+        self.items.iter().any(|(k, _)| k == _key)
     }
```

### Hop 5 — cursor-agent

Two-line `put`: the signature plus one insert/evict line. The apply
left a duplicate insert (the two-line cap cannot finish update +
evict + close).

```text
REPLACE 48
    pub fn put(&mut self, _key: K, _value: V) {
        if self.items.iter().all(|(k, _)| k != &_key) { if self.items.len() >= self.cap { self.items.remove(0); } self.items.push((_key, _value)); } }
NEXT codex
```

```diff
-    pub fn put(&mut self, _key: K, _value: V) {}
+    pub fn put(&mut self, _key: K, _value: V) {
+        if self.items.iter().all(|(k, _)| k != &_key) { if self.items.len() >= self.cap { self.items.remove(0); } self.items.push((_key, _value)); } }
+        if self.items.iter().all(|(k, _)| k != &_key) { if self.items.len() >= self.cap { self.items.remove(0); } self.items.push((_key, _value)); }
+    }
```

### Hop 6 — codex

```text
REPLACE 49
        if let Some(i) = self.items.iter().position(|(k, _)| k == &_key) { self.items.remove(i); self.items.push((_key, _value)); return; }
NEXT cursor-agent
```

```diff
     pub fn put(&mut self, _key: K, _value: V) {
-        if self.items.iter().all(|(k, _)| k != &_key) { if self.items.len() >= self.cap { self.items.remove(0); } self.items.push((_key, _value)); } }
+        if let Some(i) = self.items.iter().position(|(k, _)| k == &_key) { self.items.remove(i); self.items.push((_key, _value)); return; }
         if self.items.iter().all(|(k, _)| k != &_key) { if self.items.len() >= self.cap { self.items.remove(0); } self.items.push((_key, _value)); }
     }
```

### Hop 7 — cursor-agent

```text
REPLACE 39
        self.items.iter().find(|(k, _)| k == _key).map(|(_, v)| v)
NEXT codex
```

```diff
     pub fn peek(&self, _key: &K) -> Option<&V> {
-        None
+        self.items.iter().find(|(k, _)| k == _key).map(|(_, v)| v)
     }
```

### Hop 8 — codex

```text
REPLACE 54
        if self.items.is_empty() { None } else { Some(self.items.remove(0)) }
NEXT cursor-agent
```

```diff
     pub fn pop_lru(&mut self) -> Option<(K, V)> {
-        None
+        if self.items.is_empty() { None } else { Some(self.items.remove(0)) }
     }
```

### Hop 9 — cursor-agent

`get` still cannot drop the miss path in the same hop.

```text
REPLACE 44
        if let Some(i) = self.items.iter().position(|(k, _)| k == _key) { let p = self.items.remove(i); self.items.push(p); return self.items.last().map(|(_, v)| v); }
        None
NEXT codex
```

```diff
     pub fn get(&mut self, _key: &K) -> Option<&V> {
+        if let Some(i) = self.items.iter().position(|(k, _)| k == _key) { let p = self.items.remove(i); self.items.push(p); return self.items.last().map(|(_, v)| v); }
         None
     }
```

### Hop 10 — codex

```text
REPLACE 59
        self.items.pop()
NEXT goose
```

```diff
     pub fn pop_mru(&mut self) -> Option<(K, V)> {
-        None
+        self.items.pop()
     }
```

### Hop 11 — goose

Goose wrote a real `REPLACE`. It swapped the whole `clear` signature
for the body, so the crate no longer compiled.

```text
REPLACE 62
        self.items.clear()
NEXT claude-code
```

```diff
-    pub fn clear(&mut self) {}
+        self.items.clear()
```

### Hop 12 — claude-code

```text
REPLACE 62
    pub fn clear(&mut self) { self.items.clear(); }
NEXT codex
```

```diff
-        self.items.clear()
+    pub fn clear(&mut self) { self.items.clear(); }
```

### Hop 13 — codex

```text
REPLACE 66
        self.items.iter().rev().map(|(k, _)| k).collect()
NEXT cursor-agent
```

```diff
     pub fn keys_mru(&self) -> Vec<&K> {
-        Vec::new()
+        self.items.iter().rev().map(|(k, _)| k).collect()
     }
```

### Hop 14 — cursor-agent

```text
REPLACE 71
        self.items.iter().map(|(k, _)| k).collect()
NEXT codex
```

```diff
     pub fn keys_lru(&self) -> Vec<&K> {
-        Vec::new()
+        self.items.iter().map(|(k, _)| k).collect()
     }
```

### Hop 15 — codex

```text
REPLACE 75
        self.items.last().map(|(k, _)| k)
NEXT cursor-agent
```

```diff
     pub fn recent(&self) -> Option<&K> {
-        None
+        self.items.last().map(|(k, _)| k)
     }
```

### Hop 16 — cursor-agent

```text
REPLACE 79
        self.items.first().map(|(k, _)| k)
NEXT codex
```

```diff
     pub fn oldest(&self) -> Option<&K> {
-        None
+        self.items.first().map(|(k, _)| k)
     }
```

### Hop 17 — codex

```text
REPLACE 84
        if let Some(i) = self.items.iter().position(|(k, _)| k == _key) { let p = self.items.remove(i); self.items.push(p); true } else { false }
DONE
```

```diff
     pub fn touch(&mut self, _key: &K) -> bool {
-        false
+        if let Some(i) = self.items.iter().position(|(k, _)| k == _key) { let p = self.items.remove(i); self.items.push(p); true } else { false }
     }
```

`cargo test` for `lru`: 10 passed.

Impl after hop 17 (tests unchanged):

```rust
    pub fn cap(&self) -> usize {
        self.cap
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn contains(&self, _key: &K) -> bool {
        self.items.iter().any(|(k, _)| k == _key)
    }

    pub fn peek(&self, _key: &K) -> Option<&V> {
        self.items.iter().find(|(k, _)| k == _key).map(|(_, v)| v)
    }

    pub fn get(&mut self, _key: &K) -> Option<&V> {
        if let Some(i) = self.items.iter().position(|(k, _)| k == _key) { let p = self.items.remove(i); self.items.push(p); return self.items.last().map(|(_, v)| v); }
        None
    }

    pub fn put(&mut self, _key: K, _value: V) {
        if let Some(i) = self.items.iter().position(|(k, _)| k == &_key) { self.items.remove(i); self.items.push((_key, _value)); return; }
        if self.items.iter().all(|(k, _)| k != &_key) { if self.items.len() >= self.cap { self.items.remove(0); } self.items.push((_key, _value)); }
    }

    pub fn pop_lru(&mut self) -> Option<(K, V)> {
        if self.items.is_empty() { None } else { Some(self.items.remove(0)) }
    }

    pub fn pop_mru(&mut self) -> Option<(K, V)> {
        self.items.pop()
    }

    pub fn clear(&mut self) { self.items.clear(); }

    pub fn keys_mru(&self) -> Vec<&K> {
        self.items.iter().rev().map(|(k, _)| k).collect()
    }

    pub fn keys_lru(&self) -> Vec<&K> {
        self.items.iter().map(|(k, _)| k).collect()
    }

    pub fn recent(&self) -> Option<&K> {
        self.items.last().map(|(k, _)| k)
    }

    pub fn oldest(&self) -> Option<&K> {
        self.items.first().map(|(k, _)| k)
    }

    pub fn touch(&mut self, _key: &K) -> bool {
        if let Some(i) = self.items.iter().position(|(k, _)| k == _key) { let p = self.items.remove(i); self.items.push(p); true } else { false }
    }
```

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

## What these runs showed

- Register and `list --local` bring all five adapters up, including
  goose.
- Agents pick the next peer. This LRU run never sent the token to
  copilot; fifo did.
- The two-line cap is visible on `put` (hops 5–6) and `get` (hop 9
  keeps the `None` miss path).
- Goose can land a `REPLACE` (hop 11). A broken signature is a later
  hop's problem — claude-code restored `clear`.
- `DONE` with a green `cargo test` ends the problem (hop 17). `DONE`
  with a broken crate still advances the token (fifo hop 4).
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
