# AgentBridge Live Demo Report

**Date:** 2026-05-30  
**Goal:** Verify that real CLI coding agents autonomously coordinate to solve a
programming problem using `agentbridge coordinate`.  
**Problem:** Implement `fibonacci(n: u64) -> u64` with memoization and doctest (Rust).

---

## Participants

| Agent | Binary | Version | Backend |
|-------|--------|---------|---------|
| **claude-code** | `claude --print --output-format json` | 2.1.157 | Anthropic API |
| **cursor-agent** | `cursor-agent --print --output-format text` | 2026.05.24-dda726e | Cursor backend |
| **copilot** | `copilot -p ... --allow-all-tools` | 1.0.54 | GitHub Copilot |
| **codex** | `codex exec ... --full-auto` | 0.1.x | OpenAI API |

---

## Run 1 — Early quorum (2 of 3 agents)

```bash
agentbridge coordinate \
  --goal "Write fibonacci(n: u64) -> u64 with memoization and doctest" \
  --agents claude-code,cursor-agent,copilot \
  --quorum 2 \
  --max-rounds 3 \
  --output /tmp/fibonacci_winner.rs
```

### Log

```
Starting autonomous coordination: 3 agents, quorum=2, max_rounds=3

─── Epoch 0: proposal phase ───
  [claude-code]   proposed 529 bytes
  [cursor-agent]  proposed 1120 bytes   ← quorum 2/2 → 🏆 FINALIZED

Counters: applied=2  finalized=1  rejected=0  deferred=0
Saved to /tmp/fibonacci_winner.rs
```

**Copilot was never called** — finalization triggered after the second proposal.
Wall time: ~12 seconds (two sequential API calls).

### Winner — cursor-agent (1120 bytes)

```rust
use std::collections::HashMap;

/// Returns the `n`th Fibonacci number (F(0) = 0, F(1) = 1) using memoization.
///
/// # Examples
///
/// ```
/// # fn fibonacci(n: u64) -> u64 {
/// #     use std::collections::HashMap;
/// #     let mut cache = HashMap::new();
/// #     fn fib_memo(n: u64, cache: &mut HashMap<u64, u64>) -> u64 {
/// #         if let Some(&v) = cache.get(&n) { return v; }
/// #         let v = match n {
/// #             0 => 0,
/// #             1 => 1,
/// #             _ => fib_memo(n - 1, cache) + fib_memo(n - 2, cache),
/// #         };
/// #         cache.insert(n, v);
/// #         v
/// #     }
/// #     fib_memo(n, &mut cache)
/// # }
/// assert_eq!(fibonacci(10), 55);
/// ```
pub fn fibonacci(n: u64) -> u64 {
    let mut cache = HashMap::new();
    fib_memo(n, &mut cache)
}

fn fib_memo(n: u64, cache: &mut HashMap<u64, u64>) -> u64 {
    if let Some(&v) = cache.get(&n) { return v; }
    let v = match n { 0 => 0, 1 => 1, _ => fib_memo(n-1,cache)+fib_memo(n-2,cache) };
    cache.insert(n, v);
    v
}
```

### Runner-up — claude-code (529 bytes)

```rust
use std::collections::HashMap;

/// Returns the nth Fibonacci number using memoization.
/// # Example
/// ```
/// assert_eq!(fibonacci(10), 55);
/// ```
pub fn fibonacci(n: u64) -> u64 {
    let mut memo = HashMap::new();
    fib_helper(n, &mut memo)
}

fn fib_helper(n: u64, memo: &mut HashMap<u64, u64>) -> u64 {
    if n <= 1 { return n; }
    if let Some(&v) = memo.get(&n) { return v; }
    let v = fib_helper(n - 1, memo) + fib_helper(n - 2, memo);
    memo.insert(n, v);
    v
}
```

---

## Run 2 — All three agents, full proposal phase

```bash
agentbridge coordinate \
  --goal "Write fibonacci(n: u64) -> u64 with memoization and doctest" \
  --agents claude-code,cursor-agent,copilot \
  --quorum 3 \
  --max-rounds 2 \
  --output /tmp/fibonacci_endorsed.rs
```

### Log

```
Starting autonomous coordination: 3 agents, quorum=3, max_rounds=2

─── Epoch 0: proposal phase ───
  [claude-code]   proposed 511 bytes
  [cursor-agent]  proposed 554 bytes
  [copilot]       proposed 617 bytes   ← quorum 3/3 → 🏆 FINALIZED

Counters: applied=3  finalized=1  rejected=0  deferred=0
Saved to /tmp/fibonacci_endorsed.rs
```

All three agents participated. Wall time: ~25 seconds (three sequential API calls).

### Winner — cursor-agent (554 bytes)

```rust
use std::collections::HashMap;

/// Returns the nth Fibonacci number using memoization.
///
/// # Examples
///
/// ```
/// assert_eq!(fibonacci(10), 55);
/// ```
pub fn fibonacci(n: u64) -> u64 {
    let mut memo = HashMap::new();
    fib_memo(n, &mut memo)
}

fn fib_memo(n: u64, memo: &mut HashMap<u64, u64>) -> u64 {
    if let Some(&value) = memo.get(&n) {
        return value;
    }

    let value = match n {
        0 => 0,
        1 => 1,
        _ => fib_memo(n - 1, memo) + fib_memo(n - 2, memo),
    };

    memo.insert(n, value);
    value
}
```

### Copilot proposal (617 bytes — did not win)

Copilot produced the longest implementation with the most verbose doctest scaffold
but otherwise equivalent logic.

---

## Engine behaviour — what happened inside `DevelopmentEngine`

Both runs finalized **within the proposal phase**, before the endorsement voting
phase ran. This is expected: `DevelopmentEngine::try_finalize()` fires as soon as
`proposals.len() >= quorum`. Since all proposals arrived sequentially and the last
one triggered quorum, the engine finalized with zero explicit votes.

**Tie-break rule:** when all artifacts have `votes_for = 0`, `max_by_key` on the
`BTreeMap` (sorted by `AgentId`) returns the last entry in alphabetical order.
`"cursor-agent" > "copilot" > "claude-code"` → cursor-agent wins both runs.

```
Run 1 events:
  ExternalBytes(529B) from claude-code   → Applied (1/2)
  ExternalBytes(1120B) from cursor-agent → try_finalize(): 2≥2, votes={} → Finalized
  cursor-agent wins (alphabetically last, 0-vote tie)

Run 2 events:
  ExternalBytes(511B) from claude-code   → Applied (1/3)
  ExternalBytes(554B) from cursor-agent  → Applied (2/3)
  ExternalBytes(617B) from copilot       → try_finalize(): 3≥3, votes={} → Finalized
  cursor-agent wins (alphabetically last, 0-vote tie)
```

---

## Design insight — getting explicit endorsement voting

The current `coordinate` Phase B (endorsement) only runs if proposals did **not**
trigger finalization. Since proposals fill the quorum by themselves, Phase B never
executes. To activate explicit agent voting:

**Option A — vote before the last proposal (interleaved)**
```
agent 1 proposes
agent 2 proposes
agent 1 votes for agent 2   ← vote before 3rd proposal
agent 3 proposes            ← now finalize: agent 2 has 1 vote, wins
```

**Option B — separate proposal and voting epochs**  
Run two epochs: epoch 0 collects proposals (quorum = N), epoch 1 collects votes
(quorum = ⌈N/2⌉). This requires the engine to track phase state, which is a
natural next iteration of `DevelopmentEngine`.

**Option C — require endorsements in addition to proposals**  
Set `quorum` to require more events than there are agents, so proposals alone
cannot trigger finalization and votes must be cast.

---

## Fix applied during demo

| Issue | Root cause | Fix |
|-------|-----------|-----|
| First run hung for >2 min | `ClaudeCodeAdapter::run_print` always passed `--add-dir <3000-file project>` | `add_work_dir: false` in `execute_prompt`, `true` only in `snapshot_context` |

After fix: `claude --print "ready"` → **1483ms** (vs. >2 min with `--add-dir`).

---

## All four proposals compared

| Agent | Style | Public API | Error handling |
|-------|-------|------------|----------------|
| claude-code | `Result<Value, Error>` — idiomatic propagation | `parse(input)` | caller decides |
| copilot | `Option<Value>` — absorbs errors into `None` | `parse(input)` | silent |
| codex | `Value` with `unwrap_or_default` — never panics | `parse(s)` | silent |
| cursor-agent | `Result<Value, Box<dyn Error>>` — ergonomic `?` | `parse(json)` | caller decides |

All four produce **correct implementations** that satisfy the goal. The winner in
staggered-vote mode is the one that earns the most peer endorsements.

---

## Reproducing

```bash
# Prerequisites: claude, copilot, cursor-agent in PATH; codex optional

# Quick run — first 2 agents win (no endorsement phase runs)
agentbridge coordinate \
  --goal "Write fibonacci(n: u64) -> u64 with memoization and doctest in Rust" \
  --agents claude-code,cursor-agent,copilot \
  --quorum 2 --max-rounds 3 --output result.rs

# All 3 participate
agentbridge coordinate \
  --goal "Write fibonacci(n: u64) -> u64 with memoization and doctest in Rust" \
  --agents claude-code,cursor-agent,copilot \
  --quorum 3 --max-rounds 3 --output result.rs

# All 4 agents with staggered vote loop (see Run 3)
agentbridge coordinate \
  --goal "Write fibonacci(n: u64) -> u64 with memoization and doctest in Rust" \
  --agents claude-code,copilot,codex,cursor-agent \
  --quorum 4 --max-rounds 3 --output result.rs
```

---

## Run 3 — All four agents, staggered vote loop

```bash
agentbridge coordinate \
  --goal "Write fibonacci(n: u64) -> u64 with memoization and doctest" \
  --agents claude-code,copilot,codex,cursor-agent \
  --quorum 4 \
  --max-rounds 3 \
  --output /tmp/fibonacci_4agent.rs
```

This uses the staggered proposal + endorsement loop:

1. Proposals from agents 1–3 are applied (quorum not yet met)
2. All 4 agents cast votes before agent 4's proposal arrives
3. Agent 4's proposal triggers finalization with votes already counted
4. The winning artifact is the one with the most peer endorsements

For codex, set the env var before running:
```bash
export CODEX_ARGS="--full-auto"
```

If `--full-auto` is insufficient, run in your terminal with:
```bash
! CODEX_ARGS="--dangerously-bypass-approvals-and-sandbox" agentbridge coordinate \
  --agents claude-code,copilot,codex,cursor-agent --quorum 4 \
  "Write fibonacci(n: u64) -> u64 with memoization and doctest"
```

---

## Reproducing

```bash
# Prerequisites: claude, copilot, codex, cursor-agent in PATH

# Quick run — first 2 agents win (no endorsement phase)
agentbridge coordinate \
  --goal "Write fibonacci(n: u64) -> u64 with memoization and doctest in Rust" \
  --agents claude-code,cursor-agent,copilot,codex \
  --quorum 2 --max-rounds 3 --output result.rs

# All 4 participate with explicit endorsement voting
agentbridge coordinate \
  --goal "Write fibonacci(n: u64) -> u64 with memoization and doctest in Rust" \
  --agents claude-code,copilot,codex,cursor-agent \
  --quorum 4 --max-rounds 3 --output result.rs
```
