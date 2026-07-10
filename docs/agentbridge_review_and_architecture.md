# agentbridge — PR Review & Architecture Analysis

> PR #88 · `feat(agentbridge): CLI coding-agent interconnect with MAS coordination over SLIM A2A`
> Branch: `feat/agentbridge` → `main`
> Author: Luca Muscariello · Draft · +16,359 / -90 · 60 files changed

---

## PR Review

### Overview

Introduces three new crates and a 4-terminal demo:

- `crates/agentbridge` — adapter library (`CliAdapter` trait, `ContextPacket`, per-tool adapters)
- `crates/agentbridge_cli` — binary: `register`, `list`, `handoff`, `delegate`, `coordinate`
- `crates/shadi_mas` — MAS coordination backbone (`DevelopmentEngine`, quorum-vote finalization)
- `scripts/agentbridge_shell{1-4}_*.sh` — reproducible 4-terminal SLIM demo

Core patterns (trait abstraction, engine isolation, test coverage for the engine) are solid. Several correctness issues and design rough edges are worth addressing before merge.

---

### Correctness Issues

**1. Demo script uses `--quorum 1` — no voting actually occurs**

`agentbridge_shell4_coordinate.sh` runs with `--quorum 1` and two agents. In `coordinate.rs`, `effective_quorum = quorum.min(agents.len())` → 1. With quorum=1, the first proposal immediately triggers finalization before the vote round executes. The "staggered voting → winner elected by peers" story in the PR description doesn't hold for this demo. Either use `--quorum 2` in the demo or document that quorum=1 is a "first-proposal wins" mode.

**2. `try_finalize` tallies votes from the accumulated `self.votes` map, not per-call votes**

Votes are accumulated across the entire epoch in `self.votes`. Each time `try_finalize` is called (once per incoming proposal when `proposals.len() >= quorum`), it re-iterates `self.votes` and increments `votes_for` on the proposal entries. If `try_finalize` is called more than once for the same epoch without clearing votes (possible when quorum < N), votes are double-counted. The staggered scheme in `coordinate.rs` avoids this when `quorum == N`, but with `quorum < N` earlier proposals trigger finalization before the vote round runs.

**3. `EventId` collision on retry within an epoch**

```rust
// crates/agentbridge_cli/src/commands/coordinate.rs
EventId(format!("prop-{}-e{epoch}", agent.0))
EventId(format!("vote-{}-e{epoch}", voter.0))
```

If an agent fails and retries within the same epoch, the duplicate `EventId` is silently rejected by `seen_events`. The failure path only prints "proposal failed" — it doesn't handle the case where a retry within the same epoch is a no-op. Add a suffix (monotonic counter or UUID) to IDs to avoid accidental deduplication.

**4. `vote_event` reuses `accepted: bool` to signal "valid endorsee"**

```rust
let ev = vote_event(&voter.id, &endorsee, epoch, valid);
runtime.apply(ev);
```

When `valid = false`, the event is submitted with `accepted: false`, which the engine treats as a no-op rejection vote. This is coincidentally correct but semantically wrong — an unrecognised endorsee shouldn't be submitted to the engine at all. Cleaner: skip `runtime.apply` when `!valid`, eliminating the `accepted` parameter from `vote_event`.

---

### Design Concerns

**5. `chrono_now()` returns Unix seconds, not ISO 8601**

The doc comment on `ContextPacket.created_at` says "ISO 8601 creation timestamp" but the implementation (`crates/agentbridge/src/context.rs`) produces a plain integer string like `"1748700000"`. Fix the comment or format as `YYYY-MM-DDTHH:MM:SSZ`.

**6. `DirError` doesn't implement `std::error::Error`**

`DirError` only implements `Display`, so it can't be boxed as `Box<dyn Error>`, used with `anyhow::Context`, or propagated with `?` in most error contexts. Add `impl std::error::Error for DirError {}`.

**7. `std::thread::park()` as keep-alive in `register.rs`**

```rust
println!("Adapter is running. Press Ctrl-C to stop.");
std::thread::park();
```

`thread::park()` can return spuriously (POSIX `EINTR`, signal handlers). Use `loop { std::thread::sleep(Duration::MAX); }` instead.

**8. `build_proposal_list` shows only first line of each proposal**

The vote prompt gives agents only the first non-empty line per proposal (capped at 100 chars). For a typical implementation this is often just the function signature. Agents can't meaningfully vote on correctness from a signature alone. Consider showing the first N lines (e.g. 10) or a content hash + first line.

---

### Minor / Style

**9. Unused `Mutex` import in `coordinate.rs`**

```rust
use std::sync::{Arc, Mutex};  // Mutex is unused
```

**10. `register.rs` match arm repetition**

The `claude-code`, `copilot`, `codex` match arms are identical modulo adapter type (~20 lines each). A small generic helper would halve the code. Not blocking.

---

### Positive Highlights

- `DevelopmentEngine` is cleanly isolated behind `CoordinationEngine` trait with no I/O — fully unit-testable; 30+ tests cover deduplication, stale epoch, force-finalize, unknown participant.
- `CliToolAdapter<A>` blanket impl is an elegant zero-cost bridge between the CLI-world and MAS-world traits.
- The staggered proposal+vote ordering comment in `coordinate.rs` is exactly right — well-documented invariant.
- Demo scripts source a shared `agentbridge_env.sh` for consistent config — good practice for reproducible demos.
- `ContextPacket::to_bytes`/`from_bytes` are clean and the round-trip test is present.

---

### Blocker Summary

| # | Severity | Item |
|---|----------|------|
| 1 | Medium | Demo quorum=1 doesn't exercise voting — misleads the test plan |
| 2 | Medium | `try_finalize` vote double-count when quorum < N |
| 3 | Low | `EventId` collision risk on retry |
| 4 | Low | `vote_event` `accepted` semantics / spurious engine event |
| 5 | Low | `chrono_now` not ISO 8601 |
| 6 | Low | `DirError` missing `Error` impl |
| 7 | Low | `thread::park()` spurious wakeup risk |

---

## Architecture Analysis

### Component Map

```
agentbridge_cli (binary)
 ├── register   → spawns A2A listener on SLIM node (agntcy/shadi/<tool>-a2a)
 ├── coordinate → MasRuntime<DevelopmentEngine> proposal+vote loop
 ├── delegate   → one-shot LiveA2ATaskAdapter dispatch over A2A/SLIM
 ├── handoff    → ContextPacket snapshot → inject
 └── list       → DIR search via dirctl

crates/agentbridge (adapter library)
 ├── CliAdapter trait         (agent_id, snapshot_context, inject_context, execute_prompt)
 ├── CliToolAdapter<A>        (blanket bridge: CliAdapter → ToolAdapter for MAS use)
 ├── adapters/                (claude_code, copilot, codex, cursor_agent, generic_stdio)
 ├── context.rs               (ContextPacket — portable JSON session snapshot)
 └── dir_registry.rs          (AdapterOasfRecord + dirctl publish/search)

crates/shadi_mas (coordination backbone)
 ├── MasRuntime<E>            (thin event journal, pluggable engine)
 ├── DevelopmentEngine        (proposal + vote tally + quorum finalization)
 ├── CoordinationEngine trait (pattern(), apply(), counters())
 └── LiveA2ATaskAdapter       (remote dispatch over A2A/SLIM)
```

---

### Data Flow

#### `agentbridge coordinate --goal "..." --agents claude-code,copilot,codex --quorum 3`

```
User goal string
  → build_agents() resolves specs
      • claude-code  → ClaudeCodeAdapter  → CliToolAdapter<ClaudeCodeAdapter>
      • copilot      → CopilotAdapter     → CliToolAdapter<CopilotAdapter>
      • slim:<id>    → LiveA2ATaskAdapter (remote A2A dispatch)
  → DevelopmentEngineConfig::new([agents], quorum, max_rounds)
  → MasRuntime::new(DevelopmentEngine::new(Epoch(0), config))

  Loop per epoch:
    Proposal phase:
      For each agent:
        proposal_prompt(goal, epoch, prior_proposals) → invoke_tool()
        ToolCall { arguments: prompt.as_bytes() } → ToolAdapter::call()
        Subprocess / A2A round-trip → code string
        proposals.push((agent_id, code))

    Endorsement phase:
      Apply proposals[0..N-1] to engine  (Applied — quorum not yet met)
      All agents evaluate proposals → vote_prompt() → invoke_tool()
      runtime.apply(vote_event(...))     (votes stored in DevelopmentEngine.votes)
      Apply proposals[N-1]              (triggers try_finalize())
        → tally votes → select max(votes_for) → EventOutcome::Finalized

  finish():
    runtime.engine().selected_artifact(Epoch(epoch))
    write to --output file or print to stdout
```

#### `agentbridge register --tool copilot --slim-endpoint 127.0.0.1:47357`

```
CopilotAdapter::new("copilot", cwd)
  → run_slim_listener("copilot", adapter, endpoint, secret)
      Connect to SLIM node (TLS certs from $SHADI_TMP_DIR/shadi-slim-mtls/)
      create_app_with_secret(Name("agntcy/shadi/copilot-a2a"), secret)
      AgentBridgeRequestHandler → AgentBridgeExecutor → SlimRpcHandler
      server.serve_async()  ← blocks until Ctrl-C

Incoming A2A message:
  AgentBridgeExecutor.execute()
    extract prompt from A2A message parts
    adapter.execute_prompt(prompt) → String
    return StreamResponse::CompleteTask(TaskStatus::Completed)
```

#### `agentbridge handoff --from "generic-stdio:tool-a" --to "generic-stdio:tool-b"`

```
GenericStdioAdapter::spawn("source", "tool-a", [])
  src.snapshot_context()
    → {"cmd":"snapshot"} on subprocess stdin
    ← {"ok":true,"data":{...}} ContextPacket JSON
  save to file if --save provided
GenericStdioAdapter::spawn("destination", "tool-b", [])
  dst.inject_context(&ctx)
    → {"cmd":"inject","context":{...}} on subprocess stdin
    ← {"ok":true}
```

---

### Key Abstractions

#### `CliAdapter` — Central tool abstraction

```rust
pub trait CliAdapter: Send + Sync {
    fn agent_id(&self) -> &AgentId;
    fn snapshot_context(&self) -> Result<ContextPacket, CliAdapterError>;
    fn inject_context(&self, ctx: &ContextPacket) -> Result<(), CliAdapterError>;
    fn execute_prompt(&self, prompt: &str) -> Result<String, CliAdapterError>;
}
```

Five implementations: `ClaudeCodeAdapter`, `CopilotAdapter`, `CodexAdapter`, `CursorAgentAdapter`, `GenericStdioAdapter`. All subprocess-based in Phase 1/2.

#### `CliToolAdapter<A>` — Trait bridge

```rust
impl<A: CliAdapter> ToolAdapter for CliToolAdapter<A> {
    fn call(&self, request: ToolCall) -> Result<ToolResult, String> {
        let prompt = String::from_utf8(request.arguments)?;
        let response = self.inner.execute_prompt(&prompt)?;
        Ok(ToolResult { payload: response.into_bytes(), .. })
    }
}
```

Zero-cost adapter: converts `ToolCall.arguments` bytes → UTF-8 prompt → `execute_prompt()` → `ToolResult.payload` bytes. Allows any `CliAdapter` to participate in `MasRuntime<DevelopmentEngine>` without changes to either side.

#### `DevelopmentEngine` — Coordination logic

| State | Type | Purpose |
|-------|------|---------|
| `proposals` | `BTreeMap<AgentId, ArtifactEntry>` | Submitted code per agent |
| `votes` | `BTreeMap<AgentId, AgentId>` | voter → endorsed agent |
| `selected` | `BTreeMap<Epoch, Vec<u8>>` | Finalized artifact per epoch |

Finalization: `proposals.len() >= quorum` → tally `votes` → `max(votes_for)` wins → advance `active_epoch`. Tie-break: alphabetically first `AgentId` (BTreeMap order).

#### `MasRuntime<E>` — Event journal

```rust
pub struct MasRuntime<E: CoordinationEngine> {
    engine: E,
    history: Vec<AppliedTransition>,
}
```

Thin wrapper: no business logic. Records every `(event_id, outcome)` for audit. `engine()` / `engine_mut()` give direct access to state.

#### `ContextPacket` — Portable session snapshot

```
id              UUID v4
source_agent    name of originating agent
created_at      timestamp (currently Unix seconds)
conversation    Vec<{role, content}>
code_context    {files, git_diff, active_file, project_root}
artifacts       Vec<{name, content, media_type}>
```

Serialised as JSON. Used by `handoff`, A2A transport, and agent resume. No tool-specific fields — fully portable between agents.

#### `LiveA2ATaskAdapter` — Remote dispatch

```rust
pub struct LiveA2ATaskAdapter {
    config: LiveA2ATaskAdapterConfig,
    dispatches: Mutex<Vec<LiveTaskDispatchRecord>>,
}
```

Connects to SLIM node → `A2AClient::send_message()` → awaits `Task` response → stores `LiveTaskDispatchRecord { task, response, elapsed_ms }`. Used by `coordinate` for `slim:<agent-id>` specs and by `delegate`.

---

### Transport & Discovery

#### A2A over SLIM

```
Coordinator
  → LiveA2ATaskAdapter
  → A2AClient::send_message(prompt as A2A Message)
  → [TLS + shared-secret auth]
  → SLIM node (127.0.0.1:47357)
  → SlimRpcHandler → AgentBridgeExecutor
  → adapter.execute_prompt(prompt)
  → TaskStatus::Completed
  → [TLS]
  → A2AClient receives Task with response
```

SLIM name convention: `agntcy/shadi/<agent-id>-a2a`. TLS certs loaded from `$SHADI_TMP_DIR/shadi-slim-mtls/`.

#### DIR (Agent Directory)

- Publish: `dirctl push` with OASF record (name, skills, SLIM locator)
- Search: `dirctl search --skill "agent_orchestration/context_handoff"`
- Default server: `prod.gateway.ads.outshift.io:443`
- Optional: DIR is not required for local coordination

---

### Design Decisions

| Decision | Rationale |
|----------|-----------|
| `CliToolAdapter<A>` blanket impl | Zero-cost bridge; neither trait needs to change |
| Staggered proposal+vote ordering | Endorsement phase runs before quorum-triggering proposal; voting actually influences outcome |
| `ContextPacket` as portable JSON | Human-debuggable, OASF-compatible, no tool-specific coupling |
| Epoch-based event isolation | Prevents replay/reorder; stale events rejected, future events deferred |
| `MasRuntime` as pure event journal | Engine holds all state; runtime is audit log — clean testability |
| Subprocess-first adapters | Any tool implementing newline-delimited JSON wire protocol is a valid adapter |
| SLIM name convention as address book | No separate registry service needed for Phase 1/2 |
| `max_rounds` force-finalization | Bounded execution regardless of agent failures |
| `GenericStdioAdapter` wire protocol | `{"cmd":"snapshot"\|"inject"\|"execute", ...}` — lowest-possible barrier to new tool integration |

---

### Implementation Status

| Feature | Status |
|---------|--------|
| `register` + A2A listener | ✅ wired |
| `coordinate` (local + `slim:`) | ✅ wired |
| `delegate`, `handoff` | ✅ wired |
| `DevelopmentEngine` + voting | ✅ wired |
| All 5 CLI adapters | ✅ wired |
| DIR publish/search | ✅ wired (requires `dirctl`) |
| 43 unit tests passing | ✅ |
| `list --local` (SLIM discovery) | 🔄 stubbed |
| `shadi_memory` ContextPacket persistence | 🔄 not wired |
| SLIM group relay | 🔄 not wired |
| DID/VC identity verification | 🔄 pluggable, currently allow-all |
| Multi-pattern coordination (Cascade, Resource) | 🔄 types exist, not in CLI |

---

## Demo Run Results

```
cargo run -p agentbridge_demo
```

All 3 scenarios passed:

**Scenario 1 — Handoff Chain**
`claude-code` snapshotted a `ContextPacket` (866 bytes, 2 messages, 1 file, 1 artifact).
Successfully injected into `copilot`, `codex`, and `cursor-agent`.

**Scenario 2 — 4-Agent Coordination** (`quorum=4`)
- 4 agents proposed distinct implementations (Result, Option, `unwrap_or_default`, `Box<dyn Error>`)
- 3 agents voted before the 4th proposal triggered finalization
- `claude-code` won (3/4 votes) — Result-based implementation
- Counters: `applied=8 finalized=1 rejected=0 deferred=0`

```
Vote tally: claude-code=3, copilot=1, codex=0, cursor-agent=0
Winner: claude-code (Result-based, 3/4 endorsements)

Winning artifact:
pub fn parse(input: &str) -> Result<serde_json::Value, serde_json::Error> {
    serde_json::from_str(input)
}
```

**Scenario 3 — CliToolAdapter Bridge**
`CliToolAdapter<MockCodingAgent>` correctly wraps the adapter as `ToolAdapter` and dispatches a prompt through `MasRuntime`.

---

## Key Files Reference

| What | Where |
|------|-------|
| `CliAdapter` trait | [crates/agentbridge/src/adapter.rs](crates/agentbridge/src/adapter.rs) |
| `ContextPacket` | [crates/agentbridge/src/context.rs](crates/agentbridge/src/context.rs) |
| DIR registry | [crates/agentbridge/src/dir_registry.rs](crates/agentbridge/src/dir_registry.rs) |
| `DevelopmentEngine` | [crates/shadi_mas/src/engines/development.rs](crates/shadi_mas/src/engines/development.rs) |
| `MasRuntime` | [crates/shadi_mas/src/runtime.rs](crates/shadi_mas/src/runtime.rs) |
| `LiveA2ATaskAdapter` | [crates/shadi_mas/src/experiments/mod.rs](crates/shadi_mas/src/experiments/mod.rs) |
| CLI entry point | [crates/agentbridge_cli/src/main.rs](crates/agentbridge_cli/src/main.rs) |
| `register` command | [crates/agentbridge_cli/src/commands/register.rs](crates/agentbridge_cli/src/commands/register.rs) |
| `coordinate` command | [crates/agentbridge_cli/src/commands/coordinate.rs](crates/agentbridge_cli/src/commands/coordinate.rs) |
| 4-agent demo | [examples/agentbridge_demo/src/main.rs](examples/agentbridge_demo/src/main.rs) |
| Demo scripts | [scripts/agentbridge_shell{1-4}_*.sh](scripts/) |
