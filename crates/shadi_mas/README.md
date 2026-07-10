# shadi_mas

`shadi_mas` is the coordination runtime for SHADI multi-agent systems. It owns
group and coordination semantics: round-tagged events, epoch discipline, duplicate
and stale-event rejection, finalization rules, and the state machines that drive
concrete coordination patterns.

## Role in the SHADI workspace

```
shadi_mas  ←  coordination logic (this crate)
shadi_a2a  ←  A2A task and agent interaction
agent_transport_slim  ←  secure MLS-backed messaging transport
agentbridge ←  CLI coding-agent adapter layer built on top of shadi_mas
```

Tool integration is modeled as a provider-aware adapter boundary with support
for both MCP tools and AgentSkills-defined skills, so the same coordination
runtime works with any LLM backend.

## Core abstractions

### `CoordinationEngine` (trait)

```rust
pub trait CoordinationEngine: Send + Sync {
    fn pattern(&self) -> PatternKind;
    fn apply(&mut self, event: SemanticEvent) -> EventOutcome;
    fn counters(&self) -> RuntimeCounters;
}
```

Engines consume `SemanticEvent` values and return `EventOutcome`:
`Applied`, `Deferred`, `Finalized(summary)`, or `Rejected(reason)`.

### `MasRuntime<E>`

Wraps any engine with history tracking and a single `apply()` entry point.
History accumulates every `AppliedTransition` for audit and replay.

### Adapter traits

| Trait | Purpose |
|-------|---------|
| `MessagingAdapter` | Publish events to SLIM topics (real or recording) |
| `TaskAdapter` | Dispatch A2A tasks (real or recording) |
| `ToolAdapter` | Invoke LLM tools via MCP or AgentSkills |

## Engines

### `PreferenceEngine`

Aggregates numeric proposals (votes) per epoch and finalizes with the median
when a quorum is reached. Used for consensus on scalar decisions.

### `DevelopmentEngine`

Coordinates multiple agents toward a shared code artifact:

- Each agent submits a code proposal via `SemanticPayload::ExternalBytes`.
- Agents endorse proposals via `SemanticPayload::ToolResult { accepted: true }`.
- Finalization selects the artifact with the most endorsements when quorum is met.
- `max_rounds` provides a safety cutoff to prevent infinite loops.

```rust
let config = DevelopmentEngineConfig::new(
    ["claude", "copilot", "codex"].map(AgentId::from),
    /* quorum */ 2,
    /* max_rounds */ 10,
);
let mut runtime = MasRuntime::new(DevelopmentEngine::new(Epoch(0), config));

// Each agent submits a proposal.
runtime.apply(dev_event("claude", b"fn parse(input: &str) -> Ast { ... }"));
runtime.apply(dev_event("copilot", b"fn parse(s: &str) -> Result<Ast> { ... }"));

// Votes determine the winner; quorum triggers finalization.
runtime.apply(vote_event("codex", "copilot"));
runtime.apply(dev_event("codex", b"fn parse(s: &str) -> Option<Ast> { ... }"));
// → EventOutcome::Finalized(summary)

let winner = runtime.engine().selected_artifact(Epoch(0)).unwrap();
```

### Extending with new engines

Add `crates/shadi_mas/src/engines/<pattern>.rs`, implement `CoordinationEngine`,
and export from `engines/mod.rs`. The runtime, adapter, and test infrastructure
work without modification.

## Experiments module

`shadi_mas::experiments` contains:

- **`RecordingMessagingAdapter`** / **`RecordingTaskAdapter`** / **`RecordingToolAdapter`** — in-memory test doubles with full inspection.
- **`LiveSlimMessagingAdapter`** — real SLIM group or point-to-point transport.
- **`LiveA2ATaskAdapter`** — real A2A task dispatch over SLIMRPC.
- **`CommandToolAdapter`** — invokes an external LLM (Ollama, etc.) via subprocess stdin/stdout.
- `run_preference_experiment_with_adapters`, `run_cascade_experiment_with_adapters`, `run_resource_experiment_with_adapters` — full coordination loops usable in examples and integration tests.

## Examples

```bash
# Preference consensus over recording adapters (no infrastructure needed)
cargo run --example preference_experiment -p agntcy-shadi-mas

# Cascade supply-chain coordination
cargo run --example cascade_experiment -p agntcy-shadi-mas

# Resource extraction governance
cargo run --example resource_experiment -p agntcy-shadi-mas

# Live protocol spotcheck (needs slimctl + an LLM backend; vLLM by default)
cargo run --example mas_live_protocol_spotcheck -p agntcy-shadi-mas
```

## Integration tests

`tests/integration_slim.rs` exercises live adapters against a real SLIM node
started via `slimctl slim start`. Requires pre-generated mTLS certs
(`tools/generate_slim_mtls_certs.sh`) and `slimctl` in PATH.

```bash
cargo test -p agntcy-shadi-mas --test integration_slim -- --test-threads=1
```
