# shadi_mas

`shadi_mas` (`agntcy-shadi-mas`) is the coordination runtime for SHADI
multi-agent systems. It owns group semantics: epochs, event discipline,
finalization, and the engines that apply a class update.

The site page is [SHADI MAS](../../docs/content/shadi-mas.md). The two
group phases are
[ASSEMBLY and CONVERGE](../../docs/content/assembly-converge.md).

This crate does not own transport, identity, sandboxing, or the
`agentbridge` CLI. It is also not `slim_mas` (SLIM group membership /
`shadictl slim-mas`).

## Role

```text
agentbridge coordinate
        │
        ▼
   MasRuntime<E>
        │
        ▼
 CoordinationEngine     development | preference | cascade | resource
        │
        ▼
 MessagingAdapter / TaskAdapter / ToolAdapter
```

A `ToolAdapter` may call MCP or an Agent Skill. Engines see
`SemanticEvent` values only.

## Event loop

```rust
pub trait CoordinationEngine: Send + Sync {
    fn pattern(&self) -> PatternKind;
    fn apply(&mut self, event: SemanticEvent) -> EventOutcome;
    fn counters(&self) -> RuntimeCounters;
}
```

`MasRuntime<E>` forwards `apply()` and records every
`AppliedTransition` on `history()`. Outcomes are `Applied`,
`Deferred`, `Finalized`, or `Rejected` (duplicate, stale epoch, wrong
pattern or payload, unknown participant).

## ASSEMBLY and CONVERGE

- **ASSEMBLY** — `AssemblySession` infers a class from `CLASS <name>`
  or keywords. An unimplemented token is `PatternKind::Unmapped`.
- **CONVERGE** — peers announce local state in the form the class
  requires; the engine applies the update after a full epoch.

The protocol is not limited to numbers. `DevelopmentEngine` is CONVERGE
for a code artifact. The paper examples use `ConvergeController`.
`Unmapped` must not start a solver. Do not claim an LLM proved a
theorem (`proves_llm_mas` is not a runtime flag).

## Engines

| Engine | Local state | Finalization |
|--------|-------------|--------------|
| `DevelopmentEngine` | `ExternalBytes` artifact | Quorum of `ToolResult` endorsements |
| `PreferenceEngine` | `ScalarProposal` (`z_i`) | Jacobi step on a full inbox |
| `CascadeEngine` | last order | Order-up-to + smoothing |
| `ResourceEngine` | last extraction | Dual step and stock |

`PreferenceEngine` is not a median vote. After a full epoch it sets

```text
z_i ← (c_i + 2β Σ_{j∈N_i} z_j) / (1 + 2β d_i)
```

The unique fixed point is `z* = (I + 2β L)⁻¹ c`.

`agentbridge coordinate --pattern development` (default) uses
`DevelopmentEngine`. `--pattern preference|cascade|resource` uses the
scalar CONVERGE driver. `--assembly` infers the class first.

To add a class: implement `CoordinationEngine` under `src/engines/`,
export it from `engines/mod.rs`, and add a `PatternKind` variant.

```rust
let config = DevelopmentEngineConfig::new(
    ["claude", "copilot", "codex"].map(AgentId::from),
    /* quorum */ 2,
    /* max_rounds */ 10,
);
let mut runtime = MasRuntime::new(DevelopmentEngine::new(Epoch(0), config));

runtime.apply(dev_event("claude", b"fn parse(input: &str) -> Ast { ... }"));
runtime.apply(dev_event("copilot", b"fn parse(s: &str) -> Result<Ast> { ... }"));
runtime.apply(vote_event("codex", "copilot"));
runtime.apply(dev_event("codex", b"fn parse(s: &str) -> Option<Ast> { ... }"));
// → EventOutcome::Finalized(summary)

let winner = runtime.engine().selected_artifact(Epoch(0)).unwrap();
```

## Adapters

Traits in `adapters.rs`: `MessagingAdapter`, `TaskAdapter`,
`ToolAdapter`.

`shadi_mas::experiments` provides `RecordingMessagingAdapter`,
`RecordingTaskAdapter`, and `LiveA2ATaskAdapter` (A2A over SLIMRPC or
official unicast, DID-proof envelopes, `AUTH_REQUIRED` handling).
AgentBridge supplies `CliToolAdapter`.

`LiveA2ATaskAdapter` uses TLS 1.3 and SLIM client certificates from
`SLIM_TLS_CERT` / `SLIM_TLS_KEY` / `SLIM_TLS_CA` or
`$SHADI_TMP_DIR/shadi-slim-mtls/`. Verify those files
(`openssl x509 -text -noout -in <cert>`): not expired; RSA ≥ 2048 or
P-256+; SHA-2 signatures; self-signed only for lab. Do not hardcode
certificates or keys.

## Tests

```bash
cargo test -p agntcy-shadi-mas --lib
```
