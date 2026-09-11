# SHADI MAS

SHADI MAS is the coordination runtime for a team of agents. The crate is
`shadi_mas` (`agntcy-shadi-mas`). It owns group semantics: epochs, event
discipline, finalization, and the engines that apply a class update.

It does not own transport, identity, sandboxing, or a coding-tool CLI.
Those stay in SLIM / A2A, `shadi_identity`, `shadictl`, and
[AgentBridge](agentbridge.md). AgentBridge *consumes* this crate
(`agentbridge coordinate`).

The two group phases — joint model, then joint solve — are
[ASSEMBLY and CONVERGE](assembly-converge.md). This page is the runtime
those phases run on.

## What it is not

| Name | Role |
|------|------|
| **SHADI MAS** (`shadi_mas`) | Coordination state machines and class engines |
| **`slim_mas`** | SLIM group membership and DID allow-list evaluation (`shadictl slim-mas`) |
| **AgentBridge** | Register, list, handoff, delegate, and the `coordinate` driver that feeds this runtime |

`slim_mas` admits *who* may sit on a SLIM channel. SHADI MAS decides
*how* a roster advances a shared problem once those peers can talk.

## Place in the stack

```text
agentbridge coordinate / other driver
        │
        ▼
   MasRuntime<E>          ← history + apply()
        │
        ▼
 CoordinationEngine       ← one class (development, preference, …)
        │
        ▼
  adapter traits          ← Messaging / Task / Tool
        │
        ▼
 SLIM · A2A · CLI tools
```

The runtime is provider-agnostic. A `ToolAdapter` may call MCP or an
Agent Skill. The engine sees `SemanticEvent` values, not a vendor API.

## Event loop

Every step is one event:

```text
SemanticEvent  ──►  CoordinationEngine::apply  ──►  EventOutcome
```

`SemanticEvent` carries `PatternKind`, `EventMetadata` (`event_id`,
`epoch`, `source`), and a `SemanticPayload`. Outcomes are:

| Outcome | Meaning |
|---------|---------|
| `Applied` | Accepted; epoch not finished |
| `Deferred { expected, received }` | Future epoch; hold until the engine is there |
| `Finalized(summary)` | Epoch complete; class update applied |
| `Rejected(reason)` | Duplicate, stale, wrong pattern, wrong payload, or unknown participant |

`MasRuntime<E>` wraps any engine. `apply()` forwards to the engine and
appends an `AppliedTransition` to `history()` for audit and replay.

### Epoch discipline

Engines reject work that would corrupt the round:

- `DuplicateEvent` — same `event_id` seen again
- `StaleEpoch` — event epoch behind the engine
- `FinalizedEpoch` — that epoch already closed
- `IncompatiblePattern` / `IncompatiblePayload`
- `UnknownParticipant`

`RuntimeCounters` tally applied, rejected, deferred, duplicates, stale,
and finalized events.

## Group protocol

`ProtocolPhase` is `Assembly` or `Converge`. ASSEMBLY infers a class
(`AssemblySession`, `CLASS <name>` or keywords). CONVERGE runs the
engine for that class. A token SHADI does not implement is
`PatternKind::Unmapped` and must not start a solver.

The protocol is not limited to numbers. A class may use a code artifact,
a scalar, or another local state. Announce form is class-specific.
Details, skills, CLI flags, and honest claims are in
[ASSEMBLY and CONVERGE](assembly-converge.md).

## Engines

Each implemented class is a `CoordinationEngine`. `coordinate --pattern`
selects one.

| Engine | `PatternKind` | Local state | When the epoch finalizes |
|--------|---------------|-------------|--------------------------|
| `DevelopmentEngine` | `Development` | code artifact (`ExternalBytes`) | Quorum of endorsements (`ToolResult`) |
| `PreferenceEngine` | `Preference` | `z_i` (`ScalarProposal`) | Full inbox; Jacobi step |
| `CascadeEngine` | `Cascade` | last order | Full inbox; order-up-to + smoothing |
| `ResourceEngine` | `Resource` | last extraction | Full inbox; dual step and stock |

`Development` is the `coordinate` default. The three paper engines share
`ConvergeController` (improvement signal, `VOTE CONTINUE` / `VOTE STOP`,
plateau, class horizon). In the CLI,
`PatternKind::is_converge_class()` means “use that scalar driver.”
Development is still CONVERGE; it uses the artifact driver.

To add a class: implement `CoordinationEngine` in
`crates/shadi_mas/src/engines/<pattern>.rs`, export it from
`engines/mod.rs`, and add a `PatternKind` variant. The runtime and
adapter traits do not change.

## Adapter traits

These are the only I/O seams the crate defines:

| Trait | Job |
|-------|-----|
| `MessagingAdapter` | Publish bytes to a topic |
| `TaskAdapter` | Dispatch a `TaskEnvelope` (pattern, epoch, body) |
| `ToolAdapter` | Invoke a tool (`ToolProvider::Mcp` or `AgentSkills`) |

`shadi_mas::experiments` ships the implementations that exist today:

| Type | Role |
|------|------|
| `RecordingMessagingAdapter` | In-memory publish log |
| `RecordingTaskAdapter` | In-memory dispatch log |
| `LiveA2ATaskAdapter` | Live A2A `SendMessage` over SLIMRPC or official unicast |

[AgentBridge](agentbridge.md) supplies `CliToolAdapter` (`ToolAdapter`
over a local CLI profile). Unsigned inbound A2A parks as
`AUTH_REQUIRED` (`experiments::auth_required`); a forged DID is
rejected.

!!! note "SLIM client certificates"

    `LiveA2ATaskAdapter` authenticates to the SLIM node with TLS 1.3 and
    the same client material as AgentBridge: `SLIM_TLS_CERT` /
    `SLIM_TLS_KEY` / `SLIM_TLS_CA`, or
    `$SHADI_TMP_DIR/shadi-slim-mtls/client[-<agent>].crt|.key` and
    `ca.crt`. Verify those files before use:

    ```bash
    openssl x509 -text -noout -in <certificate_file>
    ```

    Required checks: not expired and already valid; RSA ≥ 2048 bits or
    ECDSA on P-256 or stronger; SHA-2 signature (not MD5 or SHA-1).
    Self-signed material is for lab and CI only. Generate the bundle
    with `tools/generate_slim_mtls_certs.sh`. Do not hardcode
    certificates or keys.

## How AgentBridge drives it

`agentbridge coordinate` builds a roster, optionally runs ASSEMBLY, then
constructs `MasRuntime<E>` for the inferred class and feeds events from
tool replies.

- `--pattern development` — propose / endorse until quorum or
  `--max-rounds`
- `--pattern preference\|cascade\|resource` — scalar CONVERGE driver
- `--assembly` — ASSEMBLY first; CONVERGE starts only if the class is
  implemented

Listeners, DID proof, and `delegate` / `handoff` stay on the AgentBridge
page. This crate does not parse clap flags.

## Tests

```bash
cargo test -p agntcy-shadi-mas --lib
```

Unit tests cover ASSEMBLY inference, each engine’s epoch rules, and
`AUTH_REQUIRED` policy. There is no live-SLIM integration test in this
crate today.

## File map

```text
crates/shadi_mas/src/
  lib.rs
  types.rs          PatternKind, SemanticEvent, outcomes, CONVERGE ballots
  runtime.rs        CoordinationEngine, MasRuntime
  adapters.rs       Messaging / Task / Tool traits
  assembly.rs       AssemblySession, infer_pattern
  engines/
    development.rs
    preference.rs
    cascade.rs
    resource.rs
    converge.rs     ConvergeController, ConvergeSurface, announce/vote parse
  experiments/
    mod.rs          recording adapters, LiveA2ATaskAdapter
    auth_required.rs
```

## Next steps

- Group phases, skills, and claims: [ASSEMBLY and CONVERGE](assembly-converge.md)
- Driver CLI and listeners: [AgentBridge](agentbridge.md)
- Transport and admission: [SLIM and A2A](slim_a2a.md)
- Crate README: [`crates/shadi_mas/README.md`](https://github.com/agntcy/shadi/blob/main/crates/shadi_mas/README.md)
