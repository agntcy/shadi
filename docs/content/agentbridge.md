# agentbridge — General-Purpose Agent Interconnect over A2A

agentbridge is the layer of SHADI that bridges agents over the
[A2A protocol](slim_a2a.md) — via SLIM transport, DID identity, DIR
discovery, and `shadi_mas` for autonomous multi-round coordination — so they
can exchange context, delegate tasks to each other, and coordinate
autonomously toward a shared goal. Nothing in that mechanism is specific to
any one kind of agent: any agent that speaks A2A, or the simpler agentbridge
subprocess protocol (`GenericStdioAdapter`), can be bridged this way.

Today's built-in adapters happen to target CLI coding tools — Claude Code,
GitHub Copilot CLI, OpenAI Codex CLI, Cursor Agent — because interconnecting
coding assistants was the motivating use case this was first built for, and
they remain the flagship, most-exercised example throughout this page and the
demos. The `CliAdapter` trait, the A2A/SLIM transport, and the coordination
runtime underneath them don't know or care that they're wrapping coding
tools; a bridge for any other class of agent looks the same.

## Motivation

The concrete problem that motivated agentbridge: every major coding assistant
operates in isolation. When a developer switches tools (e.g., from Claude Code
to Copilot), all conversation history, open files, and accumulated context is
lost. There was no standard way to:

- Hand off an in-progress session from one tool to another,
- Ask one agent to generate a specific artifact for another agent's task, or
- Have multiple agents propose solutions and converge on the best one without human mediation.

agentbridge solves this using the existing SHADI infrastructure: A2A for task
delegation, SLIM for transport, DIR for discovery, and `shadi_mas` for
autonomous multi-round coordination — the same general-purpose stack that
would bridge any other kind of agent, applied here to coding tools first.

## Quick start

The self-contained demo needs no infrastructure — it runs all scenarios
against an in-process SLIM node:

```bash
# Run the self-contained demo (all scenarios, no infrastructure required)
cargo run -p agentbridge_demo

# Run the 4-agent coordination scenario
cargo run -p agentbridge_demo -- --scenario coordination

# Run the context handoff scenario
cargo run -p agentbridge_demo -- --scenario handoff

# Run the CliAdapter → ToolAdapter bridge scenario
cargo run -p agentbridge_demo -- --scenario bridge
```

See [examples/agentbridge_demo/README.md](https://github.com/agntcy/shadi/blob/main/examples/agentbridge_demo/README.md)
for step-by-step instructions and the live 4-terminal SLIM demo.

## Architecture

### Deployment topology

`register` and `coordinate` run on separate hosts (or separate terminals on the
same machine). SLIM is the authenticated transport bus between them.

```mermaid
flowchart LR
  subgraph reg["agentbridge register  (one per agent)"]
    direction TB
    tool["CLI tool\ngeneric-stdio | claude-code | copilot | codex | cursor-agent"]
    ca["CliAdapter\nexecute_prompt(prompt) → text"]
    srv["A2A server\nAgentBridgeRequestHandler\nInMemoryTaskStore"]
    tool -- "stdin / stdout" --> ca --> srv
  end

  slim{{"SLIM node\nagntcy/shadi/&lt;tool&gt;-a2a\nmTLS · DID auth"}}

  subgraph coord["agentbridge coordinate"]
    direction TB
    mas["MasRuntime&lt;DevelopmentEngine&gt;\nproposal → vote → finalize"]
    sta["SlimToolAdapter\n(one per --agents spec)"]
    laa["LiveA2ATaskAdapter\nSLIMRPC dispatch"]
    mas --> sta --> laa
  end

  srv <-- "A2A tasks  (text/plain)" --> slim
  slim <-- "A2A tasks  (text/plain)" --> laa
```

`cursor-agent` doesn't have a `register` listener yet (`register --tool cursor-agent`
is not implemented) — it participates as a `coordinate` peer only (see below).

### Coordination loop

Each epoch has two phases: every agent proposes a code artifact, then every
agent votes on the best one. Finalization fires as soon as endorsements reach
the quorum — triggered by applying the last proposal of the epoch.

```mermaid
sequenceDiagram
  participant MAS as DevelopmentEngine
  participant CO as coordinator
  participant A  as copilot (SLIM)
  participant B  as codex   (SLIM)

  rect rgb(240,248,255)
    note right of CO: epoch 0 — proposal phase
    CO->>A: proposal prompt  (goal, epoch 0)
    A-->>CO: code artifact
    CO->>B: proposal prompt  (goal, epoch 0)
    B-->>CO: code artifact
    CO->>MAS: apply ExternalBytes(copilot_code)
    CO->>MAS: apply ExternalBytes(codex_code)
  end

  rect rgb(240,255,240)
    note right of CO: epoch 0 — vote phase
    CO->>A: vote prompt  (goal + both proposals)
    A-->>CO: endorses copilot
    CO->>B: vote prompt  (goal + both proposals)
    B-->>CO: endorses copilot
    CO->>MAS: apply ToolResult{copilot, accepted:true}
    CO->>MAS: apply ExternalBytes(codex_vote_artifact)
    note over MAS: quorum met on last apply
    MAS-->>CO: Finalized — winner: copilot  (2/2 votes)
  end

  CO->>CO: write artifact → output.rs
```

### A2A task flow inside a registered adapter

How one incoming task travels from the SLIM node down to the wrapped CLI tool
and back:

```mermaid
sequenceDiagram
  participant CO as coordinator
  participant SL as SLIM node
  participant SV as AgentBridgeRequestHandler
  participant EX as AgentBridgeExecutor
  participant AD as CliAdapter

  CO->>SL: SendMessage(task envelope)
  SL->>SV: SLIMRPC frame
  SV->>EX: execute(context)
  EX->>EX: strip "body:\n" envelope header
  EX->>AD: execute_prompt(prompt)
  AD->>AD: invoke CLI tool  (subprocess / API)
  AD-->>EX: response text
  EX-->>SV: StatusUpdate(Working)
  EX-->>SV: Task{Completed, message: response_text}
  SV-->>SL: stream response
  SL-->>CO: Task{Completed}
```

## Three interaction models

### 1. Context handoff

Export a session snapshot from one tool and import it into another. The
`ContextPacket` carries conversation history, open files, git diff, and any
generated artifacts.

```
agentbridge handoff --from claude-code --to copilot
```

`--from` / `--to` accept the same specs as `coordinate` (`claude-code`,
`copilot`, `codex`, `cursor-agent`, `generic-stdio:<cmd>`, `slim:<id>`).
A bare subprocess command still opens GenericStdio. `--save` /
`--from-file` persist the packet.

The snapshot is an LLM summary of the source session this cycle, not a
true session export.

1. Source adapter → `snapshot_context()` → `ContextPacket` (LLM summary)
2. Optional `--save` of the packet
3. Destination adapter → `inject_context(packet)`

### 2. Task delegation

One tool commissions a specific subtask to another and retrieves the artifact.

```
agentbridge delegate --to codex "write unit tests for src/parser.rs"
```

Implemented via `LiveA2ATaskAdapter::dispatch()` from `shadi_mas`. The result
is an A2A artifact containing the generated code.

### 3. Autonomous multi-round coordination

```
agentbridge coordinate \
  --goal "implement a JSON parser" \
  --agents claude-code,copilot,codex,cursor-agent \
  --quorum 3
```

1. `MasRuntime<DevelopmentEngine>` is instantiated with all four adapters.
2. Each agent invokes its CLI tool via `ToolAdapter::call()` → code proposal.
3. Proposals are published to a SLIM group session.
4. Agents vote via `SemanticPayload::ToolResult { accepted: true }`.
5. When `accepted_votes ≥ quorum` → `EventOutcome::Finalized` → loop exits.
6. The winning artifact is written to disk. Human approval is optional.

## A2A server — how `register` exposes an adapter over SLIM

When `agentbridge register` is called with `--slim-endpoint`, it starts a
full A2A server that makes the local adapter reachable to any SLIM peer.

### SLIM address

Each adapter registers under the hierarchical name:

```
agntcy/shadi/<tool>-a2a
```

For example, `--tool copilot` listens as `agntcy/shadi/copilot-a2a`. The
`coordinate` command reaches it with `--agents slim:copilot`.

### Request handler stack

```
SlimRpcHandler (shadi_a2a)          ← decodes SLIMRPC frames
  └─ AgentBridgeRequestHandler      ← full A2A protocol surface
       ├─ DefaultRequestHandler      ← routes send/get/list/cancel/subscribe/push
       │    └─ AgentBridgeExecutor   ← executes the task against the CliAdapter
       └─ InMemoryTaskStore          ← stores task state for get/list operations
```

`AgentBridgeRequestHandler` implements all A2A request methods and delegates
to `DefaultRequestHandler` for everything except `get_extended_agent_card`,
which returns a static `AgentCard` describing the adapter:

| Field | Value |
|-------|-------|
| `capabilities.streaming` | `true` |
| `capabilities.push_notifications` | `false` |
| `default_input_modes` | `["text/plain"]` |
| `default_output_modes` | `["text/plain"]` |

### Task execution flow

See the [A2A task flow sequence diagram](#a2a-task-flow-inside-a-registered-adapter)
above. The executor streams two events: a `Working` status update followed by a
`Completed` task carrying the adapter's response text as a `text/plain` part.
Task history (the original prompt message) is included in the completed task.

### TLS certificate resolution

The listener needs a client-side mTLS certificate to authenticate with the
SLIM node. Resolution order:

1. **Explicit env vars** — `SLIM_TLS_CERT` + `SLIM_TLS_KEY` + `SLIM_TLS_CA`
2. **Agent-specific fallback** — `.tmp/shadi-slim-mtls/client-<agent_id>.crt` / `.key`
3. **Generic fallback** — `.tmp/shadi-slim-mtls/client.crt` / `.key`

`SLIM_TLS_CA` defaults to `.tmp/shadi-slim-mtls/ca.crt`. Generate the
certificate bundle once with `tools/generate_slim_mtls_certs.sh`.

### Lifecycle

```
register --slim-endpoint 127.0.0.1:47357
  │
  ├─ service.connect()               connect to SLIM node (TLS 1.3)
  ├─ shadi_identity::require_did_auth_from_env()
  │    + shadi_identity::create_app() authenticate with this agent's DID
  ├─ app.subscribe()                 subscribe to agntcy/shadi/<tool>-a2a
  ├─ srv.serve()                     start the A2A/SLIMRPC event loop
  │
  │  [agentbridge] ready — listening on agntcy/shadi/<tool>-a2a
  │
  ├─ … handles tasks until Ctrl-C …
  │
  └─ app.unsubscribe()       deregister from the SLIM topic
     service.disconnect()    close the SLIM connection
     service.shutdown()      clean up
```

### Wiring to `coordinate`

The `coordinate` command uses `slim:<agent-id>` specs to reach registered
adapters. It constructs a `LiveA2ATaskAdapter` per spec, which speaks the
same SLIMRPC protocol to the listening server:

```
coordinate --agents slim:copilot,slim:codex
  │
  ├─ LiveA2ATaskAdapter { peer: agntcy/shadi/copilot-a2a }
  └─ LiveA2ATaskAdapter { peer: agntcy/shadi/codex-a2a }
        │
        └─ SlimToolAdapter::call() → dispatch() → receives Task(Completed)
```

The A2A traffic is printed with `┌─ A2A ─→` / `┌─ A2A ←─` banners showing
the agent ID, coordination phase, epoch, and elapsed milliseconds.

## Security model

agentbridge executes real coding tools on your machine and reaches them over a
shared SLIM bus, so two trust boundaries matter.

### The register listener is a remote-execution surface

A registered adapter forwards every incoming A2A task straight to the local CLI
tool (`execute_prompt` → subprocess). Some adapters run their tool with elevated
permissions — for example, `CopilotAdapter` invokes `copilot --allow-all-tools`
so it can act non-interactively.

!!! warning "Any peer able to reach the listener can drive local code execution"

    Any peer able to reach `agntcy/shadi/<tool>-a2a` on the SLIM node can drive
    local code execution through the wrapped CLI tool.

Controls:

- **Enforced**: `register --slim-endpoint` refuses to start unless the process is
  running under a SHADI sandbox with network blocked by default
  (`shadi_sandbox::sandbox_enforced_from_env`). Seatbelt (macOS), Landlock
  (Linux), and AppContainer + Job Objects (Windows) sandboxes are all
  kernel-enforced and inherited by child processes, so wrapping `agentbridge
  register` in [`shadictl`](sandbox.md) — `shadictl --net-block --net-allow
  <slim-endpoint> --read <mtls-cert-dir> -- agentbridge register ...` — is
  enough to confine whatever CLI tool the adapter spawns to run a task.
  agentbridge has no sandboxing code of its own; it leans entirely on the same
  enforcement `shadictl` already provides. The `--read` grant needs the SLIM
  mTLS client certificate directory so the listener itself can still connect;
  on macOS, resolve it to its real path first (`/tmp` is a symlink to
  `/private/tmp`, and Seatbelt's rules don't match a path reached through the
  symlink if generated for the canonicalized form).
- The listener prints a warning on start-up naming the tool that will execute
  incoming tasks.
- Only expose the listener to trusted SLIM peers (`SLIM_MEMBER_DIDS` decides
  *who* may send a task; the sandbox decides *what* it can do once it runs).
- Keep the SLIM node on loopback (`127.0.0.1`) for local demos; only bind a
  routable address when the peer set is trusted and authenticated.

### DID authentication

SLIM apps authenticate with a per-agent DID, not a shared secret. Set
`SHADI_SLIM_AUTH=did` and `SLIM_HUMAN_SEED` (the human root key every agent's
DID is derived from), plus `SLIM_MEMBER_DIDS` — the allow-list of DIDs
permitted to participate. `shadi_identity::require_did_auth_from_env` enforces
this: it errors out if `SHADI_SLIM_AUTH` isn't `did`, so `register`,
`delegate`, and `coordinate` cannot silently fall back to a shared secret.

See the [Secure Agent Group Demo](demos/did-agent-group.md) for a full
worked example, including how DID admission is verified against the
allow-list.

### Transport authentication

Peer-to-peer A2A traffic runs over SLIMRPC with mutual TLS. The listener resolves
a client certificate from `SLIM_TLS_CERT` / `SLIM_TLS_KEY` / `SLIM_TLS_CA`, an
agent-specific fallback, or a generic fallback (see
[TLS certificate resolution](#tls-certificate-resolution)). Generate the bundle
with `tools/generate_slim_mtls_certs.sh` and keep the CA private to the peers you
trust.

## Multi-agent coordination layer (`shadi_mas`)

`shadi_mas` is the coordination runtime that sits above the transport layer,
consumed by `agentbridge coordinate`. It provides epoch-disciplined state
machines that can drive any multi-agent pattern to a deterministic
finalization outcome.

```
SemanticEvent  ──►  CoordinationEngine  ──►  EventOutcome
(proposal,          (PreferenceEngine,        (Applied,
 vote, tool          DevelopmentEngine,         Finalized,
 result, …)          …)                         Rejected,
                                               Deferred)
```

Engines are wrapped in `MasRuntime<E>` which tracks the full history of applied
transitions and exposes `engine()` / `engine_mut()` for inspection.

| Engine | Pattern | Finalization criterion |
|--------|---------|----------------------|
| `PreferenceEngine` | Consensus on a scalar value | Median of proposals when quorum is met |
| `DevelopmentEngine` | Consensus on a code artifact | Most-endorsed artifact when quorum is met |

Three adapter traits connect the runtime to real infrastructure:

| Trait | Implementation | Purpose |
|-------|---------------|---------|
| `MessagingAdapter` | `RecordingMessagingAdapter` / `LiveSlimMessagingAdapter` | Publish events to SLIM |
| `TaskAdapter` | `RecordingTaskAdapter` / `LiveA2ATaskAdapter` | Dispatch A2A tasks |
| `ToolAdapter` | `RecordingToolAdapter` / `CommandToolAdapter` / `CliToolAdapter` | Invoke LLMs / CLI tools |

### `DevelopmentEngine` — the coordination core

`DevelopmentEngine` is a `CoordinationEngine` that coordinates code artifacts
rather than scalar numeric values (unlike `PreferenceEngine`).

| Event | Payload | Effect |
|-------|---------|--------|
| Code proposal | `ExternalBytes(code)` | Stored keyed by source agent |
| Endorsement vote | `ToolResult { accepted: true, tool_name: agent_id }` | Votes tallied per artifact |
| Other payloads | any | Accepted silently (applied) |
| Finalization | — | Artifact with most votes wins; epoch advances |
| Max rounds exceeded | — | Force-finalizes with current best artifact |

Epoch discipline prevents duplicate, stale, and future-epoch events from
corrupting the state machine.

??? note "Goal analysis: what was asked for vs. what is built"

    ### Original goal

    > "Write a new application to interconnect Claude CLI, Copilot CLI, Codex CLI or
    > other similar applications to exchange context or messages, artifacts etc.
    > Use the A2A protocol, SLIM/shadi for transport, and DIR to discover each other.
    > Make agents coordinate with a goal and work in autonomy until the work is achieved."

    ### What is implemented

    | Requirement | Status | Detail |
    |-------------|--------|--------|
    | Architecture design | ✅ | Full A2A + SLIM + DIR stack documented |
    | Coordination backbone | ✅ | `shadi_mas` migrated + `DevelopmentEngine` added |
    | `CliAdapter` trait | ✅ | Unified interface for any coding tool |
    | `ContextPacket` | ✅ | Portable session snapshot with JSON serde |
    | Generic subprocess adapter | ✅ | `GenericStdioAdapter` — newline-delimited JSON protocol |
    | Native adapters | ✅ | `ClaudeCodeAdapter`, `CopilotAdapter`, `CodexAdapter`, `CursorAgentAdapter` |
    | `CliToolAdapter` bridge | ✅ | Any `CliAdapter` → `shadi_mas::ToolAdapter` |
    | DIR registration | ✅ | Real AgentCard (skills + SLIM endpoint) published to DIR's `integration/a2a` OASF module, DID carried in `authors` |
    | DIR-driven group discovery | ✅ | `MemberSource` (skill search / DID lookup / explicit list) resolves SLIM group trust sets from Directory — see the [Agent Directory Discovery Demo](demos/dir-group-discovery.md) |
    | `agentbridge` library | ✅ | `crates/agentbridge` |
    | CLI binary | ✅ | `agentbridge register \| list \| handoff \| delegate \| coordinate` |
    | Live A2A transport | ✅ | `LiveA2ATaskAdapter` wired into `register` and `coordinate` |
    | Quorum-vote finalization | ✅ | `DevelopmentEngine` — autonomous, no human required |
    | SLIM group relay | ✅ | `shadictl slim a2a-collaborate` (SLIMRPC `Collaborate` RPC via `shadi_a2a::A2AGroupChannel`) — see [SLIM and A2A](slim_a2a.md) |
    | DID-identified secure groups | ✅ | Moderator-invited channels admitted against a per-agent DID allow-list — see the [Secure Agent Group Demo](demos/did-agent-group.md) |

    ### What remains

    | Requirement | Detail |
    |-------------|--------|
    | `shadi_memory` ContextPacket persistence | `SqlCipherStore` wire-up in `crates/shadi_memory/` |
    | `register --tool cursor-agent` | Not yet implemented; `cursor-agent` is currently reachable only via `coordinate` |

    ### Does the existing middleware help?

    **Yes — substantially.** Every component of the target architecture existed or
    was extended from existing SHADI infrastructure:

    - **A2A**: `shadi_a2a::A2AChannelBuilder` and `a2a-slimrpc` provide identity-verified A2A over SLIMRPC. `LiveA2ATaskAdapter` in `shadi_mas` is a ready-made task dispatcher.
    - **SLIM**: `agent_transport_slim::NativeSlimSession` and `LiveSlimMessagingAdapter` provide group and point-to-point messaging. The `LiveSlimGroupSender` handles multi-agent broadcast with receipt acknowledgements.
    - **DIR**: `shadictl dir` subcommand already integrates with `agntcy/dir`. OASF records are the natural format for adapter agent cards.
    - **shadi_mas**: The `DevelopmentEngine` required a new `PatternKind` and engine implementation, but the runtime, epoch discipline, adapter traits, and test infrastructure were already in place.
    - **shadi_memory**: `SqlCipherStore` provides encrypted `ContextPacket` persistence with no additional code.

    The middleware was designed for exactly this use case. The agentbridge application is an adapter layer on top of an existing, tested coordination stack.

??? note "File map"

    ```
    crates/
      agentbridge/              ← library
        src/
          adapter.rs           ← CliAdapter trait + CliToolAdapter
          context.rs           ← ContextPacket, CodeContext, ArtifactPayload
          dir_registry.rs      ← AgentCard → OASF module wrapping + dirctl integration
          member_source.rs     ← MemberSource (skill/DID/explicit list) group-discovery trait
          adapters/
            generic_stdio.rs   ← subprocess JSON protocol adapter
            claude_code.rs     ← Claude Code native adapter
            copilot.rs         ← GitHub Copilot CLI adapter
            codex.rs           ← OpenAI Codex CLI adapter
            cursor_agent.rs    ← Cursor Agent adapter
      agentbridge_cli/          ← binary (agentbridge)
        src/
          main.rs
          commands/
            register.rs        ← register + SLIM A2A listener
            list.rs
            handoff.rs
            delegate.rs        ← single-shot A2A dispatch
            coordinate.rs      ← MasRuntime<DevelopmentEngine> loop
      shadi_mas/               ← coordination runtime
        src/
          engines/
            development.rs     ← DevelopmentEngine
            preference.rs      ← PreferenceEngine (existing)
          experiments/
            mod.rs             ← live adapters + experiment runners
        tests/
          integration_slim.rs  ← SLIM node integration tests (run with --include-ignored)
    examples/
      agentbridge_demo/         ← self-contained demo (no infrastructure needed)
    ```

## Next steps

- Try the [Secure Agent Group Demo](demos/did-agent-group.md) for a full multi-agent, DID-identified walkthrough.
- Try the [Agent Directory Discovery Demo](demos/dir-group-discovery.md) to form and grow a group by discovering members in DIR instead of naming them by hand.
- Review the transport layer in [SLIM and A2A](slim_a2a.md).
- See sandboxing guidance for running bridged tools in [Sandbox and Policies](sandbox.md).
