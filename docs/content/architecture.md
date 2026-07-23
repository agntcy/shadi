# Architecture

SHADI (Secure Host Agentic AI Dynamic Instantiation) is a secure host runtime for
interactive, autonomous agents. It combines secure secret storage, verified
identity, and kernel-enforced sandboxing to reduce the blast radius of agent
actions and prevent unauthorized data access or exfiltration.

## Goals
- Run dynamic, interactive agents with least-privilege access.
- Protect secrets at rest and limit access to verified sessions.
- Enforce kernel-level restrictions so unauthorized operations are blocked by the OS.
- Provide secure, low-latency agent-to-agent messaging via SLIM/A2A,
  DID-authenticated and MLS-encrypted.
- Keep platform support across macOS, Windows, and mobile targets.

!!! warning "Non-goals"

    - Protect against a fully compromised host OS or kernel.
    - Provide complete metadata privacy for network traffic in v1.
    - Replace upstream MLS or OS keystore implementations.

## Architecture overview

SHADI as four layers — control, secure runtime, protected workloads, and the
external systems they're allowed to reach once trust checks pass:

```mermaid
flowchart TB
  subgraph Experience[Experience and Control]
    Operator[Operators and platform teams]
    Configuration[Policies, profiles, and workload configuration]
    Launch[Secure launch orchestration]
  end

  subgraph Platform[SHADI secure runtime]
    Identity[Identity and session trust]
    SecretControl[Secret control plane]
    Delivery[Trusted secret delivery]
    Enforcement[OS sandbox enforcement]
    Memory[Encrypted local memory]
    Transport[Secure agent transport]
  end

  subgraph Workloads[Protected workloads]
    Agents[Agents, tools, and automations]
  end

  subgraph Services[External systems]
    Repos[GitHub and developer systems]
    Models[Model providers]
    Peers[SLIM and A2A peers]
  end

  Operator --> Configuration
  Configuration --> Launch
  Launch --> Identity
  Launch --> SecretControl
  Launch --> Enforcement
  Identity --> SecretControl
  SecretControl --> Delivery
  SecretControl --> Memory
  Enforcement --> Agents
  Delivery -. scoped secret access .-> Agents
  Memory -. encrypted state .-> Agents
  Transport --> Agents
  Agents --> Repos
  Agents --> Models
  Agents --> Peers
```

The system can be read as four presentation layers:

- **Experience and control**: operators, policies, profiles, and `shadictl` define the launch contract before a process starts.
- **Secure runtime**: identity, secret control, trusted delivery, sandboxing, transport, and encrypted memory enforce that contract during execution.
- **Protected workloads**: agents, tools, and automations run inside the approved runtime boundary.
- **External systems**: workloads connect to GitHub, model providers, and SLIM/A2A peers only after policy and trust checks are in place.

## Core components

### 1) Secrets layer
- **OS keystores**: Keychain (macOS/iOS), DPAPI/CNG (Windows), Keystore (Android),
  Secret Service (Linux).
- **1Password backend** (optional): Cross-platform secret storage via the `op` CLI.
  Enabled with the `onepassword` Cargo feature and `SHADI_SECRET_BACKEND=onepassword`.
  Supports team/shared vaults and headless CI via `OP_SERVICE_ACCOUNT_TOKEN`.
- **Access control**: Secrets are accessed only after DID/VC verification.
- **Memory safety**: Secrets are wrapped in `SecretBytes` and zeroized on drop.
- **OpenPGP parsing**: `shadictl` uses `sequoia-openpgp` to ingest keys without calling OS `gpg`.

#### Key modules
- `crates/agent_secrets/src/lib.rs`: `SecretStore` trait, errors, and default store.
- `crates/agent_secrets/src/agent.rs`: `AgentSecretAccess` gates reads/writes on verification.
- `crates/agent_secrets/src/memory.rs`: `SecretBytes` zeroization wrapper.
- `crates/agent_secrets/src/platform`: platform keychain backends.
- `crates/agent_secrets/src/platform/macos.rs`: Keychain storage + key registry for listing.
- `crates/agent_secrets/src/platform/onepassword.rs`: 1Password backend via `op` CLI.
- `crates/shadictl/src/identity_command.rs`: OpenPGP/GPG ingestion and DID derivation commands.
- `crates/shadictl/src/secrets_command.rs`: secret store list/get helpers.

### 1b) Identity derivation and provenance
- **Deterministic derivation**: Agent keys are derived from human identity material
  through a fixed KDF pipeline.
- **KDF details**: HKDF-SHA256 with salt `shadi-agent-derive`, IKM from human
  source bytes (`gpg` or `seed`), and `agent_name` as HKDF info.
- **Output model**: 32-byte Ed25519 seed -> local agent keypair -> `did:key` DID document.
- **Provenance binding**: Optional `{prefix}/{agent}/human_did` binding allows
  explicit linkage from derived agent identity back to a stored human DID.
- **Verification command**: `verify-agent-identity` recomputes derived key + DID
  and compares with stored values; can also enforce human DID binding checks.

#### Key modules
- `crates/shadictl/src/identity_command.rs`: `derive-agent-did`, `derive-agent-identity`,
  `verify-agent-identity`, and derivation helpers, delegating to `shadi_identity::AgentIdentity::derive`.

### 2) Sandbox layer
- **macOS**: Seatbelt profile enforcement for filesystem and network policies.
- **Windows**: AppContainer + ACL allowlists + Job Objects (kill-on-close).
- **CLI**: `shadi` provides JSON policy loading, profile defaults, optional command blocklists, process-scoped secret disclosure, and trusted secret delivery.
- **Portable launcher model**: `shadi` supports built-in profiles
  (`strict`, `balanced`, `connected`) for portable secure launch defaults.
- **Launch-time enforcement**: Policy is resolved before the agent process starts, so the sandbox is not a prompt-level suggestion that the agent can rewrite from inside the session.
- **Operational hardening**: macOS launcher support now resolves relative paths before emitting Seatbelt rules and accounts for required local IPC paths such as 1Password, SLIM runtime state, and temporary trusted-secret broker endpoints.

#### Key modules
- `crates/shadi_sandbox/src/policy.rs`: policy model and helpers.
- `crates/shadi_sandbox/src/platform`: OS-specific sandbox enforcement.
- `crates/shadictl/src/cli_types.rs`: CLI arg parsing.
- `crates/shadictl/src/policy_helpers.rs`: profile defaults and policy resolution.

### 3) Memory layer
- **Local encrypted store**: SQLCipher-backed SQLite for portable, on-device memory.
- **Key management**: Encryption keys live in SHADI secrets (keychain backed).
- **Agent usage**: workloads running on SHADI can persist local state in the encrypted store.

#### Key modules
- `crates/shadi_memory/src/lib.rs`: SQLCipher store and query helpers.
- `crates/shadictl/src/memory_command.rs`: `shadictl memory` helper.
- `crates/shadi_py/src/lib.rs`: SQLCipher bindings.

### 4) Transport layer
- **Identity**: `shadi_identity` authenticates every SLIM peer with a per-agent
  DID-JWT (`SHADI_SLIM_AUTH=did`) instead of a shared secret; group admission
  is checked against an explicit DID allow-list.
- **SLIM/A2A**: point-to-point and moderator/participant group sessions
  additionally enable MLS session encryption for confidentiality and
  integrity between agents (`agent_transport_slim`, `shadictl slim create`/
  `invite`/`join`).
- **Verified sessions**: Messages are only sent/received after DID/VC checks.

### 5) Secret delivery and policy framework

SHADI has a launch-time secret-delivery framework with exact executable
matching: `process_inject_keychain` (explicit disclosure), `process_trusted_secret`
(process-scoped trusted delivery), and `process_secret_policy` (action-based
rules, including `delegate-to-child` final-consumer delivery on Unix/macOS).

For the full rule shapes, the security rationale behind final-consumer
delivery, and the prompt-injection boundary, see
[Security Notes → Secret delivery and disclosure modes](security.md#secret-delivery-and-disclosure-modes).

??? note "Code map (file paths by layer)"

    **Secrets layer**

    - `crates/agent_secrets/src/lib.rs`: `SecretStore` trait, errors, and default store.
    - `crates/agent_secrets/src/agent.rs`: `AgentSecretAccess` gates reads/writes on verification.
    - `crates/agent_secrets/src/memory.rs`: `SecretBytes` zeroization wrapper.
    - `crates/agent_secrets/src/platform`: platform keychain backends.
    - `crates/agent_secrets/src/platform/macos.rs`: Keychain storage + key registry for listing.
    - `crates/agent_secrets/src/platform/onepassword.rs`: 1Password backend via `op` CLI.
    - `crates/shadictl/src/identity_command.rs`: OpenPGP/GPG ingestion and DID derivation commands.
    - `crates/shadictl/src/secrets_command.rs`: secret store list/get helpers.

    **Identity derivation**

    - `crates/shadictl/src/identity_command.rs`: `derive-agent-did`, `derive-agent-identity`,
      `verify-agent-identity`, and derivation helpers, delegating to `shadi_identity::AgentIdentity::derive`.

    **Sandbox layer**

    - `crates/shadi_sandbox/src/policy.rs`: policy model and helpers.
    - `crates/shadi_sandbox/src/platform`: OS-specific sandbox enforcement.
    - `crates/shadictl/src/cli_types.rs`: CLI arg parsing.
    - `crates/shadictl/src/policy_helpers.rs`: profile defaults and policy resolution.

    **Memory layer**

    - `crates/shadi_memory/src/lib.rs`: SQLCipher store and query helpers.
    - `crates/shadictl/src/memory_command.rs`: `shadictl memory` helper.
    - `crates/shadi_py/src/lib.rs`: SQLCipher bindings.

    **Transport layer**

    - `crates/agent_transport_slim/src/lib.rs`: transport adapter, verifier gating, and native SLIM session bootstrap.
    - `crates/agent_transport_slim/src/bin/slim-stdio-bridge.rs`: standalone stdio bridge helper; the same bridge engine is now used directly by shadictl for in-sandbox SLIM sessions.

    **Secret delivery and policy framework**

    - `crates/shadictl/src/trusted_secret_delivery.rs`: secret resolution, exact-program matching, broker lifecycle, and delegated child verification.
    - `crates/shadictl/src/sandbox_snapshot.rs`: launch orchestration, runtime policy augmentation for broker endpoints, and trusted-secret post-spawn delivery.
    - `crates/shadi_sandbox/src/policy.rs`: minimal-profile and local Unix socket opt-in controls.

## Language bindings

SHADI exposes a Python extension for secrets, SQLCipher memory, and sandbox
execution, backed by `crates/shadi_py/src/lib.rs`. See
[API Guide → Language Bindings](api_integration.md#language-bindings) for the
full Rust and Python surface with examples.

## CLI policy resolution

The CLI combines profile defaults, policy file settings, and explicit flags:

- Profile defaults are loaded first (`balanced` by default).
- Policy file values are merged next.
- CLI flags override or extend resulting policy.
- The effective policy can be printed with `--print-policy`.

## Detailed flow diagrams

The overview diagram above shows the main blocks. The following diagrams zoom in
on the paths that matter most when reading or operating the system.

### 1) Identity, secret storage, and memory bootstrap

```mermaid
flowchart LR
  Source[Human identity source] --> Derive[Derive agent identity]
  Derive --> Register[Register trusted secrets]
  Register --> Verify[Verify session and operator context]
  Verify --> Access[Authorize secret access]
  Access --> Protect[Release memory key]
  Protect --> Persist[Persist encrypted state]
```

This is the trust bootstrap path:

1. Human identity material is imported or derived.
2. SHADI stores agent keys, DIDs, and optional provenance bindings in the secret store.
3. Session verification gates later reads.
4. The SQLCipher memory key is retrieved through the same secret-control path rather than living in plaintext config.

### 2) Policy resolution and sandbox launch

```mermaid
flowchart LR
  Profiles[Launcher profiles] --> Resolve[Resolve effective policy]
  Policy[Policy file] --> Resolve
  Overrides[CLI overrides] --> Resolve
  Resolve --> SecretPolicy[Resolve secret delivery intent]
  SecretPolicy --> Runtime[Prepare runtime guardrails]
  Runtime --> Launch[Launch protected process]
```

This launch path matters because the agent does not get to reinterpret the policy from inside the session.

- Profile defaults establish the baseline (`strict`, `balanced`, or `connected`).
- Policy JSON adds exact executable rules and file/network allowances.
- CLI flags override or extend the result.
- Secret rules are resolved before spawn so SHADI knows whether a secret is being disclosed, directly trusted-delivered, or delegated to a child.
- Runtime policy is expanded only as needed, for example to allow a temporary broker endpoint or local Unix socket transport.

### 3) Trusted secret delivery and delegated child flow

```mermaid
sequenceDiagram
  participant SHADI as SHADI runtime
  participant Parent as Parent workload
  participant Broker as Delivery broker
  participant Child as Authorized child tool
  participant Store as Secret store

  SHADI->>Store: Resolve secret rule and target identity
  SHADI->>Parent: Launch protected parent process
  SHADI->>Broker: Create launch-scoped delivery channel
  Broker-->>Parent: Endpoint reference and nonce
  Parent->>Child: Start authorized tool
  Child->>Broker: Request secret delivery
  Broker->>Broker: Verify process identity, executable path, and optional hash
  Broker->>Store: Read approved secret payload
  Store-->>Broker: Secret bytes
  Broker-->>Child: Release one-time secret payload
  Broker-->>Broker: Close channel and revoke reuse
```

This is the main architecture change in the PR series:

- `process_inject_keychain` remains explicit disclosure.
- `process_trusted_secret` provides direct process-scoped trusted delivery.
- `process_secret_policy` adds action-based rules such as `delegate-to-child`.
- On Unix/macOS, SHADI verifies the final child consumer before releasing the secret.

### 4) Runtime workload flow

```mermaid
flowchart LR
  Workload[Protected workload] --> Secrets[Verified secret access]
  Workload --> Memory[Encrypted memory]
  Workload --> Transport[Secure transport]
  Workload --> GitHub[GitHub and developer systems]
  Workload --> Models[Model providers]
  Workload --> Outcomes[Reports, issues, PRs, or actions]
```

Agent workloads sit on top of the same runtime contract:

- secret reads are still gated by verification,
- local persistence still flows through encrypted memory,
- network access still depends on the resolved sandbox policy,
- and transport still uses SLIM/A2A when agents communicate with each other.

## Threats addressed

### Secrets and credential theft
- **Stopped**: Reading secrets without verification.
- **Stopped**: Exfiltration of secrets from disk when keystore access is denied.
- **Stopped**: Accidental logging of secrets by non-verified sessions.
- **Mitigated**: In-memory exposure via zeroization and limited lifetime.

### Identity spoofing / provenance ambiguity
- **Stopped**: Undetected key substitution when `verify-agent-identity` is used.
- **Mitigated**: Agent ownership ambiguity via stored `human_did` binding + verification.

### Filesystem abuse
- **Stopped**: Accessing paths outside allowlists (kernel enforcement).
- **Stopped**: Writing to disallowed paths in sandboxed processes.
- **Mitigated**: Destructive commands via CLI blocklist.

### Network abuse
- **Stopped**: Network access when `net_block` is enabled.
- **Mitigated**: Unapproved endpoints with best-effort `net_allow` guard for
  Python sandbox runners.

### Agent-to-agent data leakage
- **Stopped**: Unverified peers joining a session; DID-JWT authentication and
  (for groups) an explicit member allow-list gate admission.
- **Stopped**: Unauthorized peers reading messages; MLS provides confidentiality
  on point-to-point and group SLIM sessions.
- **Stopped**: Message tampering; MLS provides integrity/authentication.

### Privilege escalation
- **Mitigated**: Prompt-level or path-level agent reasoning by applying sandbox policy before launch.
- **Mitigated**: Running blocked commands via CLI blocklist when that feature is used.
- **Mitigated**: Kernel-level constraints remain even if the agent tries to evade application-layer logic.

## Threat-to-control mapping

| Threat | Control | Outcome |
| --- | --- | --- |
| Unverified secret access | DID/VC verifier + `AgentSecretAccess` | Blocked |
| Secret theft at rest | OS keystore storage | Blocked |
| Secret exfiltration in sandbox | OS sandbox + net block | Blocked |
| Unauthorized file access | Seatbelt/AppContainer allowlists | Blocked |
| Destructive commands | CLI blocklist | Mitigated |
| Peer/agent impersonation on SLIM | DID-JWT auth + member allow-list | Blocked |
| Message interception | MLS in SLIM | Blocked |
| Message tampering | MLS integrity | Blocked |
| Agent identity substitution | HKDF derivation + verify-agent-identity | Blocked (with verification) |
| Process escape | Kernel enforcement | Mitigated |

## Residual risks
- Host OS compromise or kernel-level malware can bypass sandbox controls.
- Metadata leakage (timing, sizes, endpoints) is not fully addressed in v1.
- ACL changes on Windows could be interrupted before rollback in a crash.
- Application-level path deny rules are weaker than OS-enforced sandbox restrictions; do not rely on path matching alone for high-assurance policy.

## Deployment guidance
- Prefer running agents under the sandbox with a JSON policy file.
- Use explicit disclosure only when a demo or workload truly needs the secret in the parent process, and prefer process-scoped or delegated trusted delivery where possible.
- Rotate secrets and use short-lived tokens whenever possible.

## Policy examples

### Minimal sandbox
```json
{
  "allow": ["."],
  "net_block": true
}
```

### Read-only project
```json
{
  "read": ["./src"],
  "net_block": true
}
```

---

## Multi-agent coordination layer (`shadi_mas`)

`shadi_mas` is the coordination runtime that sits above the transport layer. It
provides epoch-disciplined state machines that can drive any multi-agent pattern
to a deterministic finalization outcome.

### `CoordinationEngine` abstraction

```
SemanticEvent  ──►  CoordinationEngine  ──►  EventOutcome
(proposal,          (PreferenceEngine,        (Applied,
 vote, tool          DevelopmentEngine,         Finalized,
 result, …)          …)                         Rejected,
                                               Deferred)
```

Engines are wrapped in `MasRuntime<E>` which tracks the full history of applied
transitions and exposes `engine()` / `engine_mut()` for inspection.

### Engines

| Engine | Pattern | Finalization criterion |
|--------|---------|----------------------|
| `PreferenceEngine` | Consensus on a scalar value | Median of proposals when quorum is met |
| `DevelopmentEngine` | Consensus on a code artifact | Most-endorsed artifact when quorum is met |

### Adapter traits

Three adapter traits connect the runtime to real infrastructure:

| Trait | Implementation | Purpose |
|-------|---------------|---------|
| `MessagingAdapter` | `RecordingMessagingAdapter` / `LiveSlimMessagingAdapter` | Publish events to SLIM |
| `TaskAdapter` | `RecordingTaskAdapter` / `LiveA2ATaskAdapter` | Dispatch A2A tasks |
| `ToolAdapter` | `RecordingToolAdapter` / `CommandToolAdapter` / `CliToolAdapter` | Invoke LLMs / CLI tools |

---

## agentbridge — CLI coding-agent interconnect

agentbridge is an application layer on top of `shadi_mas` that wraps CLI coding
tools as A2A agents and orchestrates them via SLIM + DIR.

### Architecture

```mermaid
flowchart TB
  subgraph devenv["Developer environment"]
    tools["Claude Code  ·  Copilot CLI  ·  Codex CLI  ·  Cursor Agent"]
  end

  subgraph agb["agentbridge  —  adapter + CLI layer"]
    direction LR
    adp["CliAdapter\nexecute_prompt · snapshot_context · inject_context"]
    pkt["ContextPacket\n(portable session snapshot)"]
    brd["CliToolAdapter  →  ToolAdapter"]
  end

  subgraph mas["shadi_mas  —  coordination runtime"]
    rt["MasRuntime&lt;DevelopmentEngine&gt;\nproposal  ·  vote  ·  quorum  ·  finalize"]
  end

  subgraph infra["SHADI infrastructure"]
    direction LR
    a2a["shadi_a2a\nA2A / SLIMRPC\n(task dispatch)"]
    slim["agent_transport_slim\nSLIM messaging\n(group broadcast)"]
    mem["shadi_memory\nSQLCipher\n(ContextPacket store)"]
    dir["DIR  (OASF)\n(agent discovery)"]
  end

  tools -- "stdin / stdout" --> adp
  adp -. "handoff payload" .-> pkt
  adp -- "coordinate" --> brd --> rt
  pkt -. "persist / restore" .-> mem
  rt -- "task dispatch" --> a2a
  rt -- "broadcast" --> slim
  adp -- "register agent card" --> dir
```

Solid arrows are the primary execution path (`coordinate`). Dashed arrows are
the context-handoff path (`handoff`).

### Interaction models

| Command | What it does | Key components |
|---------|-------------|----------------|
| `register` | Wraps a CLI tool as a live A2A service on SLIM | `CliAdapter` → `AgentBridgeRequestHandler` → SLIMRPC |
| `handoff` | Exports a session snapshot and injects it into another tool | `ContextPacket` → `shadi_memory` → A2A `inject-context` task |
| `delegate` | Sends a single task to a remote adapter and returns the artifact | `LiveA2ATaskAdapter::dispatch()` over SLIMRPC |
| `coordinate` | Runs multi-round proposal + vote loop across N agents | `CliToolAdapter` → `MasRuntime<DevelopmentEngine>` → finalization |

For full details and sequence diagrams see [agentbridge](agentbridge.md).

- Review the full threat model, secret-delivery rationale, and residual risks in [Security Notes](security.md).
- Put this into practice with [Sandbox and Policies](sandbox.md) and the [CLI Reference](cli.md).
- Integrate into an agent or app via the [API Guide](api_integration.md).
- See the multi-agent coordination layer and general-purpose A2A agent interconnect in [AgentBridge](agentbridge.md).
