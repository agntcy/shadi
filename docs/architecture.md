# Architecture

SHADI (Secure Host Agentic AI Dynamic Instantiation) is a secure host runtime for
interactive, autonomous agents. It combines secure secret storage, verified
identity, and kernel-enforced sandboxing to reduce the blast radius of agent
actions and prevent unauthorized data access or exfiltration.

## Goals
- Run dynamic, interactive agents with least-privilege access.
- Protect secrets at rest and limit access to verified sessions.
- Enforce kernel-level restrictions so unauthorized operations are blocked by the OS.
- Provide secure, low-latency agent-to-agent messaging via MLS.
- Keep platform support across macOS, Windows, and mobile targets.

## Non-goals
- Protect against a fully compromised host OS or kernel.
- Provide complete metadata privacy for network traffic in v1.
- Replace upstream MLS or OS keystore implementations.

## Architecture overview

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
- `crates/shadictl/src/main.rs`: OpenPGP ingestion, DID derivation, and secret store helpers.

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
- `crates/shadictl/src/main.rs`: `derive-agent-did`, `derive-agent-identity`,
  `verify-agent-identity`, and derivation helpers.

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
- `crates/shadictl/src/main.rs`: CLI parsing, policy resolution, and key listing.

### 3) Memory layer
- **Local encrypted store**: SQLCipher-backed SQLite for portable, on-device memory.
- **Key management**: Encryption keys live in SHADI secrets (keychain backed).
- **Agent usage**: workloads running on SHADI can persist local state in the encrypted store.

#### Key modules
- `crates/shadi_memory/src/lib.rs`: SQLCipher store and query helpers.
- `crates/shadictl/src/main.rs`: `shadictl memory` helper.
- `crates/shadi_py/src/lib.rs`: SQLCipher bindings.

### 4) Transport layer
- **SLIM/A2A**: MLS provides confidentiality and integrity between agents.
- **Verified sessions**: Messages are only sent/received after DID/VC checks.

#### Key modules
- `crates/agent_transport_slim/src/lib.rs`: transport adapter, verifier gating, and native SLIM session bootstrap.
- `crates/agent_transport_slim/src/bin/slim-stdio-bridge.rs`: standalone stdio bridge helper; the same bridge engine is now used directly by shadictl for in-sandbox SLIM sessions.

### 5) Secret delivery and policy framework

SHADI now has a launch-time secret-delivery framework with exact executable
matching. The important distinction is not just what secret is being requested,
but which process may receive it and whether the secret is being disclosed or
trusted-delivered.

#### Current rule types

- `process_inject_keychain`: explicit env disclosure to the exact launched executable.
- `process_trusted_secret`: process-scoped direct trusted-secret delivery to the exact launched executable.
- `process_secret_policy`: action-based rules for a launched executable, including delegated child delivery on Unix/macOS.

CLI compatibility flags exist for the same concepts:

- `--inject-keychain KEY=ENV`
- `--trusted-secret KEY=NAME`
- `--trusted-secret-exec NAME=PROGRAM`
- `--trusted-secret-fd-env NAME=ENV`

#### Current delivery modes

1. **Explicit disclosure**
  SHADI reads the secret before launch and injects it into the target process
  environment. This is compatibility-oriented and should be treated as
  intentional disclosure.

2. **Process-scoped trusted delivery**
  The launched executable receives a protocol-specific endpoint reference
  rather than a broad ambient secret. On Unix/macOS the current implementation
  is a one-shot brokered fetch with a launch-scoped nonce companion env.

3. **Delegated child delivery**
  A launched parent process can be allowed to request delivery of a secret to a
  specific child executable. On Unix/macOS, SHADI verifies the child process,
  optional child SHA-256 constraints, and the presented nonce before releasing
  the secret. The parent process does not receive the secret itself.

#### Key modules
- `crates/shadictl/src/trusted_secret_delivery.rs`: secret resolution, exact-program matching, broker lifecycle, and delegated child verification.
- `crates/shadictl/src/sandbox_snapshot.rs`: launch orchestration, runtime policy augmentation for broker endpoints, and trusted-secret post-spawn delivery.
- `crates/shadictl/src/policy_helpers.rs`: env disclosure helpers for explicit inject-keychain behavior.
- `crates/shadi_sandbox/src/policy.rs`: minimal-profile and local Unix socket opt-in controls.

## Secret delivery security model

The current implementation distinguishes explicit disclosure from final-consumer
delivery. The important distinction is not only what secret is being requested,
but which process may receive it and whether that process needs raw disclosure
at all.

### Problem statement

Two different risks need different controls:

- **Wrong-process disclosure**: a secret is placed in a parent process or its
  ambient environment and becomes available to unrelated descendants.
- **Prompt-injection misuse**: an LLM-driven process that legitimately sees a
  secret is induced to exfiltrate it.

The current trusted-secret path improves the first risk on Unix/macOS. The
current model is based on these security properties:

- SHADI remains the delivery authority until the final authorized consumer
  process exists.
- A parent process may request or authorize a child tool launch, but the parent
  does not become the carrier of the secret.
- Environment injection is treated as explicit disclosure, not as the default secure path.

### Secret actions

Policy should be expressed in terms of actions on a secret rather than a coarse secret category.

- `disclose`: the process may read the secret value directly.
- `use`: the policy may represent a narrower operation that depends on the secret without implying ambient plaintext disclosure.
- `delegate-to-child`: the process may request that SHADI deliver the secret to
  a specific child process, but the parent does not receive the secret.
- `sign` or `authenticate`: the process may invoke a narrower operation backed
  by the secret without receiving the raw secret when the platform integration
  supports that shape.

### Final-consumer delivery rule

The core enforcement rule is:

> A secret must be delivered by SHADI directly to the final authorized consumer
> process, not inherited through a parent process and not placed into a general
> environment visible to unrelated descendants.

This rule applies even when the process tree is parent-driven:

1. An agent or parent tool requests launch of child tool `T`.
2. SHADI validates that `T` is allowed to receive action `A` on secret `S`.
3. SHADI verifies the exact executable identity for `T`.
4. SHADI launches or mediates the final consumer boundary.
5. SHADI delivers the secret to `T` one time.
6. The parent does not receive the secret as an env var, inherited fd, handle,
   or reusable fetch token.

### Prompt-injection boundary

Prompt injection is a separate concern from wrong-process delivery.

- Process-boundary controls decide **which process can receive a secret**.
- Prompt-injection controls decide **whether that process should ever receive a
  raw secret at all**.

This means LLM-driven executables should default away from `disclose` whenever a
safer action is available.

- Deterministic or tightly scoped tools may receive `disclose` when necessary.
- LLM-driven agents should more commonly receive `delegate-to-child` or a
  narrower `use` capability.
- High-value provider credentials should prefer mediation patterns where SHADI
  or a trusted adapter performs the authenticated action and returns only the
  result.

### Current cross-platform behavior

The common security property is:

> SHADI delivers the secret to the final authorized consumer process after that
> process exists and has been verified, without requiring the parent process to
> carry the secret.

The transport can be platform-specific, but the policy and trust boundary should
stay the same.

- **macOS / Linux**: local broker endpoint after spawn, with peer PID and
  executable verification before one-shot delivery.
- **Windows**: direct trusted-secret delivery currently uses a compatibility
  inherited-handle transport. The final-consumer delegated path described above
  is documented for Unix/macOS.

### Compatibility mode

The existing env-injection and inherited-handle paths may still be kept as
explicit compatibility mechanisms, but they should be documented as disclosure
mode rather than the target secure design.

- env injection: explicit `disclose` to the target process,
- inherited Windows handles: compatibility path for direct trusted delivery,
- brokered final-consumer delivery: preferred secure path.

## Python bindings
SHADI exposes a Python extension for secrets, SQLCipher memory, and sandbox
execution.

#### Key modules
- `crates/shadi_py/src/lib.rs`: `ShadiStore`, `PySessionContext`,
  `SqlCipherMemoryStore`, `SandboxPolicyHandle`, and `run_sandboxed` bindings.

#### Python API surface
- `ShadiStore.set_verifier(callable)` to supply DID/VC verification logic.
- `ShadiStore.verify_session(session, presentation)` to set verified sessions.
- `ShadiStore.get/put/delete` for secret access.
- `ShadiStore.list_keys` to enumerate stored keys (backed by key registry on macOS).
- `SqlCipherMemoryStore` for encrypted local memory.
- `SandboxPolicyHandle` + `run_sandboxed` for sandbox execution.

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
- **Stopped**: Unauthorized peers reading messages; MLS provides confidentiality.
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

