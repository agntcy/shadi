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

## Core components

### 1) Secrets layer
- **OS keystores**: Keychain (macOS/iOS), DPAPI/CNG (Windows), Keystore (Android),
  Secret Service (Linux).
- **Access control**: Secrets are accessed only after DID/VC verification.
- **Memory safety**: Secrets are wrapped in `SecretBytes` and zeroized on drop.
- **OpenPGP parsing**: `shadictl` uses `sequoia-openpgp` to ingest keys without calling OS `gpg`.

#### Key modules
- `crates/agent_secrets/src/lib.rs`: `SecretStore` trait, errors, and default store.
- `crates/agent_secrets/src/agent.rs`: `AgentSecretAccess` gates reads/writes on verification.
- `crates/agent_secrets/src/memory.rs`: `SecretBytes` zeroization wrapper.
- `crates/agent_secrets/src/platform`: platform keychain backends.
- `crates/agent_secrets/src/platform/macos.rs`: Keychain storage + key registry for listing.
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
- **CLI**: `shadi` provides command blocklists and a JSON policy format.
- **Portable launcher model**: `shadi` supports built-in profiles
  (`strict`, `balanced`, `connected`) for portable secure launch defaults.

#### Key modules
- `crates/shadi_sandbox/src/policy.rs`: policy model and helpers.
- `crates/shadi_sandbox/src/platform`: OS-specific sandbox enforcement.
- `crates/shadictl/src/main.rs`: CLI parsing, policy resolution, and key listing.

### 3) Memory layer
- **Local encrypted store**: SQLCipher-backed SQLite for portable, on-device memory.
- **Key management**: Encryption keys live in SHADI secrets (keychain backed).
- **Agent usage**: SecOps writes summaries to the encrypted store; ADK memory remains in-process unless configured for persistent backends.

#### Key modules
- `crates/shadi_memory/src/lib.rs`: SQLCipher store and query helpers.
- `crates/shadi_memory/src/main.rs`: shadi-memory CLI.
- `crates/shadictl/src/main.rs`: `shadictl memory` helper.
- `crates/shadi_py/src/lib.rs`: SQLCipher bindings.
- `agents/secops/skills.py`: SecOps summary persistence.

### 4) Transport layer
- **SLIM/A2A**: MLS provides confidentiality and integrity between agents.
- **Verified sessions**: Messages are only sent/received after DID/VC checks.

#### Key modules
- `crates/agent_transport_slim/src/lib.rs`: transport adapter and verifier gating.

### 5) Brokered secret injection (optional)
- If sandbox rules prevent keystore access, secrets can be brokered outside the
  sandbox and injected as environment variables into the agent process.

#### Key modules
- `crates/shadictl/src/main.rs`: `--inject-keychain` and policy enforcement.

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

## SecOps agent architecture
The SecOps agent runs locally under SHADI and uses the Python bindings for secrets
plus GitHub APIs for security signals.

#### Key modules
- `agents/secops/skills.py`: skills to collect alerts and issues.
- `agents/secops/secops.py`: runner invoking the skill.
- `agents/secops/adk_agent/agent.py`: Google ADK agent.
- `agents/secops/SKILL.md`: Agent Skills spec metadata and runbook.

#### SecOps flow
1. Read config from secops.toml.
2. Fetch GitHub token and workspace path from SHADI.
3. Collect Dependabot alerts and security-labeled issues.
4. Write `secops_security_report.json` to the workspace.

## Data flow (high level)
1. Human identity material is ingested (OpenPGP or seed bytes).
2. Agent local keypair + `did:key` are deterministically derived and stored.
3. Optional human DID binding is stored for provenance checks.
4. Agent session starts and performs DID/VC verification.
5. SHADI sandbox applies OS-level restrictions to the agent process.
6. Agent requests secrets; access is granted only if verification succeeds.
7. Agent communicates over SLIM/MLS; messages are encrypted end-to-end.

```mermaid
sequenceDiagram
  participant Human
  participant Agent
  participant SHADI
  participant Sandbox
  participant Keystore
  participant MemoryStore
  participant SLIM

  Human->>SHADI: Provide source identity material
  SHADI->>SHADI: HKDF derive agent local key + did:key
  SHADI->>Keystore: Store agent keys + DID (+ optional human binding)
  Agent->>SHADI: Start session + DID/VC
  SHADI->>Sandbox: Apply OS policy
  Agent->>SHADI: Secret request
  SHADI->>Keystore: Read secret (if verified)
  Keystore-->>SHADI: Secret bytes
  SHADI-->>Agent: Secret handle
  Agent->>MemoryStore: Write encrypted summary (SQLCipher)
  MemoryStore-->>Agent: Persisted entry id
  Agent->>SLIM: Send MLS message
  SLIM-->>Agent: Encrypted transport
```

```mermaid
flowchart LR
  A[Profile Defaults] --> B[Sandbox Policy]
  A2[Policy JSON] --> B
  A3[CLI Flags] --> B
  B --> C[macOS Seatbelt]
  B --> D[Windows AppContainer + ACL]
  H0[Human Identity Source] --> H1[HKDF Derivation]
  H1 --> H2[Agent Local Keypair]
  H2 --> H3[did:key]
  H3 --> G
  E[Session Verification] --> F[Secrets Access]
  F --> G[OS Keystore]
  G --> J[Memory Key]
  J --> K[SQLCipher Memory Store]
  E --> K
  H[SLIM/MLS] --> I[Agent-to-Agent Secure Channel]
```

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
- **Stopped**: Running blocked commands via CLI blocklist.
- **Mitigated**: Kernel-level constraints remain even if the agent tries to evade.

## Threat-to-control mapping

| Threat | Control | Outcome |
| --- | --- | --- |
| Unverified secret access | DID/VC verifier + `AgentSecretAccess` | Blocked |
| Secret theft at rest | OS keystore storage | Blocked |
| Secret exfiltration in sandbox | OS sandbox + net block | Blocked |
| Unauthorized file access | Seatbelt/AppContainer allowlists | Blocked |
| Destructive commands | CLI blocklist | Blocked |
| Message interception | MLS in SLIM | Blocked |
| Message tampering | MLS integrity | Blocked |
| Agent identity substitution | HKDF derivation + verify-agent-identity | Blocked (with verification) |
| Process escape | Kernel enforcement | Mitigated |

## Residual risks
- Host OS compromise or kernel-level malware can bypass sandbox controls.
- Metadata leakage (timing, sizes, endpoints) is not fully addressed in v1.
- ACL changes on Windows could be interrupted before rollback in a crash.

## Deployment guidance
- Prefer running agents under the sandbox with a JSON policy file.
- Use brokered secrets for demos, and keystore access for production where allowed.
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

## Future work
- Signed policy files with provenance (Sigstore/DSSE).
- OS-enforced network allowlist/denylist policies.
- Stronger metadata privacy controls.
