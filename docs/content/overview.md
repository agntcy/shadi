# SHADI Overview

## Runtime Safety Infrastructure for Agentic Systems

Secure Host for Agentic AI Dynamic Instantiation (SHADI) is a hardened runtime
for agents operating near real credentials, local data, and developer tooling.
It enforces launch-time policy through verified identity, gated secret access,
OS-level sandboxing, encrypted local memory, and secure transport.

[Get Started](getting_started.md) | [Read the Docs](architecture.md)

## Why SHADI

SHADI is built for environments where trust boundaries matter:

- Secrets are only released to verified sessions.
- Sandbox policy is enforced by the OS, not prompt intent.
- Memory stays encrypted at rest.
- Transport between agents is authenticated and protected.

## Five Layers of Runtime Safety

Each layer builds on the previous one to reduce blast radius and make behavior auditable.

1. **Verified Identity**: deterministic human-to-agent derivation with provenance checks.
2. **Secrets Gate**: keychain-backed secrets with optional 1Password integration.
3. **Kernel Sandbox**: OS-enforced policies with portable profiles and JSON policy support.
4. **Encrypted Memory**: SQLCipher-backed local state for agent memory.
5. **Secure Transport**: DID-authenticated, MLS-encrypted messaging via SLIM and A2A.

## Architecture Snapshot

SHADI presents the runtime as four product layers:

1. **Experience and control**: operators define profiles, policies, and workload launch intent.
2. **Secure runtime**: identity, secret control, trusted delivery, sandboxing, transport, and encrypted memory enforce the launch contract.
3. **Protected workloads**: agents and tools run inside that approved boundary.
4. **External systems**: GitHub, model providers, and SLIM/A2A peers are reached only after policy and trust checks succeed.

## Core Capabilities

- Git-backed sandbox snapshots for before/after capture and audit trails.
- Process-scoped secret injection and trusted delivery with exact executable matching.
- Python bindings for secrets, memory, and sandboxed execution.
- CLI workflows for policy, identity, key management, and sandbox execution.
- Example agents and demos, including a SecOps workflow against real GitHub signals.
- **agentbridge**: general-purpose agent interconnect over A2A, SLIM, and DIR
  with autonomous coordination toward a shared goal — ships today with
  adapters for Claude Code, Copilot, Codex, Cursor Agent, and other CLI
  coding tools.
- **Secure agent groups**: moderator-invited SLIM channels admitted against a
  per-agent DID allow-list, with many-to-many A2A Collaborate broadcast
  messaging between every member.

## Start Here

- New to SHADI? Start with [Getting Started](getting_started.md).
- Running or debugging live agent workflows? Use [Operations](operations.md).
- Need the system model? Read [Architecture](architecture.md) and [Security Notes](security.md).
- Integrating into an agent or app? Start with the [API Guide](api_integration.md).
- Looking for flags and commands? See the [CLI Reference](cli.md).
- Interconnecting agents over A2A autonomously? Start with [AgentBridge](agentbridge.md).

## By Role

**Operator**
- [Getting Started](getting_started.md)
- [Operations](operations.md)
- [Security Notes](security.md)

**Agent or Platform Engineer**
- [Architecture](architecture.md)
- [API Guide](api_integration.md)
- [SLIM and A2A](slim_a2a.md)
- [agentbridge — general-purpose A2A agent interconnect](agentbridge.md)

**Security Engineering**
- [Security Notes](security.md)
- [Design Overview](design.md)

## Documentation Map

- Introduction: framing, architecture, security, and design intent.
- Guides: onboarding and operational flows for setup, sandboxing, and demos.
- Integrations: API usage, transport, framework integration, and agentbridge.
- Reference: commands and flags for `shadictl` and `agentbridge`.

## Runtime Model (At a Glance)

1. Identity verification determines whether a session is trusted.
2. Secrets are released only to verified sessions and only through the policy-approved disclosure or trusted-delivery path.
3. Sandbox policy and secret-delivery policy are resolved before process start and enforced by the OS plus SHADI launch mediation.
4. Local memory stays encrypted at rest.
5. Inter-agent transport is DID-authenticated and MLS-encrypted.

The current policy framework distinguishes three secret-delivery modes:

- explicit disclosure to the launched process (`--inject-keychain`, `process_inject_keychain`)
- process-scoped trusted secret delivery to the launched process (`process_trusted_secret`)
- action-based delegated delivery to a verified child process on Unix/macOS (`process_secret_policy` with `delegate-to-child`)

For a deeper walkthrough, continue to [Architecture](architecture.md).
