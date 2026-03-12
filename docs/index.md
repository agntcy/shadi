# SHADI

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
5. **Secure Transport**: MLS-backed messaging via SLIM and A2A.

## Core Capabilities

- Git-backed sandbox snapshots for before/after capture and audit trails.
- Python bindings for secrets, memory, and sandboxed execution.
- CLI workflows for policy, identity, key management, and sandbox execution.
- Example agents and demos, including a SecOps workflow against real GitHub signals.

## Start Here

- New to SHADI? Start with [Getting Started](getting_started.md).
- Running or debugging live agent workflows? Use [Operations](operations.md).
- Need the system model? Read [Architecture](architecture.md) and [Security Notes](security.md).
- Integrating into an agent or app? Start with the [API Guide](api_integration.md).
- Looking for flags and commands? See the [CLI Reference](cli.md).

## By Role

**Operator**
- [Getting Started](getting_started.md)
- [Operations](operations.md)
- [Security Notes](security.md)

**Agent or Platform Engineer**
- [Architecture](architecture.md)
- [API Guide](api_integration.md)
- [SLIM and A2A](slim_a2a.md) or [Google ADK](adk_integration.md)

**Security Engineering**
- [Security Notes](security.md)
- [SecOps Demo](secops_agent.md)
- [Design Overview](design.md)

## Documentation Map

- Introduction: framing, architecture, security, and design intent.
- Guides: onboarding and operational flows for setup, sandboxing, and demos.
- Integrations: API usage plus transport and framework integration notes.
- Reference: commands and flags for `shadictl`.

## Runtime Model (At a Glance)

1. Identity verification determines whether a session is trusted.
2. Secrets are released only to verified sessions.
3. Sandbox policy is resolved before process start and enforced by the OS.
4. Local memory stays encrypted at rest.
5. Inter-agent transport is protected by MLS-backed messaging.

For a deeper walkthrough, continue to [Architecture](architecture.md).
