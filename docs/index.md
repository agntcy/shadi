# SHADI

SHADI is a secure host runtime for agents that run close to real credentials,
local data, and developer tooling. It combines verified identity, gated secret
access, OS-enforced sandboxing, encrypted local memory, and secure transport so
agent execution is constrained by launch-time policy instead of prompt-time
intent alone.

## Start Here

Use the docs by task, not by file name:

- If you are new to SHADI, start with [Getting Started](getting_started.md).
- If you are running or debugging real agent workflows, start with [Operations](operations.md).
- If you need the system model, start with [Architecture](architecture.md) and [Security Notes](security.md).
- If you are integrating an agent or app, start with [API Guide](api_integration.md), then the relevant integration page.
- If you need commands and flags, use [CLI Reference](cli.md).

## What SHADI Gives You

- Verified secret access backed by platform keystores and optional 1Password integration.
- Deterministic human-to-agent identity derivation with provenance checks.
- Kernel-enforced sandbox execution with portable profiles and JSON policy support.
- Encrypted on-device memory through SQLCipher.
- Python bindings for secrets, memory, and sandboxed execution.
- Secure agent-to-agent messaging through SLIM and A2A.
- Example agents and demos, including a SecOps workflow that exercises the runtime against real GitHub signals.

## Read By Role

### Operator

You are trying to run agents safely on a workstation or end device.

- Read [Getting Started](getting_started.md) for the shortest path from clone to first sandboxed command.
- Read [Operations](operations.md) for runtime checks, demo flows, and troubleshooting.
- Read [Security Notes](security.md) for the threat model and deployment caveats.

### Agent or Platform Engineer

You are integrating SHADI into an agent runtime, toolchain, or application.

- Read [Architecture](architecture.md) for the runtime split between launch, trust, sandbox, memory, and transport.
- Read [API Guide](api_integration.md) for Rust and Python integration patterns.
- Read [SLIM and A2A](slim_a2a.md) or [Google ADK](adk_integration.md) for runtime-specific paths.

### Security Engineering

You are evaluating controls, provenance, and remediation behavior.

- Read [Security Notes](security.md) for the control model.
- Read [SecOps Demo](secops_agent.md) for the security-demo workload, remediation boundaries, and operator workflows.
- Read [Design Overview](design.md) for implementation direction and current constraints.

## Documentation Map

The site is organized into four sections:

- `Introduction`: project framing, architecture, security, and design intent.
- `Guides`: onboarding and operational flows for setup, sandboxing, and demo workloads.
- `Integrations`: API usage plus transport and agent-framework integration notes.
- `Reference`: command and flag documentation for `shadictl`.

## Core Runtime Model

SHADI is built around a small set of enforcement layers:

- Identity verification determines whether an agent session is trusted.
- Secret access is gated on that verified session.
- Sandbox policy is resolved before process start and enforced by the OS.
- Local memory stays encrypted at rest.
- Inter-agent transport is protected by MLS-backed messaging.

For a system-level view of how those layers fit together, continue to [Architecture](architecture.md).
