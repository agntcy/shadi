# Design Overview

The workspace contains these crates:
- agent_secrets: secret storage and access control
- shadictl: CLI for sandboxing, key management, identity, and policy resolution
- shadi_memory: SQLCipher-backed encrypted memory store
- shadi_sandbox: OS sandbox enforcement layer
- shadi_py: Python bindings for secrets, SQLCipher memory, and sandbox execution
- shadi_identity: DID identity derivation and SLIM DID-JWT auth
- shadi_a2a: A2A-over-SLIM wrapper, including secure group (Collaborate) messaging
- slim_mas: SLIM multi-agent group config and DID allow-list evaluation (a library, consumed by `shadictl slim-mas`, not itself a CLI)
- shadi_mas: autonomous multi-round agent coordination runtime (proposal/vote/finalize), consumed by `agentbridge coordinate`
- agentbridge / agentbridge_cli: CLI coding-agent interconnect (register, handoff, delegate, coordinate)
- agent_transport_slim: transport adapter for SLIM/A2A and stdio bridge for SHADI-managed sessions
- shadi_telemetry: OpenTelemetry tracing/metrics initialization

Platform-specific backends live under agent_secrets/src/platform.

## Documentation
The documentation site is built with MkDocs. See docs/README.md for running it
locally.

## Next steps

- See how these crates fit together in [Architecture](architecture.md).
- Start using the runtime with [Getting Started](getting_started.md).
