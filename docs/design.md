# Design Overview

The workspace contains several crates:
- agent_secrets: secret storage and access control
- shadictl: CLI for sandboxing, key management, and policy resolution
- shadi_memory: SQLCipher-backed encrypted memory store
- shadi_sandbox: OS sandbox enforcement layer
- shadi_py: Python bindings for secrets, SQLCipher memory, and sandbox execution
- slim_mas: SLIM multi-agent moderator CLI
- agent_transport_slim: transport adapter for SLIM/A2A

Platform-specific backends live under agent_secrets/src/platform.

## Documentation
The documentation site is built with MkDocs. See docs/README.md for running it
locally.
