# SHADI: Secure Host Agentic AI Dynamic Instantiation

SHADI is a secure host runtime for autonomous, multi-agent systems running on end devices. It focuses on verified identity, secrets access gating, and OS-level sandboxing so agent actions are least-privilege by default.

Key capabilities:
- Secrets stored in OS keystores with verified-session access.
- SQLCipher-backed local memory for durable, encrypted context.
- OS sandbox enforcement for filesystem and network constraints.
- SLIM/A2A transport integration for secure agent-to-agent messaging.
- Python bindings for secrets, memory, and sandbox execution.

This repository includes the SecOps agent, sandbox tooling, and bindings to integrate SHADI into agent runtimes.
