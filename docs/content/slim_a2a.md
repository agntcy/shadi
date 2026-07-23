# SLIM/A2A Integration

This crate is designed to hook into the slima2a distribution and SLIM's MLS
stack without re-implementing MLS.

SHADI's current A2A wrapper is built on the official Rust SDK from
`a2aproject/a2a-rs`, using its core protocol, client, server, and SLIMRPC
bindings while preserving SHADI's verifier-gated secret and identity checks.

## Intended flow
1. SLIM session setup verifies agent identity (DID/VC).
2. Secrets are accessed only after verification succeeds.
3. MLS provides content confidentiality between agents.
