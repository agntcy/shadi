# SLIM/A2A Integration

This crate is designed to hook into the slima2a distribution and SLIM's MLS
stack without re-implementing MLS.

## Intended flow
1. SLIM session setup verifies agent identity (DID/VC).
2. Secrets are accessed only after verification succeeds.
3. MLS provides content confidentiality between agents.
