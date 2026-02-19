# agent_secrets

Secure secret storage and access primitives for autonomous agents.

## Goals
- Provide a stable Rust API to store and retrieve secrets.
- Support Windows, macOS, iOS, Android, and Linux using OS keystores.
- Minimize in-memory exposure through explicit secret wrappers.

## Status
This crate provides a public API scaffold. Platform backends are stubbed and
return `NotSupported` until implemented.
