# Security Notes

This library targets confidentiality for agent secrets at rest and in memory.
It does not assume a hostile OS for v1.

OpenPGP key handling is performed in-process via `sequoia-openpgp` rather than
shelling out to `gpg`.

## Non-goals
- Protecting against a fully compromised host OS.
- Metadata privacy beyond message content when using SLIM/MLS.
