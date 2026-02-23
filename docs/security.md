# Security Notes

This library targets confidentiality for agent secrets at rest and in memory.
It does not assume a hostile OS for v1.

OpenPGP key handling is performed in-process via `sequoia-openpgp` rather than
shelling out to `gpg`.

## Agent key derivation

SHADI derives local agent keys from human identity material using:

- KDF: `HKDF-SHA256`
- Salt: `shadi-agent-derive`
- IKM: human source bytes (`gpg` material or generic seed bytes)
- Info: agent name

The 32-byte HKDF output becomes an Ed25519 private key seed. SHADI stores the
derived public key and computes `did:key` from that key.

## Human-to-agent linkage verification

Use `shadictl verify-agent-identity` to recompute the expected agent key and
DID from the same human source and compare them to stored values.

If a human DID binding is stored (`{prefix}/{agent}/human_did`), verification
can additionally assert that the binding matches a specific human DID key.

## Non-goals
- Protecting against a fully compromised host OS.
- Metadata privacy beyond message content when using SLIM/MLS.
