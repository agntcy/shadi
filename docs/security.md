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

## 1Password backend

When `SHADI_SECRET_BACKEND=onepassword` is set, secrets are stored in a
1Password vault instead of the OS keychain. The backend shells out to the `op`
CLI (1Password CLI v2). No secrets are cached in memory beyond the lifetime of
each operation.

- Items are stored as Secure Notes with base64-encoded content, tagged `shadi`.
- For CI/headless environments, set `OP_SERVICE_ACCOUNT_TOKEN` (never stored
  by SHADI; consumed directly by `op`).
- The vault name defaults to `shadi` and can be overridden via `SHADI_OP_VAULT`.

## Non-goals
- Protecting against a fully compromised host OS.
- Metadata privacy beyond message content when using SLIM/MLS.
