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

## Secret delivery and disclosure modes

SHADI now separates secret storage from secret delivery.

The important distinction is not only whether a secret exists in the store, but
which executable is allowed to receive it and by what mechanism.

Current launch-time modes:

- `--inject-keychain` and `process_inject_keychain`: explicit disclosure as an environment variable.
- `process_trusted_secret`: process-scoped trusted delivery to the launched executable.
- `process_secret_policy`: action-based rules, including `delegate-to-child` for Unix/macOS final-consumer delivery.

### Why this matters

Two risks need different controls:

- wrong-process disclosure: a secret reaches a parent or sibling process that was not the intended consumer
- prompt-injection misuse: an LLM-facing process that legitimately sees a secret is induced to exfiltrate it

SHADI's current policy framework primarily improves the first risk by keeping
secret rules bound to the exact launched executable and, for delegated
Unix/macOS delivery, to a verified child executable plus a one-shot broker
protocol.

### Current platform behavior

- Unix/macOS trusted delivery uses a launch-scoped broker endpoint, a companion nonce env (`*_NONCE`), peer-process verification, and one-shot release semantics.
- macOS temporarily opts into local Unix socket permissions only for launches that require trusted-secret delivery.
- Windows currently supports direct trusted-secret delivery through a compatibility inherited-handle path.
- Windows direct trusted-secret rules can optionally pin the launched executable hash with `exec_sha256` to avoid path-only trust.
- Windows ACL allowlist changes are journaled to disk before mutation and replayed on the next sandbox startup if a previous `shadictl` process crashes before cleanup. The journal directory is locked to owner + SYSTEM with a protected DACL, and each journal entry carries an HMAC-SHA256 tag verified before replay to prevent tampering.

### Policy intent

Treat environment injection as explicit disclosure, not as the default secure
path. Prefer final-consumer delivery when the parent process only needs to
launch a child tool rather than directly hold the credential.

## agentbridge listeners

`agentbridge register` exposes a local coding tool as an A2A service over SLIM.
Every incoming task is forwarded to that tool's subprocess, so a registered
listener is a **remote code-execution surface**: any peer that can reach
`agntcy/shadi/<tool>-a2a` can drive the local tool (some adapters, such as
`copilot`, run with `--allow-all-tools`).

Controls:

- SLIM peers authenticate with a shared secret. The built-in default secret is
  public and for loopback demos only — set `SLIM_SHARED_SECRET` to a private
  value before binding a routable address. The CLI warns when the default is in
  use and warns more loudly for non-loopback endpoints.
- Transport is mutually authenticated with SLIMRPC over TLS; keep the CA bundle
  private to trusted peers.
- Run bridged tools inside the SHADI [sandbox](sandbox.md) so tool execution is
  confined by OS policy. See [AgentBridge → Security model](agentbridge.md#security-model).

## Non-goals
- Protecting against a fully compromised host OS.
- Metadata privacy beyond message content when using SLIM/MLS.
