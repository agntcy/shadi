# Design note: DID identity wiring

Status: **draft for review** · Scope: SHADI admission over SLIM v2 · Author: (draft)

## Goal

Gate admission to the SLIM mesh and its channels on **cryptographic DID identity**:
an agent proves control of its DID to join, and only DIDs on a group's allow-list
are admitted. Today membership is *declared* by DID but *enforced* by a shared
secret — anyone holding the secret gets in. This note connects the two.

## Non-goals (for v1)

- Full W3C Verifiable Credentials / credential schemas.
- Network-resolved DID methods (`did:web`, `did:peer`).
- Centralized real-time revocation (status lists / CRLs).
- Replacing mTLS (transport security stays as-is).

## What exists today

1. **Transport admission = shared secret.** ~8 `create_app_with_secret(name, secret)`
   sites (agent_transport_slim, shadictl, shadi_mas, agentbridge_cli, shadi_a2a via
   builder). HMAC shared secret; no DID.
2. **DID allow-list = policy only, in `slim_mas`.** `GroupConfig { moderator_did,
   members: [{ did, role }] }` + `is_member_allowed(group, did, role)`. Uses
   `did:key:*`. Not wired to admission.
3. **Verification hook = trivial.** `agent_secrets::AgentVerifier::verify(&SessionContext)`
   (called by `A2AChannel` before each send). `SessionContext { agent_id, session_id,
   verified, claims }` — **no `did` field**; real impls currently wave through.

## What SLIM v2 gives us (grounding)

`agntcy-slim-auth` (0.13):
- `AuthProvider::{ JwtSigner, StaticToken, SharedSecret, Spire }`
- `AuthVerifier::{ JwtVerifier, SharedSecret, Spire }`
- Constructors `AuthProvider::jwt_signer(SignerJwt)` / `AuthVerifier::jwt_verifier(VerifierJwt)`
- JWT algorithms include **EdDSA (Ed25519)** and **ES256 (P-256)**

`Service::create_app(&name, provider, verifier)` already takes an
`AuthProvider`/`AuthVerifier` pair — the shared-secret path is just one choice.

SHADI already depends on **`ed25519-dalek`** and **`bs58`** — exactly the primitives
`did:key` (Ed25519) needs. No new crypto stack required.

Control-plane / channel-manager expose **no ready admission API** today → v1 enforces
per-connection, not centrally.

## Decisions (the five questions)

| # | Question | Recommendation (v1) | Why |
|---|---|---|---|
| 1 | DID method | **`did:key` (Ed25519) only** | Self-contained (pubkey embedded, no network resolution); already used in configs; maps to EdDSA JWT. `did:web`/`did:peer` deferred (need resolvers). |
| 2 | Credential format | **DID-signed JWT (EdDSA)**: `sub = did`, `aud = channel`, short `exp` | Rides `slim_auth`'s existing JWT signer/verifier directly. SLIM has no "service" concept, so the token binds to the **channel**. W3C VC is heavier and unneeded for admission; can extend to VC-JWT later. |
| 3 | Replace vs. layer | **Layer, then migrate.** DID-JWT becomes the admission auth; keep shared-secret behind a config flag during transition; DID-only later. | De-risks rollout; keeps existing deployments working while DID rolls out. |
| 4 | Where enforced | **Per-connection (auth provider) + SHADI policy check.** JWT verifier proves the DID; `AgentVerifier` + `is_member_allowed` gates it against group policy. | No control-plane admission API exists yet; per-connection is the available, sufficient point. Central admission = future. |
| 5 | Revocation | **Short JWT TTL + allow-list removal.** Removed DIDs fail `is_member_allowed` on next join/verify; tokens expire naturally. | Simple, no new infra. Real-time revocation deferred. |

## Flow (v1)

```
Agent (did:key + Ed25519 key, both from the agent_secrets secret store)
  └─ mint JWT: sub=<did>, aud=<channel>, exp=now+TTL, signed EdDSA
        │  AuthProvider::jwt_signer(SignerJwt)
        ▼
  Service::create_app(name, provider, verifier)  ──▶ join mesh/session
        ▲
  Verifier: AuthVerifier::jwt_verifier(VerifierJwt)
     1. validate EdDSA signature against did:key-embedded pubkey
     2. validate claims (aud, exp)
        │  → SessionContext.did = sub
        ▼
  SHADI AgentVerifier.verify(ctx):
     is_member_allowed(group, ctx.did, role)  → admit / reject
```

## Work breakdown

- **P0 — enforce policy at the app layer (no transport change).** Add `did` to
  `SessionContext`; add a `DidPolicyVerifier` impl of `AgentVerifier` that calls
  `slim_mas::is_member_allowed`. Wire the group config in. *Immediately makes the
  allow-list real for the A2A channel path.*
- **P1 — DID + DID-JWT primitives.** Small `identity` module: `did:key` gen/parse
  (Ed25519 via ed25519-dalek + bs58 multibase), mint/verify DID-JWT through
  `slim_auth` `SignerJwt`/`VerifierJwt`.
- **P2 — swap admission auth.** Replace `create_app_with_secret` with a helper that
  builds the JWT provider/verifier at the ~8 sites, behind a `--auth did|shared-secret`
  config flag (shared-secret fallback retained).
- **P3 — tests.** Unit: DID-JWT mint/verify, policy allow/deny. Integration: allowed
  DID joins + exchanges; disallowed DID rejected at admission.
- **Future.** `did:web` resolver; VC-JWT; control-plane/channel-manager central
  admission; real-time revocation.

## Touch points

`agent_secrets` (SessionContext + AgentVerifier), the `create_app_with_secret` sites,
`slim_mas` (policy), a new `identity` module, `slim_auth` JWT path.

## Resolved

- **Key custody:** the agent's Ed25519 private key + its `did:key` live in the
  **`agent_secrets` secret store** (built for this), retrieved like shared secrets today.
- **Token binding:** SLIM has no "service" concept — JWT `aud` = **channel**.

- **Transition/interop → DECIDED: Option A (homogeneous mesh, flag-day cutover).**
  A mesh uses a single auth approach; to adopt DID, upgrade the whole mesh at once.
  Admission auth is per-connection (joiner mints a token, accepter verifies it, and the
  verifier must understand the token type), so mixing DID and shared-secret agents in one
  mesh is unsupported by design. No dual-verify path; the `--auth did|shared-secret` flag
  is a per-deployment choice, set the same across all agents. (Dual-verify / per-channel
  were considered and rejected as unnecessary complexity.)

## Open / to confirm before P2

- **Moderator role:** how `moderator_did` maps to elevated session capabilities
  (does not block P0 — admission uses `is_member_allowed(group, did, role)` as-is).
