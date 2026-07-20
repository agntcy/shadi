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

**Config-driven, not hand-rolled crypto.** slim-bindings exposes
`Service::create_app(name, IdentityProviderConfig, IdentityVerifierConfig)`;
`create_app_with_secret` is just the `SharedSecret` convenience over it. The provider
enum has a **`Jwt { config: ClientJwtAuth { key, subject, audience, issuer, duration } }`**
variant — SHADI supplies the **Ed25519 key + `subject = did` + `audience = channel`**
and slim's config layer signs/verifies the JWT. So SHADI does **not** touch
`jsonwebtoken` `EncodingKey`/DER directly; the DID path is the same `create_app` call
with a `Jwt` config in place of `SharedSecret`.

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
- **P1 — DID primitives + identity-config builders.** `did:key` gen/parse (Ed25519 via
  ed25519-dalek + bs58 multibase/multicodec `0xed01`), and helpers that build
  `IdentityProviderConfig::Jwt { ClientJwtAuth { key, subject=did, audience=channel } }`
  + the matching verifier config. No `jsonwebtoken`/DER hand-rolling — slim's config
  layer signs/verifies. Key material sourced from the `agent_secrets` secret store.
  (Confirm the `Key` field's format — inline PEM vs file path — before wiring.)
- **P2 — swap admission auth.** Replace `create_app_with_secret(name, secret)` with
  `create_app(name, provider_cfg, verifier_cfg)` at the ~8 sites, behind a
  `--auth did|shared-secret` flag (shared-secret retained). Populate `SessionContext.did`
  from the verified token and flip `DidPolicyVerifier` on.
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

## Moderator role & enrollment (design)

### Derived identities (human root → client/moderator)

Identities are **hierarchical**. A human has a **root identity**; their moderator and
client identities are **derived** from it — a human can have **many** (per device, per
channel, per client). The moderator is a *client connected to* the human identity, not
the human's key used directly.

For a verifier to confirm a derived DID belongs to human X, the human→derived link must
be **provable**:

- **Signed delegation (required for verifiability):** the human root DID signs a small
  attestation — *"derived DID D acts for me"*. The derived identity presents it; a
  verifier checks D's own signature **and** the root's signature on the delegation.
  Works with plain Ed25519; publicly verifiable. This is a minimal signed attestation,
  not full W3C VC machinery.
- **HD key derivation (optional, key-management only):** SLIP-0010 Ed25519 lets one root
  seed produce many child keys — convenient, but Ed25519 HD is *hardened-only*, so a
  child public key can't be derived/verified from the parent public key. HD does **not**
  provide the verifiable link; delegation does.

Implication for the allow-list: a channel can trust a **human root DID** and accept any
derived identity that presents a valid delegation from it (verify delegation → then the
JWKS/allow-list check), rather than pinning every individual derived DID.

### Moderator role

The **moderator is a human** (via a derived client identity bound to that human),
bound to the person who **creates the channel** — not an agent. `GroupConfig.moderator_did`
is that human's root DID (or a derived identity linked to it). The moderator has
authority agents do not:

- **Creates channels** — establishes a group and sets `moderator_did = <their DID>`.
- **Invites members** — adds a member's DID (+ role) to the channel's allow-list.
  Only the moderator may change membership.
- **May be offline.** Membership authority is exercised at *config time* (create /
  invite). At *runtime*, member admission is the member JWKS (allow-list) — the
  moderator's key is not needed for members to join and interact. So a channel keeps
  working with its moderator offline.

**Enrollment flow:** an agent generates its own `did:key` (held in `agent_secrets`) and
presents it to the moderator out of band; the **moderator invites** it (adds the DID to
the group config). Agents self-hold keys; only the moderator mutates the allow-list.

**UX requirement (SHADI app):** the moderator's special role must be **visible** —
distinguish the human moderator from agent members, show who created the channel, and
surface that only the moderator can invite/remove. This is a product-surface concern
beyond the auth plumbing (P0–P3) and should be tracked as its own workstream.

## Open / to confirm before P2

- **`aud` binding** — `create_app` fixes auth per-app (mesh-wide today), before any
  channel is joined. Options: `aud = None` (identity-only; allow-list is the gate) /
  app's own name / destination channel (must be known at `create_app`). Leaning
  `aud = None` for the current lifecycle.
