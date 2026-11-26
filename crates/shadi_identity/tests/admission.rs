// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! End-to-end crypto proof of DID admission: a DID-JWT minted by a member of the
//! allow-list verifies; one minted by a non-member is rejected. Exercises SLIM's
//! real auth runtime (`build_auth_provider` / `build_auth_verifier` → `get_token`
//! / `verify`) from the configs `shadi_identity` produces.

use std::time::Duration;

use shadi_identity::config::{did_provider_config_with_ttl, did_verifier_config};
use shadi_identity::{build_did_auth_for_peer, jwks_from_dids, AgentIdentity};
use slim_bindings::Name;

use slim_auth::traits::{TokenProvider, Verifier};
use slim_config::auth::identity::{
    IdentityProviderConfig as CoreProvider, IdentityVerifierConfig as CoreVerifier,
};

fn mint(agent: &AgentIdentity) -> String {
    let core: CoreProvider = agent.provider_config(None).unwrap().into();
    core.build_auth_provider()
        .unwrap()
        .get_token()
        .expect("mint DID-JWT")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn did_admission_accepts_member_rejects_nonmember() {
    // The JWT verifier builds a rustls-backed HTTP client; slim installs the crypto
    // provider at runtime startup, so do the same in this isolated test.
    slim_config::tls::provider::initialize_crypto_provider();

    let member = AgentIdentity::generate().unwrap();
    let intruder = AgentIdentity::generate().unwrap();

    // Allow-list = the member only.
    let jwks = jwks_from_dids([member.did().as_str()]).unwrap();
    let verifier_cfg: CoreVerifier = did_verifier_config(&jwks, None).into();
    let verifier = verifier_cfg.build_auth_verifier().unwrap();

    let member_token = mint(&member);
    let intruder_token = mint(&intruder);

    // Member is in the allow-list JWKS → admitted.
    assert!(
        verifier.verify(&member_token).is_ok(),
        "a member DID must be admitted"
    );
    // Intruder's key is absent from the JWKS → no trusted key → InvalidSignature.
    assert!(
        verifier.verify(&intruder_token).is_err(),
        "a non-member DID must be rejected by the allow-list"
    );
}

/// A caller pinned to the peer it dialled trusts that peer and itself (SLIM's MLS
/// Welcome verifies the caller's own credential too) and no one else.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_pinned_caller_verifies_peer_and_self_but_not_a_third_did() {
    slim_config::tls::provider::initialize_crypto_provider();

    let caller = AgentIdentity::derive(b"seed", "caller").unwrap();
    let peer = AgentIdentity::derive(b"seed", "peer").unwrap();
    let third = AgentIdentity::derive(b"seed", "third").unwrap();

    let auth = build_did_auth_for_peer(b"seed", "caller", &peer.did()).unwrap();
    let name = Name::from_string("org/ns/caller".to_string()).unwrap();
    let (_, verifier_cfg) = auth.configs(&name).unwrap();
    let verifier_cfg: CoreVerifier = verifier_cfg.into();
    let verifier = verifier_cfg.build_auth_verifier().unwrap();

    assert!(
        verifier.verify(mint(&peer)).is_ok(),
        "the dialled peer must be admitted"
    );
    assert!(
        verifier.verify(mint(&caller)).is_ok(),
        "the caller's own credential must be admitted"
    );
    assert!(
        verifier.verify(mint(&third)).is_err(),
        "a DID that was not dialled must be rejected"
    );
}

/// The DID credential is minted per call, not once at startup.
///
/// `SlimAuth::Did` carries the signing key, not a token, and SLIM's
/// `SignerJwt::get_token` signs fresh claims every time the session layer asks
/// for identity — which is why a long-running node needs no refresh loop. A
/// provider that cached one token would keep serving it past its expiry, so
/// this pins the re-minting.
///
/// It does not assert that an expired credential is refused: SLIM builds its
/// `Validation` without touching `leeway`, so jsonwebtoken's 60s default
/// applies and a token is honoured for its TTL plus a further minute.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_keeps_minting_credentials_rather_than_holding_one() {
    slim_config::tls::provider::initialize_crypto_provider();

    let member = AgentIdentity::generate().unwrap();
    let jwks = jwks_from_dids([member.did().as_str()]).unwrap();
    let verifier_cfg: CoreVerifier = did_verifier_config(&jwks, None).into();
    let verifier = verifier_cfg.build_auth_verifier().unwrap();

    let provider_cfg = short_lived_provider_config(&member, Duration::from_secs(1));
    let provider = provider_cfg.build_auth_provider().unwrap();

    let first = provider.get_token().expect("mint the first DID-JWT");
    assert!(
        verifier.verify(&first).is_ok(),
        "a freshly minted credential must be admitted"
    );

    // `exp`/`iat` are whole seconds, so a second mint after the first has
    // lapsed carries different claims — unless the token was cached.
    tokio::time::sleep(Duration::from_millis(1_100)).await;

    let second = provider.get_token().expect("mint a replacement DID-JWT");
    assert_ne!(
        first, second,
        "get_token must sign fresh claims rather than return a cached token"
    );
    assert!(
        verifier.verify(&second).is_ok(),
        "the node must keep authenticating once its first credential has lapsed"
    );
}

/// The default 5-minute TTL is too long to wait out in a test; this is the
/// same builder shadi uses, with a shorter lifetime.
fn short_lived_provider_config(agent: &AgentIdentity, ttl: Duration) -> CoreProvider {
    did_provider_config_with_ttl(&agent.to_pkcs8_pem().unwrap(), &agent.did(), None, ttl).into()
}
