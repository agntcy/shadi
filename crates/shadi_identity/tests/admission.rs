// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! End-to-end crypto proof of DID admission: a DID-JWT minted by a member of the
//! allow-list verifies; one minted by a non-member is rejected. Exercises SLIM's
//! real auth runtime (`build_auth_provider` / `build_auth_verifier` → `get_token`
//! / `verify`) from the configs `shadi_identity` produces.

use shadi_identity::config::did_verifier_config;
use shadi_identity::{jwks_from_dids, AgentIdentity};

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
        verifier.verify(&member_token).await.is_ok(),
        "a member DID must be admitted"
    );
    // Intruder's key is absent from the JWKS → no trusted key → InvalidSignature.
    assert!(
        verifier.verify(&intruder_token).await.is_err(),
        "a non-member DID must be rejected by the allow-list"
    );
}
