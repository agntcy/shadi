//! Answers a peer's credential challenge from the operator's release policy.

use std::sync::Arc;

use shadi_mas::experiments::{LiveA2ATaskAdapter, LiveA2ATaskAdapterConfig};

/// A live adapter that answers a credential challenge with [`present`].
pub fn live_adapter(config: LiveA2ATaskAdapterConfig) -> LiveA2ATaskAdapter {
    let agent_id = config.agent_id.clone();
    let peer_did = config.peer_did.clone();
    // Attached even with nothing to release, so an unconfigured sender refuses
    // with a reason instead of burning its retries on an unanswerable challenge.
    LiveA2ATaskAdapter::new(config).with_presenter(Arc::new(move |challenge| {
        present(challenge, &agent_id, peer_did.as_deref())
    }))
}

/// Claim names this sender will release, from `SHADI_RELEASE_CLAIMS`. Empty
/// is legal: a sender that never presents.
fn release_claims() -> Vec<String> {
    std::env::var("SHADI_RELEASE_CLAIMS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// An explicit `SHADI_CREDENTIAL_BACKEND` is obeyed. Without one, an exported
/// `SHADI_CREDENTIAL_DB` or `SHADI_CREDENTIAL_KEY` selects sqlcipher, as in
/// `shadictl credential issue`: a vault opened differently would look like
/// "no credential found".
fn open_vault() -> Result<Box<dyn shadi_credential::CredentialVault>, String> {
    let db = std::env::var_os("SHADI_CREDENTIAL_DB").map(std::path::PathBuf::from);
    let key = std::env::var("SHADI_CREDENTIAL_KEY").ok();
    let explicit = std::env::var("SHADI_CREDENTIAL_BACKEND").ok();
    let backend = choose_backend(
        explicit.as_deref(),
        db.is_some() || key.is_some(),
        shadi_credential::default_backend,
    )?;
    shadi_credential::default_vault(backend, db.as_deref(), key.as_deref())
        .map_err(|e| e.to_string())
}

fn choose_backend(
    explicit: Option<&str>,
    db_or_key_given: bool,
    default: impl FnOnce() -> shadi_credential::VaultBackend,
) -> Result<shadi_credential::VaultBackend, String> {
    match explicit {
        Some(name) => name
            .parse()
            .map_err(|e| format!("SHADI_CREDENTIAL_BACKEND: {e}")),
        None if db_or_key_given => Ok(shadi_credential::VaultBackend::SqlCipher),
        None => Ok(default()),
    }
}

/// Answer a credential challenge with the claims the operator allowed. `Err`
/// is the reason the sender refuses.
fn present(challenge: &str, agent_id: &str, peer_did: Option<&str>) -> Result<String, String> {
    // First, so the diagnostic is the same whether or not a vault exists.
    let claims = release_claims();
    if claims.is_empty() {
        return Err(
            "the peer asked for a credential and SHADI_RELEASE_CLAIMS names no claim to release"
                .to_string(),
        );
    }
    // The audience check cannot run without knowing who we dialled.
    let peer_did =
        peer_did.ok_or("the peer's DID is unknown, so the challenge audience cannot be checked")?;
    let challenge: shadi_credential::Challenge =
        serde_json::from_str(challenge).map_err(|e| format!("malformed challenge: {e}"))?;
    let query =
        shadi_credential::DcqlQuery::parse(&challenge.dcql_query).map_err(|e| e.to_string())?;
    let paths: Vec<[&str; 1]> = claims.iter().map(|c| [c.as_str()]).collect();
    let paths: Vec<&[&str]> = paths.iter().map(|p| p.as_slice()).collect();
    let policy = shadi_credential::ReleasePolicy::new(&paths);
    let vault = open_vault()?;
    let identity = shadi_identity::agent_identity_from_env(agent_id).map_err(|e| e.to_string())?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    shadi_credential::answer_challenge(
        vault.as_ref(),
        &identity,
        &policy,
        peer_did,
        &challenge.aud,
        &challenge.nonce,
        &query,
        now,
    )
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadi_credential::VaultBackend;

    fn with_claims<T>(value: Option<&str>, f: impl FnOnce() -> T) -> T {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        match value {
            Some(v) => std::env::set_var("SHADI_RELEASE_CLAIMS", v),
            None => std::env::remove_var("SHADI_RELEASE_CLAIMS"),
        }
        let out = f();
        std::env::remove_var("SHADI_RELEASE_CLAIMS");
        out
    }

    #[test]
    fn release_claims_trims_and_drops_empties() {
        assert_eq!(with_claims(Some(" groups , "), release_claims), ["groups"]);
        assert!(with_claims(Some(",,"), release_claims).is_empty());
        assert!(with_claims(None, release_claims).is_empty());
    }

    #[test]
    fn explicit_backend_wins_over_a_named_db() {
        assert_eq!(
            choose_backend(Some("keychain"), true, || VaultBackend::SqlCipher),
            Ok(VaultBackend::Keychain)
        );
    }

    #[test]
    fn db_or_key_alone_selects_sqlcipher() {
        // The default is Keychain, so SqlCipher can only come from the rule.
        assert_eq!(
            choose_backend(None, true, || VaultBackend::Keychain),
            Ok(VaultBackend::SqlCipher)
        );
    }

    #[test]
    fn neither_named_uses_the_default() {
        assert_eq!(
            choose_backend(None, false, || VaultBackend::Keychain),
            Ok(VaultBackend::Keychain)
        );
        assert_eq!(
            choose_backend(None, false, || VaultBackend::SqlCipher),
            Ok(VaultBackend::SqlCipher)
        );
    }

    #[test]
    fn unparsable_backend_names_the_variable() {
        let err = choose_backend(Some("bogus"), false, || VaultBackend::Keychain)
            .expect_err("not a backend");
        assert!(err.contains("SHADI_CREDENTIAL_BACKEND"), "{err}");
    }

    #[test]
    fn present_without_claims_names_the_variable() {
        let err = with_claims(None, || present("{}", "agent", Some("did:key:zPeer")))
            .expect_err("nothing to release");
        assert!(err.contains("SHADI_RELEASE_CLAIMS"), "{err}");
    }

    #[test]
    fn present_without_peer_did_refuses() {
        let err = with_claims(Some("groups"), || present("{}", "agent", None))
            .expect_err("no audience to check");
        assert!(err.contains("peer's DID is unknown"), "{err}");
    }

    /// Sets every env var `present` reads, restoring each on drop so a panic
    /// mid-test cannot leak state into a sibling.
    struct FullEnv {
        prev: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }

    impl FullEnv {
        fn set(vars: &[(&'static str, &str)]) -> Self {
            let prev = vars
                .iter()
                .map(|(k, v)| {
                    let prev = std::env::var_os(k);
                    std::env::set_var(k, v);
                    (*k, prev)
                })
                .collect();
            Self { prev }
        }
    }

    impl Drop for FullEnv {
        fn drop(&mut self) {
            for (k, v) in &self.prev {
                match v {
                    Some(v) => std::env::set_var(k, v),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    #[test]
    fn present_builds_a_real_presentation_the_listener_can_verify() {
        use shadi_credential::testkit;

        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());

        let agent_id = "presenter-test-agent";
        let seed = "presenter-test-seed";
        let identity = shadi_identity::AgentIdentity::derive(seed.as_bytes(), agent_id).unwrap();

        // The kit's own `exp` is in the past; `present` reads the real clock.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let discs = [testkit::disclosure("groups", "platform-admins")];
        let mut claims = testkit::base_claims(&identity, &discs);
        claims["exp"] = (now + 3_600).into();
        let cred = testkit::credential(&testkit::issuer_key(), &testkit::base_header(), &claims, &discs);

        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("vault.db");
        let vault = shadi_credential::default_vault(
            shadi_credential::VaultBackend::SqlCipher,
            Some(&db),
            Some("test-key"),
        )
        .unwrap();
        shadi_credential::import(vault.as_ref(), &cred, now).unwrap();

        let peer_did = "did:key:zPeer";
        let dcql_query = serde_json::json!({
            "credentials": [{
                "id": "admission",
                "format": shadi_credential::SD_JWT_FORMAT,
                "meta": {"vct_values": [claims["vct"].clone()]},
                "claims": [{"path": ["groups"]}],
            }]
        })
        .to_string();
        // `Challenge` is `#[non_exhaustive]`; a real listener mints one the
        // same way, through the store it stamps `aud` and the query from.
        let nonces = shadi_credential::NonceStore::new(peer_did, dcql_query);
        let challenge = nonces.issue("t1", "did:key:unused", now).unwrap();
        let challenge_json = serde_json::to_string(&challenge).unwrap();

        let _env = FullEnv::set(&[
            ("SHADI_RELEASE_CLAIMS", "groups"),
            ("SHADI_CREDENTIAL_BACKEND", "sqlcipher"),
            ("SHADI_CREDENTIAL_DB", db.to_str().unwrap()),
            ("SHADI_CREDENTIAL_KEY", "test-key"),
            ("SHADI_SLIM_AUTH", "did"),
            ("SLIM_HUMAN_SEED", seed),
        ]);

        let token = present(&challenge_json, agent_id, Some(peer_did)).expect("presents");

        // Exactly the one disclosure the release policy allowed, verbatim,
        // followed by a three-part KB-JWT: confirms the vault lookup, the
        // claim-release intersection, and the signing all actually ran.
        let parts: Vec<&str> = token.split('~').collect();
        assert_eq!(parts.len(), 3, "{token}");
        assert_eq!(parts[1], discs[0]);
        assert_eq!(parts[2].split('.').count(), 3);
    }
}
