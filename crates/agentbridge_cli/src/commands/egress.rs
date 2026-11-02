//! The one check a message passes before it leaves agentbridge: the reply to
//! a task, the automatic `NEXT` handoff, and `delegate`, `handoff` and
//! `coordinate`.

use std::sync::Arc;

use a2a::Message;
use agent_secrets::{AgentVerifier, SecretResult, SessionContext};
use shadi_mas::experiments::{LiveA2ATaskAdapter, LiveA2ATaskAdapterConfig};

/// Allows every message: the policy until #367 and #368 add rules.
struct NoRules;

impl AgentVerifier for NoRules {
    fn verify(&self, _session: &SessionContext) -> SecretResult<()> {
        Ok(())
    }
}

/// The policy every outbound message passes.
pub(crate) fn policy() -> Arc<dyn AgentVerifier> {
    Arc::new(NoRules)
}

/// A live adapter whose every send passes [`policy`].
pub(crate) fn live_adapter(config: LiveA2ATaskAdapterConfig) -> LiveA2ATaskAdapter {
    let agent_id = config.agent_id.clone();
    let peer_did = config.peer_did.clone();
    // Attached even with nothing to release, so an unconfigured sender refuses
    // with a reason instead of burning its retries on an unanswerable challenge.
    LiveA2ATaskAdapter::new(config)
        .with_verifier(policy())
        .with_presenter(Arc::new(move |challenge| {
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

/// Same variables as `shadictl credential issue`: a vault opened differently
/// would look like "no credential found".
fn open_vault() -> Result<Box<dyn shadi_credential::CredentialVault>, String> {
    let backend = match std::env::var("SHADI_CREDENTIAL_BACKEND") {
        Ok(value) => value
            .parse::<shadi_credential::VaultBackend>()
            .map_err(|e| format!("SHADI_CREDENTIAL_BACKEND: {e}"))?,
        Err(_) => shadi_credential::default_backend(),
    };
    let db = std::env::var_os("SHADI_CREDENTIAL_DB").map(std::path::PathBuf::from);
    let key = std::env::var("SHADI_CREDENTIAL_KEY").ok();
    shadi_credential::default_vault(backend, db.as_deref(), key.as_deref())
        .map_err(|e| e.to_string())
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
    let shadi_identity::SlimAuth::Did { signing_pem, .. } =
        shadi_identity::require_did_auth_from_env(agent_id).map_err(|e| e.to_string())?
    else {
        return Err("presenting a credential requires SHADI_SLIM_AUTH=did".to_string());
    };
    let identity =
        shadi_identity::AgentIdentity::from_pkcs8_pem(&signing_pem).map_err(|e| e.to_string())?;
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

/// Check a message sent without an A2A channel, which is a listener's reply.
/// `Err` is the reason it may not leave, carrying the evaluation id the
/// refusal is logged under.
pub(crate) fn check(
    policy: &dyn AgentVerifier,
    session: &SessionContext,
    message: &Message,
) -> Result<(), String> {
    let request = shadi_a2a::request_context(message, policy.wants_content());
    let evaluation_id = request.evaluation_id();
    match policy.verify_request(session, &request) {
        Ok(()) => {
            tracing::info!(evaluation_id, "egress policy allowed a message");
            Ok(())
        }
        Err(err) => {
            tracing::warn!(evaluation_id, %err, "egress policy refused a message");
            Err(format!(
                "withheld by egress policy ({evaluation_id}): {err}"
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_claims<T>(value: Option<&str>, f: impl FnOnce() -> T) -> T {
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
}
