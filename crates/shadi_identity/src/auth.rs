// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Auth-mode selection for creating SLIM apps.
//!
//! [`SlimAuth`] is the DID-aware replacement for `create_app_with_secret`: it
//! yields the `(provider, verifier)` config pair for either the legacy shared
//! secret or DID-JWT admission, so call sites choose a mode without duplicating
//! config assembly.

use std::sync::Arc;

use slim_bindings::{
    App, IdentityProviderConfig, IdentityVerifierConfig, Name, Service, SlimError,
};

use crate::{config, jwks_from_dids, AgentIdentity, IdentityError};

/// How a SLIM app authenticates to the mesh.
pub enum SlimAuth {
    /// Symmetric mesh secret (legacy; a homogeneous mesh shares one secret).
    SharedSecret(String),
    /// DID-JWT admission: prove `did` by signing with `signing_pem`; admit peers
    /// whose DID is in `member_jwks`, or any did:key when it is `None`.
    Did {
        signing_pem: String,
        did: String,
        member_jwks: Option<String>,
        self_certified: bool,
    },
}

impl SlimAuth {
    /// DID auth for `agent`, trusting `member_dids` as the allow-list.
    pub fn did<'a, I>(agent: &AgentIdentity, member_dids: I) -> Result<Self, IdentityError>
    where
        I: IntoIterator<Item = &'a str>,
    {
        Ok(SlimAuth::Did {
            signing_pem: agent.to_pkcs8_pem()?,
            did: agent.did(),
            member_jwks: Some(jwks_from_dids(member_dids)?),
            self_certified: false,
        })
    }

    /// Open-admission auth for `agent`: any did:key is admitted unless `member_dids` is non-empty.
    pub fn open<'a, I>(agent: &AgentIdentity, member_dids: I) -> Result<Self, IdentityError>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let dids: Vec<&str> = member_dids.into_iter().collect();
        Ok(SlimAuth::Did {
            signing_pem: agent.to_pkcs8_pem()?,
            did: agent.did(),
            member_jwks: (!dids.is_empty()).then(|| jwks_from_dids(dids)).transpose()?,
            self_certified: true,
        })
    }

    /// Build the `(provider, verifier)` config pair for an app named `name`.
    pub fn configs(&self, name: &Name) -> (IdentityProviderConfig, IdentityVerifierConfig) {
        match self {
            SlimAuth::SharedSecret(secret) => (
                IdentityProviderConfig::SharedSecret {
                    id: name.to_string(),
                    data: secret.clone(),
                },
                IdentityVerifierConfig::SharedSecret {
                    id: name.to_string(),
                    data: secret.clone(),
                },
            ),
            SlimAuth::Did {
                signing_pem,
                did,
                member_jwks,
                self_certified,
            } => match (member_jwks.as_deref(), *self_certified) {
                (Some(jwks), false) => (
                    config::did_provider_config(signing_pem, did, None),
                    config::did_verifier_config(jwks, None),
                ),
                (jwks, true) => self_certified_configs(signing_pem, did, jwks),
                (None, false) => (IdentityProviderConfig::None, IdentityVerifierConfig::None),
            },
        }
    }
}

#[cfg(feature = "open-admission")]
fn self_certified_configs(
    signing_pem: &str,
    did: &str,
    member_jwks: Option<&str>,
) -> (IdentityProviderConfig, IdentityVerifierConfig) {
    let provider = match config::did_provider_config(signing_pem, did, None) {
        IdentityProviderConfig::Jwt { config } => {
            IdentityProviderConfig::InsecureSelfCertifiedDid { config }
        }
        other => other,
    };
    let verifier = match member_jwks {
        Some(jwks) => config::did_verifier_config(jwks, None),
        None => IdentityVerifierConfig::InsecureSelfCertifiedDid {
            config: slim_bindings::SelfCertifiedDidVerifierAuth { audience: None },
        },
    };
    (provider, verifier)
}

// Without the feature there is no self-certified provider; create_app then errors.
#[cfg(not(feature = "open-admission"))]
fn self_certified_configs(
    _: &str,
    _: &str,
    _: Option<&str>,
) -> (IdentityProviderConfig, IdentityVerifierConfig) {
    (IdentityProviderConfig::None, IdentityVerifierConfig::None)
}

/// `SHADI_SLIM_ADMISSION`: unset or empty is off, `open` is open, anything else is an error.
pub fn open_admission_from_env() -> Result<bool, IdentityError> {
    let value = std::env::var("SHADI_SLIM_ADMISSION").unwrap_or_default();
    match value.trim() {
        "" => Ok(false),
        v if v.eq_ignore_ascii_case("open") && cfg!(feature = "open-admission") => Ok(true),
        v if v.eq_ignore_ascii_case("open") => Err(IdentityError::Config(
            "SHADI_SLIM_ADMISSION=open requires a build with the open-admission feature"
                .to_string(),
        )),
        _ => Err(IdentityError::Config(
            "SHADI_SLIM_ADMISSION must be unset or `open`".to_string(),
        )),
    }
}

/// Create an app on `service` authenticated per `auth` — the DID-aware replacement
/// for `Service::create_app_with_secret`.
pub fn create_app(
    service: &Service,
    name: Arc<Name>,
    auth: &SlimAuth,
) -> Result<Arc<App>, SlimError> {
    let (provider, verifier) = auth.configs(&name);
    service.create_app(name, provider, verifier)
}

#[cfg(test)]
pub(crate) fn lock_slim_auth_env() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Build DID-JWT auth for `agent_id`: derive the agent key from `human_seed` (via
/// SHADI's HKDF agent derivation) and trust the comma-separated `member_dids` as the
/// allow-list. Pure (no environment access) so it is easy to unit-test.
pub fn build_did_auth(
    human_seed: &[u8],
    member_dids: &str,
    agent_id: &str,
) -> Result<SlimAuth, IdentityError> {
    did_auth_for(&AgentIdentity::derive(human_seed, agent_id)?, member_dids)
}

fn did_auth_for(agent: &AgentIdentity, member_dids: &str) -> Result<SlimAuth, IdentityError> {
    let dids: Vec<&str> = member_dids
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if dids.is_empty() {
        return Err(IdentityError::Config(
            "member DID allow-list is empty".to_string(),
        ));
    }
    SlimAuth::did(agent, dids)
}

/// Resolve how `agent_id` should authenticate to the SLIM mesh, from the environment.
///
/// Returns `Some(..)` iff `SHADI_SLIM_AUTH=did`, in which case the agent key is
/// derived from `SLIM_HUMAN_SEED` and the allow-list is `SLIM_MEMBER_DIDS`
/// (comma-separated `did:key`s). Returns `None` for any other mode, signalling the
/// caller to fall back to its own shared secret. This is the single env contract
/// shared by every SHADI `create_app` site.
pub fn did_auth_from_env(agent_id: &str) -> Option<Result<SlimAuth, IdentityError>> {
    let mode = std::env::var("SHADI_SLIM_AUTH").unwrap_or_default();
    if !mode.eq_ignore_ascii_case("did") {
        return None;
    }
    Some(resolve_did_env(agent_id))
}

/// Like [`did_auth_from_env`], but treats anything other than DID mode as a hard
/// error instead of a signal to fall back to a shared secret.
///
/// Coding-agent adapters (the CLI tools `agentbridge` wraps) must always
/// authenticate to the SLIM mesh via DID/keys — never a shared secret — so
/// callers that admit those adapters should use this instead of
/// [`did_auth_from_env`].
pub fn require_did_auth_from_env(agent_id: &str) -> Result<SlimAuth, IdentityError> {
    did_auth_from_env(agent_id).unwrap_or_else(|| {
        Err(IdentityError::Config(
            "coding-agent adapters must authenticate via DID (set SHADI_SLIM_AUTH=did, \
             SLIM_HUMAN_SEED, SLIM_MEMBER_DIDS); shared secrets are not permitted"
                .to_string(),
        ))
    })
}

/// The agent's own key from the environment: `SHADI_SLIM_AUTH=did` plus
/// `SLIM_HUMAN_SEED`. Unlike [`did_auth_from_env`] it needs no peer allow-list,
/// so callers that only sign or name themselves do not depend on one.
pub fn agent_identity_from_env(agent_id: &str) -> Result<AgentIdentity, IdentityError> {
    let mode = std::env::var("SHADI_SLIM_AUTH").unwrap_or_default();
    if !mode.eq_ignore_ascii_case("did") {
        return Err(IdentityError::Config(
            "an agent identity requires SHADI_SLIM_AUTH=did and SLIM_HUMAN_SEED".to_string(),
        ));
    }
    let human_seed = std::env::var("SLIM_HUMAN_SEED").map_err(|_| {
        IdentityError::Config("SHADI_SLIM_AUTH=did requires SLIM_HUMAN_SEED".to_string())
    })?;
    AgentIdentity::derive(human_seed.as_bytes(), agent_id)
}

/// [`require_did_auth_from_env`] for a caller that dials `peer_did`: under open
/// admission the verifier is pinned to that peer and the caller's own DID.
pub fn require_did_auth_for_peer(
    agent_id: &str,
    peer_did: Option<&str>,
) -> Result<SlimAuth, IdentityError> {
    if !open_admission_from_env()? {
        return require_did_auth_from_env(agent_id);
    }
    let peer = peer_did.ok_or_else(|| {
        IdentityError::Config("open admission needs the dialled peer's DID".to_string())
    })?;
    let agent = agent_identity_from_env(agent_id)?;
    // MLS also verifies our own credential, so the pinned list must hold our DID.
    let own = agent.did();
    SlimAuth::open(&agent, [peer, own.as_str()])
}

/// [`require_did_auth_from_env`] for a listener: under open admission any did:key
/// is admitted unless `SLIM_MEMBER_DIDS` lists some.
pub fn listener_did_auth_from_env(agent_id: &str) -> Result<SlimAuth, IdentityError> {
    if !open_admission_from_env()? {
        return require_did_auth_from_env(agent_id);
    }
    let agent = agent_identity_from_env(agent_id)?;
    let members = std::env::var("SLIM_MEMBER_DIDS").unwrap_or_default();
    SlimAuth::open(
        &agent,
        members.split(',').map(str::trim).filter(|s| !s.is_empty()),
    )
}

fn resolve_did_env(agent_id: &str) -> Result<SlimAuth, IdentityError> {
    let agent = agent_identity_from_env(agent_id)?;
    let members = std::env::var("SLIM_MEMBER_DIDS").map_err(|_| {
        IdentityError::Config("SHADI_SLIM_AUTH=did requires SLIM_MEMBER_DIDS".to_string())
    })?;
    did_auth_for(&agent, &members)
}

#[cfg(test)]
mod tests {
    use super::*;
    use slim_bindings::Name;

    #[test]
    fn shared_secret_configs_match_create_app_with_secret() {
        let name = Name::from_string("org/ns/app".to_string()).unwrap();
        let auth = SlimAuth::SharedSecret("s3cret".to_string());
        let (p, v) = auth.configs(&name);
        match (p, v) {
            (
                IdentityProviderConfig::SharedSecret { id, data },
                IdentityVerifierConfig::SharedSecret { id: vid, data: vdata },
            ) => {
                assert_eq!(id, name.to_string());
                assert_eq!(vid, name.to_string());
                assert_eq!(data, "s3cret");
                assert_eq!(vdata, "s3cret");
            }
            _ => panic!("expected shared-secret configs"),
        }
    }

    #[test]
    fn did_configs_are_jwt_provider_and_verifier() {
        let agent = AgentIdentity::generate().unwrap();
        let peer = AgentIdentity::generate().unwrap();
        let name = Name::from_string("org/ns/app".to_string()).unwrap();
        let auth = SlimAuth::did(&agent, [agent.did().as_str(), peer.did().as_str()]).unwrap();
        let (p, v) = auth.configs(&name);
        assert!(matches!(p, IdentityProviderConfig::Jwt { .. }));
        assert!(matches!(v, IdentityVerifierConfig::Jwt { .. }));
    }

    #[test]
    fn build_did_auth_builds_did_for_members() {
        let a = AgentIdentity::derive(b"seed", "agent-x").unwrap();
        let p = AgentIdentity::derive(b"seed", "peer").unwrap();
        let members = format!("{}, {}", a.did(), p.did());
        let auth = build_did_auth(b"seed", &members, "agent-x").expect("did auth");
        assert!(matches!(auth, SlimAuth::Did { .. }));
    }

    #[test]
    fn build_did_auth_rejects_empty_and_invalid_members() {
        assert!(matches!(
            build_did_auth(b"seed", "  ,  ", "agent-x"),
            Err(IdentityError::Config(_))
        ));
        assert!(build_did_auth(b"seed", "not-a-did-key", "agent-x").is_err());
    }

    #[test]
    fn did_auth_from_env_selects_mode() {
        use std::env;
        let _guard = crate::auth::lock_slim_auth_env();
        let member = AgentIdentity::derive(b"human", "avatar").unwrap().did();

        env::remove_var("SHADI_SLIM_AUTH");
        assert!(did_auth_from_env("avatar").is_none());
        // require_did_auth_from_env never falls back — not-DID-mode is a hard error.
        assert!(matches!(
            require_did_auth_from_env("avatar"),
            Err(IdentityError::Config(_))
        ));

        env::set_var("SHADI_SLIM_AUTH", "did");
        env::set_var("SLIM_HUMAN_SEED", "human");
        env::set_var("SLIM_MEMBER_DIDS", &member);
        assert!(matches!(
            did_auth_from_env("avatar"),
            Some(Ok(SlimAuth::Did { .. }))
        ));
        assert!(matches!(
            require_did_auth_from_env("avatar"),
            Ok(SlimAuth::Did { .. })
        ));

        env::remove_var("SLIM_HUMAN_SEED");
        assert!(matches!(
            did_auth_from_env("avatar"),
            Some(Err(IdentityError::Config(_)))
        ));

        env::remove_var("SHADI_SLIM_AUTH");
        env::remove_var("SLIM_MEMBER_DIDS");
    }

    #[test]
    fn agent_identity_from_env_requires_did_mode_not_members() {
        use std::env;
        let _guard = crate::auth::lock_slim_auth_env();
        env::set_var("SLIM_HUMAN_SEED", "human");
        env::remove_var("SLIM_MEMBER_DIDS");

        env::remove_var("SHADI_SLIM_AUTH");
        assert!(matches!(
            agent_identity_from_env("avatar"),
            Err(IdentityError::Config(_))
        ));
        env::set_var("SHADI_SLIM_AUTH", "shared-secret");
        assert!(agent_identity_from_env("avatar").is_err());

        env::set_var("SHADI_SLIM_AUTH", "DID");
        let id = agent_identity_from_env("avatar").expect("no member list needed");
        let expected = AgentIdentity::derive(b"human", "avatar").unwrap().did();
        assert_eq!(id.did(), expected);

        env::remove_var("SHADI_SLIM_AUTH");
        env::remove_var("SLIM_HUMAN_SEED");
    }

    #[cfg(feature = "open-admission")]
    #[test]
    fn open_auth_is_self_certified_and_pins_only_listed_peers() {
        let agent = AgentIdentity::generate().unwrap();
        let peer = AgentIdentity::generate().unwrap();
        let name = Name::from_string("org/ns/app".to_string()).unwrap();

        let (p, v) = SlimAuth::open(&agent, []).unwrap().configs(&name);
        assert!(matches!(p, IdentityProviderConfig::InsecureSelfCertifiedDid { .. }));
        assert!(matches!(v, IdentityVerifierConfig::InsecureSelfCertifiedDid { .. }));

        let (p, v) = SlimAuth::open(&agent, [peer.did().as_str()]).unwrap().configs(&name);
        assert!(matches!(p, IdentityProviderConfig::InsecureSelfCertifiedDid { .. }));
        assert!(matches!(v, IdentityVerifierConfig::Jwt { .. }));
    }

    #[test]
    fn configs_that_cannot_be_served_are_none() {
        let agent = AgentIdentity::generate().unwrap();
        let name = Name::from_string("org/ns/app".to_string()).unwrap();
        let neither = SlimAuth::Did {
            signing_pem: agent.to_pkcs8_pem().unwrap(),
            did: agent.did(),
            member_jwks: None,
            self_certified: false,
        };
        let (p, v) = neither.configs(&name);
        assert!(matches!(p, IdentityProviderConfig::None));
        assert!(matches!(v, IdentityVerifierConfig::None));
        #[cfg(not(feature = "open-admission"))]
        {
            let (p, v) = SlimAuth::open(&agent, []).unwrap().configs(&name);
            assert!(matches!(p, IdentityProviderConfig::None));
            assert!(matches!(v, IdentityVerifierConfig::None));
        }
    }

    #[test]
    fn admission_env_is_parsed_strictly() {
        use std::env;
        let _guard = crate::auth::lock_slim_auth_env();
        env::remove_var("SHADI_SLIM_ADMISSION");
        assert!(!open_admission_from_env().unwrap());
        env::set_var("SHADI_SLIM_ADMISSION", "  ");
        assert!(!open_admission_from_env().unwrap());
        env::set_var("SHADI_SLIM_ADMISSION", "allow");
        let err = open_admission_from_env().unwrap_err().to_string();
        assert!(err.contains("SHADI_SLIM_ADMISSION"), "{err}");
        env::set_var("SHADI_SLIM_ADMISSION", " OPEN ");
        let open = open_admission_from_env();
        #[cfg(feature = "open-admission")]
        assert!(open.unwrap());
        #[cfg(not(feature = "open-admission"))]
        assert!(open.unwrap_err().to_string().contains("open-admission"));
        env::remove_var("SHADI_SLIM_ADMISSION");
    }

    #[cfg(feature = "open-admission")]
    #[test]
    fn open_admission_pins_callers_and_leaves_other_paths_alone() {
        use std::env;
        let _guard = crate::auth::lock_slim_auth_env();
        env::set_var("SHADI_SLIM_AUTH", "did");
        env::set_var("SLIM_HUMAN_SEED", "human");
        env::set_var("SHADI_SLIM_ADMISSION", "open");
        env::set_var("SLIM_MEMBER_DIDS", AgentIdentity::generate().unwrap().did());

        assert!(matches!(
            require_did_auth_for_peer("avatar", None),
            Err(IdentityError::Config(_))
        ));
        let peer = AgentIdentity::generate().unwrap().did();
        let own = AgentIdentity::derive(b"human", "avatar").unwrap().did();
        match require_did_auth_for_peer("avatar", Some(&peer)).unwrap() {
            SlimAuth::Did { member_jwks, self_certified, .. } => {
                assert!(self_certified);
                assert_eq!(
                    member_jwks,
                    Some(jwks_from_dids([peer.as_str(), own.as_str()]).unwrap())
                );
            }
            SlimAuth::SharedSecret(_) => panic!("expected DID auth"),
        }

        // The shared env path ignores the admission switch.
        match did_auth_from_env("avatar").unwrap().unwrap() {
            SlimAuth::Did { self_certified, member_jwks, .. } => {
                assert!(!self_certified);
                assert!(member_jwks.is_some());
            }
            SlimAuth::SharedSecret(_) => panic!("expected DID auth"),
        }
        env::remove_var("SLIM_MEMBER_DIDS");
        assert!(matches!(
            did_auth_from_env("avatar"),
            Some(Err(IdentityError::Config(_)))
        ));

        match listener_did_auth_from_env("avatar").unwrap() {
            SlimAuth::Did { member_jwks, self_certified, .. } => {
                assert!(self_certified);
                assert!(member_jwks.is_none());
            }
            SlimAuth::SharedSecret(_) => panic!("expected DID auth"),
        }

        env::remove_var("SHADI_SLIM_ADMISSION");
        env::remove_var("SHADI_SLIM_AUTH");
        env::remove_var("SLIM_HUMAN_SEED");
    }

    #[cfg(not(feature = "open-admission"))]
    #[test]
    fn open_admission_without_the_feature_is_an_error() {
        use std::env;
        let _guard = crate::auth::lock_slim_auth_env();
        env::set_var("SHADI_SLIM_AUTH", "did");
        env::set_var("SLIM_HUMAN_SEED", "human");
        env::set_var("SLIM_MEMBER_DIDS", AgentIdentity::generate().unwrap().did());
        env::set_var("SHADI_SLIM_ADMISSION", "open");

        let is_feature_err = |r: Result<SlimAuth, IdentityError>| {
            matches!(r, Err(IdentityError::Config(m)) if m.contains("open-admission"))
        };
        assert!(is_feature_err(require_did_auth_for_peer("avatar", Some("did:key:zPeer"))));
        assert!(is_feature_err(listener_did_auth_from_env("avatar")));
        // The shared env path ignores the switch.
        assert!(matches!(did_auth_from_env("avatar"), Some(Ok(_))));

        env::remove_var("SHADI_SLIM_ADMISSION");
        env::remove_var("SHADI_SLIM_AUTH");
        env::remove_var("SLIM_HUMAN_SEED");
        env::remove_var("SLIM_MEMBER_DIDS");
    }
}
