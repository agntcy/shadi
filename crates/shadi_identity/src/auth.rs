// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Auth-mode selection for creating SLIM apps.
//!
//! [`SlimAuth`] is the DID-aware replacement for `create_app_with_secret`: it
//! yields the `(provider, verifier)` config pair for either the legacy shared
//! secret or DID-JWT admission, so call sites choose a mode without duplicating
//! config assembly. In DID mode, [`SlimMembers`] says which peers an app admits:
//! an allow-list of `did:key`s, or any `did:key` that proves its key (open).

use std::sync::Arc;

use slim_bindings::{App, IdentityProviderConfig, IdentityVerifierConfig, Name, Service};

use crate::{config, jwks_from_dids, AgentIdentity, IdentityError};

/// How a SLIM app authenticates to the mesh.
pub enum SlimAuth {
    /// Symmetric mesh secret (legacy; a homogeneous mesh shares one secret).
    SharedSecret(String),
    /// DID-JWT admission: prove `did` by signing with `signing_pem`; admit peers
    /// per `members`.
    Did {
        signing_pem: String,
        did: String,
        members: SlimMembers,
    },
}

/// Which peers a DID-mode app admits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlimMembers {
    /// Peers whose `did:key` is in `jwks` (the cryptographic allow-list), checked
    /// by SLIM's stock JWT verifier.
    AllowList { jwks: String },
    /// Any `did:key` that proves its key. Needs SHADI's `did:key` verifier, which
    /// this build does not include, so [`SlimAuth::configs`] refuses it.
    Open,
}

const OPEN_ADMISSION_UNSUPPORTED: &str =
    "open admission needs SHADI's did:key verifier, which this build does not include";

impl SlimAuth {
    /// DID auth for `agent`, trusting `member_dids` as the allow-list.
    pub fn did<'a, I>(agent: &AgentIdentity, member_dids: I) -> Result<Self, IdentityError>
    where
        I: IntoIterator<Item = &'a str>,
    {
        Ok(SlimAuth::Did {
            signing_pem: agent.to_pkcs8_pem()?,
            did: agent.did(),
            members: SlimMembers::AllowList {
                jwks: jwks_from_dids(member_dids)?,
            },
        })
    }

    /// DID auth for `agent`, admitting any `did:key` that proves its key.
    pub fn did_open(agent: &AgentIdentity) -> Result<Self, IdentityError> {
        Ok(SlimAuth::Did {
            signing_pem: agent.to_pkcs8_pem()?,
            did: agent.did(),
            members: SlimMembers::Open,
        })
    }

    /// Build the `(provider, verifier)` config pair for an app named `name`.
    ///
    /// Fails closed for [`SlimMembers::Open`]: this build has no verifier for it,
    /// and it never falls back to an allow-list or a shared secret.
    pub fn configs(
        &self,
        name: &Name,
    ) -> Result<(IdentityProviderConfig, IdentityVerifierConfig), IdentityError> {
        match self {
            SlimAuth::SharedSecret(secret) => Ok((
                IdentityProviderConfig::SharedSecret {
                    id: name.to_string(),
                    data: secret.clone(),
                },
                IdentityVerifierConfig::SharedSecret {
                    id: name.to_string(),
                    data: secret.clone(),
                },
            )),
            SlimAuth::Did {
                signing_pem,
                did,
                members: SlimMembers::AllowList { jwks },
            } => Ok((
                config::did_provider_config(signing_pem, did, None),
                config::did_verifier_config(jwks, None),
            )),
            SlimAuth::Did {
                members: SlimMembers::Open,
                ..
            } => Err(IdentityError::Config(
                OPEN_ADMISSION_UNSUPPORTED.to_string(),
            )),
        }
    }
}

/// Create an app on `service` authenticated per `auth` — the DID-aware replacement
/// for `Service::create_app_with_secret`. A config error from
/// [`SlimAuth::configs`] is returned before `service` is touched; SLIM's own
/// failure comes back as [`IdentityError::Slim`].
pub fn create_app(
    service: &Service,
    name: Arc<Name>,
    auth: &SlimAuth,
) -> Result<Arc<App>, IdentityError> {
    let (provider, verifier) = auth.configs(&name)?;
    Ok(service.create_app(name, provider, verifier)?)
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
        let (p, v) = auth.configs(&name).unwrap();
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
        let (p, v) = auth.configs(&name).unwrap();
        assert!(matches!(p, IdentityProviderConfig::Jwt { .. }));
        assert!(matches!(v, IdentityVerifierConfig::Jwt { .. }));
    }

    #[test]
    fn allow_list_configs_are_the_did_provider_and_member_jwks_verifier() {
        let agent = AgentIdentity::generate().unwrap();
        let peer = AgentIdentity::generate().unwrap();
        let name = Name::from_string("org/ns/app".to_string()).unwrap();
        let dids = [agent.did(), peer.did()];
        let auth = SlimAuth::did(&agent, dids.iter().map(String::as_str)).unwrap();
        let jwks = jwks_from_dids(dids.iter().map(String::as_str)).unwrap();
        match &auth {
            SlimAuth::Did { members, .. } => {
                assert_eq!(members, &SlimMembers::AllowList { jwks: jwks.clone() })
            }
            SlimAuth::SharedSecret(_) => panic!("expected DID auth"),
        }

        let (p, v) = auth.configs(&name).unwrap();
        let pem = agent.to_pkcs8_pem().unwrap();
        assert_eq!(p, config::did_provider_config(&pem, &agent.did(), None));
        assert_eq!(v, config::did_verifier_config(&jwks, None));
    }

    #[test]
    fn open_configs_fail_closed_with_the_reason() {
        let agent = AgentIdentity::generate().unwrap();
        let name = Name::from_string("org/ns/app".to_string()).unwrap();
        let auth = SlimAuth::did_open(&agent).unwrap();
        assert!(matches!(
            &auth,
            SlimAuth::Did {
                members: SlimMembers::Open,
                ..
            }
        ));
        match auth.configs(&name) {
            Err(IdentityError::Config(msg)) => {
                assert!(msg.contains("open admission"), "{msg}");
                assert!(msg.contains("did:key verifier"), "{msg}");
            }
            Err(e) => panic!("expected a config error, got {e:?}"),
            Ok(_) => panic!("open admission must not yield configs"),
        }
    }

    #[test]
    fn create_app_refuses_open_before_creating_an_app() {
        let agent = AgentIdentity::generate().unwrap();
        let name = Arc::new(Name::from_string("org/ns/open-app".to_string()).unwrap());
        let auth = SlimAuth::did_open(&agent).unwrap();
        let service = Service::new("shadi-identity-open-admission-test".to_string());
        match create_app(&service, name, &auth) {
            Err(IdentityError::Config(msg)) => assert!(msg.contains("open admission"), "{msg}"),
            Err(e) => panic!("expected a config error, got {e:?}"),
            Ok(_) => panic!("open admission must not create an app"),
        }
    }

    #[test]
    fn did_auth_for_still_rejects_an_empty_allow_list() {
        let agent = AgentIdentity::derive(b"seed", "agent-x").unwrap();
        match did_auth_for(&agent, " , ,") {
            Err(IdentityError::Config(msg)) => {
                assert!(msg.contains("allow-list is empty"), "{msg}")
            }
            _ => panic!("an empty allow-list must be a config error"),
        }
        assert!(matches!(
            build_did_auth(b"seed", "", "agent-x"),
            Err(IdentityError::Config(_))
        ));
    }

    #[test]
    fn slim_errors_display_as_slim_reported_them() {
        let slim = slim_bindings::SlimError::ConfigError {
            message: "bad".to_string(),
        };
        let shown = slim.to_string();
        let err = IdentityError::from(slim);
        assert!(matches!(err, IdentityError::Slim(_)));
        assert_eq!(err.to_string(), shown);
        assert!(std::error::Error::source(&err).is_some());
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
}
