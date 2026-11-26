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

use crate::{config, jwks_from_dids, parse_did_key, AgentIdentity, IdentityError};

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
///
/// This builds the `SLIM_MEMBER_DIDS` allow-list, so it supports only
/// [`SlimAdmission::Closed`]: under `SHADI_SLIM_ADMISSION=open` it returns
/// `Some(Err(..))`, and a bad or conflicting admission setting is the same
/// `Some(Err(..))`. Flows that support open admission use
/// [`require_did_auth_for_peer`] instead.
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
/// [`did_auth_from_env`]. Like it, this is closed-admission only and returns an
/// error under `SHADI_SLIM_ADMISSION=open`.
pub fn require_did_auth_from_env(agent_id: &str) -> Result<SlimAuth, IdentityError> {
    did_auth_from_env(agent_id).unwrap_or_else(|| {
        Err(IdentityError::Config(
            "coding-agent adapters must authenticate via DID (set SHADI_SLIM_AUTH=did, \
             SLIM_HUMAN_SEED, SLIM_MEMBER_DIDS); shared secrets are not permitted"
                .to_string(),
        ))
    })
}

/// Environment variable that selects the admission mode.
const SLIM_ADMISSION_VAR: &str = "SHADI_SLIM_ADMISSION";

/// Longest copy of a rejected `SHADI_SLIM_ADMISSION` value echoed in an error.
const ADMISSION_ECHO_MAX_CHARS: usize = 32;

/// Which peers a DID-mode app admits, as selected by `SHADI_SLIM_ADMISSION`.
///
/// The switch is explicit: nothing infers the mode from whether
/// `SLIM_MEMBER_DIDS` happens to be set. Only meaningful under
/// `SHADI_SLIM_AUTH=did`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlimAdmission {
    /// `SLIM_MEMBER_DIDS` is the required allow-list (the default).
    Closed,
    /// Any `did:key` may connect to a listener; a caller that dials a peer pins
    /// that peer's DID.
    Open,
}

impl SlimAdmission {
    /// The lowercase name: `"closed"` or `"open"`.
    pub const fn as_str(self) -> &'static str {
        match self {
            SlimAdmission::Closed => "closed",
            SlimAdmission::Open => "open",
        }
    }
}

impl std::fmt::Display for SlimAdmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Short, printable copy of an untrusted value for an error message: control
/// characters stripped, at most [`ADMISSION_ECHO_MAX_CHARS`] characters.
fn sanitized_echo(raw: &str) -> String {
    let mut chars = raw.chars().filter(|c| !c.is_control());
    let mut out: String = chars.by_ref().take(ADMISSION_ECHO_MAX_CHARS).collect();
    if chars.next().is_some() {
        out.push('…');
    }
    out
}

/// Parse the admission switch from the raw `SHADI_SLIM_ADMISSION` and
/// `SLIM_MEMBER_DIDS` values (`None`: unset). Pure (no environment access).
///
/// - `raw` unset or blank after trimming: [`SlimAdmission::Closed`].
/// - `raw` is `open` (trimmed; ASCII case-insensitive, like the `did` check of
///   `SHADI_SLIM_AUTH`): [`SlimAdmission::Open`].
/// - anything else: [`IdentityError::Config`] naming the variable and the
///   accepted values; never silently closed or open.
/// - `open` together with a non-blank `member_dids`: [`IdentityError::Config`],
///   because the two contradict. Neither wins.
///
/// Closed does not look at `member_dids`: the allow-list builders require it.
pub fn parse_slim_admission(
    raw: Option<&str>,
    member_dids: Option<&str>,
) -> Result<SlimAdmission, IdentityError> {
    let mode = match raw.map(str::trim) {
        None | Some("") => SlimAdmission::Closed,
        Some(v) if v.eq_ignore_ascii_case("open") => SlimAdmission::Open,
        Some(v) => {
            return Err(IdentityError::Config(format!(
                "{SLIM_ADMISSION_VAR} must be unset, empty, or \"open\" \
                 (unset or empty means closed: SLIM_MEMBER_DIDS is the allow-list); got \"{}\"",
                sanitized_echo(v)
            )));
        }
    };
    if mode == SlimAdmission::Open && member_dids.is_some_and(|m| !m.trim().is_empty()) {
        return Err(IdentityError::Config(format!(
            "{SLIM_ADMISSION_VAR}=open and SLIM_MEMBER_DIDS contradict each other: unset \
             SLIM_MEMBER_DIDS for open admission, or unset {SLIM_ADMISSION_VAR} to use the \
             allow-list"
        )));
    }
    Ok(mode)
}

/// The admission mode from the environment (`SHADI_SLIM_ADMISSION`, with the
/// `SLIM_MEMBER_DIDS` conflict check); see [`parse_slim_admission`].
///
/// Every consumer goes through this rather than reading either variable itself.
/// A value that is not valid Unicode is an error, like any other bad value.
pub fn slim_admission_from_env() -> Result<SlimAdmission, IdentityError> {
    let raw = match std::env::var(SLIM_ADMISSION_VAR) {
        Ok(v) => Some(v),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(IdentityError::Config(format!(
                "{SLIM_ADMISSION_VAR} must be unset, empty, or \"open\" (value is not valid Unicode)"
            )));
        }
    };
    let members = std::env::var_os("SLIM_MEMBER_DIDS").map(|v| v.to_string_lossy().into_owned());
    parse_slim_admission(raw.as_deref(), members.as_deref())
}

const OPEN_NOT_SUPPORTED_BY_ALLOW_LIST: &str =
    "SHADI_SLIM_ADMISSION=open has no member allow-list; this flow does not support open admission";

/// DID auth for a caller that dialled exactly `peer_did`, from the environment.
///
/// Pins the verifier to `{peer_did, own DID}` and never reads `SLIM_MEMBER_DIDS`,
/// so under open admission a caller trusts the peer it dialled, not any `did:key`.
/// The own DID is included because SLIM's MLS Welcome verifies every member
/// credential, the caller's own among them. Needs `SHADI_SLIM_AUTH=did` and
/// `SLIM_HUMAN_SEED`; a missing or malformed `peer_did` is an error, never a
/// fallback to the env allow-list.
pub fn require_did_auth_for_peer(
    agent_id: &str,
    peer_did: &str,
) -> Result<SlimAuth, IdentityError> {
    let mode = std::env::var("SHADI_SLIM_AUTH").unwrap_or_default();
    if !mode.eq_ignore_ascii_case("did") {
        return Err(IdentityError::Config(
            "coding-agent adapters must authenticate via DID (set SHADI_SLIM_AUTH=did \
             and SLIM_HUMAN_SEED); shared secrets are not permitted"
                .to_string(),
        ));
    }
    did_auth_for_peer(&agent_identity_from_env(agent_id)?, peer_did)
}

/// Like [`require_did_auth_for_peer`], with the key derived from `human_seed` (via
/// SHADI's HKDF agent derivation). Pure (no environment access) for unit tests.
pub fn build_did_auth_for_peer(
    human_seed: &[u8],
    agent_id: &str,
    peer_did: &str,
) -> Result<SlimAuth, IdentityError> {
    did_auth_for_peer(&AgentIdentity::derive(human_seed, agent_id)?, peer_did)
}

fn did_auth_for_peer(agent: &AgentIdentity, peer_did: &str) -> Result<SlimAuth, IdentityError> {
    let peer_key = parse_did_key(peer_did)?;
    let own_did = agent.did();
    if peer_key.as_bytes() == &agent.verifying_key_bytes() {
        // Dialling ourselves: one entry, not a duplicate `kid`.
        return SlimAuth::did(agent, [own_did.as_str()]);
    }
    SlimAuth::did(agent, [peer_did, own_did.as_str()])
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
    // Fail closed: a bad or conflicting admission setting stops here, and open
    // admission has no allow-list for this builder to use.
    if slim_admission_from_env()? == SlimAdmission::Open {
        return Err(IdentityError::Config(
            OPEN_NOT_SUPPORTED_BY_ALLOW_LIST.to_string(),
        ));
    }
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

        env::remove_var("SHADI_SLIM_ADMISSION");
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

    /// The `kid`s of an allow-list `auth`'s JWKS, in order.
    fn jwks_kids(auth: &SlimAuth) -> Vec<String> {
        let SlimAuth::Did {
            members: SlimMembers::AllowList { jwks },
            ..
        } = auth
        else {
            panic!("expected an allow-list DID auth");
        };
        let jwks: serde_json::Value = serde_json::from_str(jwks).unwrap();
        jwks["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| k["kid"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn build_did_auth_for_peer_pins_exactly_the_peer_and_own_did() {
        let own = AgentIdentity::derive(b"seed", "agent-x").unwrap().did();
        let peer = AgentIdentity::derive(b"seed", "peer").unwrap().did();
        let auth = build_did_auth_for_peer(b"seed", "agent-x", &peer).unwrap();
        match &auth {
            SlimAuth::Did { did, .. } => assert_eq!(did, &own),
            SlimAuth::SharedSecret(_) => panic!("expected DID auth"),
        }
        assert_eq!(jwks_kids(&auth), vec![peer.clone(), own.clone()]);
        // Each entry is a real key for its DID, not just a label.
        let SlimAuth::Did {
            members: SlimMembers::AllowList { jwks },
            ..
        } = &auth
        else {
            unreachable!()
        };
        assert_eq!(
            jwks,
            &jwks_from_dids([peer.as_str(), own.as_str()]).unwrap()
        );
    }

    #[test]
    fn build_did_auth_for_peer_dedupes_when_the_peer_is_the_caller() {
        let own = AgentIdentity::derive(b"seed", "agent-x").unwrap().did();
        let auth = build_did_auth_for_peer(b"seed", "agent-x", &own).unwrap();
        assert_eq!(jwks_kids(&auth), vec![own]);
    }

    #[test]
    fn build_did_auth_for_peer_rejects_a_bad_peer() {
        let non_ed25519 = format!(
            "did:key:z{}",
            bs58::encode([&[0xe7u8, 0x01][..], &[2u8; 33][..]].concat()).into_string()
        );
        let good = AgentIdentity::derive(b"seed", "peer").unwrap().did();
        let padded = format!(" {good}");
        for bad in [
            "",
            "   ",
            "peer",
            "did:web:example.com",
            "did:key:z",
            non_ed25519.as_str(),
            padded.as_str(),
        ] {
            assert!(
                matches!(
                    build_did_auth_for_peer(b"seed", "agent-x", bad),
                    Err(IdentityError::InvalidDid(_))
                ),
                "{bad:?} must be an invalid did:key"
            );
        }
    }

    #[test]
    fn require_did_auth_for_peer_ignores_slim_member_dids() {
        use std::env;
        let _guard = crate::auth::lock_slim_auth_env();
        let own = AgentIdentity::derive(b"human", "avatar").unwrap().did();
        let peer = AgentIdentity::derive(b"human", "peer").unwrap().did();
        let third = AgentIdentity::derive(b"human", "third").unwrap().did();
        env::set_var("SHADI_SLIM_AUTH", "DID");
        env::set_var("SLIM_HUMAN_SEED", "human");

        // Works with no allow-list at all (open admission).
        env::remove_var("SLIM_MEMBER_DIDS");
        let auth = require_did_auth_for_peer("avatar", &peer).expect("no member list needed");
        assert_eq!(jwks_kids(&auth), vec![peer.clone(), own.clone()]);

        // A listed DID, even a valid one, never widens the pin.
        env::set_var("SLIM_MEMBER_DIDS", format!("{third},{peer}"));
        let auth = require_did_auth_for_peer("avatar", &peer).unwrap();
        assert_eq!(jwks_kids(&auth), vec![peer.clone(), own.clone()]);
        // Nor does a bad peer fall back to it.
        assert!(matches!(
            require_did_auth_for_peer("avatar", ""),
            Err(IdentityError::InvalidDid(_))
        ));

        env::remove_var("SHADI_SLIM_AUTH");
        env::remove_var("SLIM_HUMAN_SEED");
        env::remove_var("SLIM_MEMBER_DIDS");
    }

    #[test]
    fn require_did_auth_for_peer_needs_did_mode_and_a_seed() {
        use std::env;
        let _guard = crate::auth::lock_slim_auth_env();
        let peer = AgentIdentity::derive(b"human", "peer").unwrap().did();
        env::remove_var("SLIM_MEMBER_DIDS");
        env::set_var("SLIM_HUMAN_SEED", "human");

        for mode in [None, Some("shared-secret"), Some("")] {
            match mode {
                Some(m) => env::set_var("SHADI_SLIM_AUTH", m),
                None => env::remove_var("SHADI_SLIM_AUTH"),
            }
            match require_did_auth_for_peer("avatar", &peer) {
                Err(IdentityError::Config(msg)) => {
                    assert!(msg.contains("shared secrets are not permitted"), "{msg}")
                }
                _ => panic!("mode {mode:?} must be a config error"),
            }
        }

        env::set_var("SHADI_SLIM_AUTH", "did");
        env::remove_var("SLIM_HUMAN_SEED");
        match require_did_auth_for_peer("avatar", &peer) {
            Err(IdentityError::Config(msg)) => assert!(msg.contains("SLIM_HUMAN_SEED"), "{msg}"),
            _ => panic!("a missing seed must be a config error"),
        }

        env::remove_var("SHADI_SLIM_AUTH");
    }

    fn config_msg(r: Result<SlimAdmission, IdentityError>) -> String {
        match r {
            Err(IdentityError::Config(msg)) => msg,
            other => panic!("expected a config error, got {other:?}"),
        }
    }

    #[test]
    fn parse_slim_admission_unset_or_blank_is_closed() {
        for raw in [None, Some(""), Some("  "), Some(" \t\n")] {
            assert_eq!(
                parse_slim_admission(raw, None).unwrap(),
                SlimAdmission::Closed,
                "{raw:?}"
            );
        }
    }

    #[test]
    fn parse_slim_admission_open_is_trimmed_and_ascii_case_insensitive() {
        for raw in ["open", " OPEN ", "Open", "\topen\n"] {
            assert_eq!(
                parse_slim_admission(Some(raw), None).unwrap(),
                SlimAdmission::Open,
                "{raw:?}"
            );
        }
    }

    #[test]
    fn parse_slim_admission_rejects_anything_else_naming_the_variable() {
        for raw in [
            "opne",
            "closed",
            "true",
            "1",
            "open;",
            "o pen",
            "ópen",
            "open open",
        ] {
            let msg = config_msg(parse_slim_admission(Some(raw), None));
            assert!(msg.contains("SHADI_SLIM_ADMISSION"), "{msg}");
            assert!(msg.contains("\"open\""), "{msg}");
            assert!(msg.contains(&format!("got \"{raw}\"")), "{msg}");
            // A bad value is never closed, even with an allow-list present.
            assert!(parse_slim_admission(Some(raw), Some("did:key:zA")).is_err());
        }
    }

    #[test]
    fn parse_slim_admission_sanitizes_and_caps_the_echoed_value() {
        let msg = config_msg(parse_slim_admission(Some("bad\u{1b}[31m\r\nvalue\0"), None));
        assert!(msg.contains("got \"bad[31mvalue\""), "{msg}");
        assert!(!msg.chars().any(char::is_control), "{msg:?}");

        let long = "x".repeat(1000);
        let msg = config_msg(parse_slim_admission(Some(&long), None));
        assert!(msg.contains(&format!("\"{}…\"", "x".repeat(32))), "{msg}");
        assert!(!msg.contains(&"x".repeat(33)), "{msg}");
        assert!(msg.len() < 400, "{}", msg.len());

        // Exactly at the cap: no ellipsis.
        let exact = "y".repeat(32);
        let msg = config_msg(parse_slim_admission(Some(&exact), None));
        assert!(msg.contains(&format!("\"{exact}\"")), "{msg}");
    }

    #[test]
    fn parse_slim_admission_open_with_member_dids_is_a_conflict() {
        let did = AgentIdentity::derive(b"human", "peer").unwrap().did();
        for members in [did.as_str(), "  did:key:zA  ", "a,b"] {
            let msg = config_msg(parse_slim_admission(Some("open"), Some(members)));
            assert!(msg.contains("contradict"), "{msg}");
            assert!(
                msg.contains("unset SLIM_MEMBER_DIDS for open admission"),
                "{msg}"
            );
            assert!(
                msg.contains("unset SHADI_SLIM_ADMISSION to use the allow-list"),
                "{msg}"
            );
            assert!(
                !msg.contains(members.trim()),
                "the DIDs are not echoed: {msg}"
            );
        }
        for blank in ["", "  ", " \t\n"] {
            assert_eq!(
                parse_slim_admission(Some("open"), Some(blank)).unwrap(),
                SlimAdmission::Open,
                "{blank:?}"
            );
        }
    }

    #[test]
    fn parse_slim_admission_closed_ignores_member_dids() {
        for members in [None, Some(""), Some("did:key:zA"), Some("not even a did")] {
            for raw in [None, Some(""), Some("  ")] {
                assert_eq!(
                    parse_slim_admission(raw, members).unwrap(),
                    SlimAdmission::Closed
                );
            }
        }
    }

    #[test]
    fn slim_admission_names() {
        assert_eq!(SlimAdmission::Closed.as_str(), "closed");
        assert_eq!(SlimAdmission::Open.as_str(), "open");
        assert_eq!(SlimAdmission::Closed.to_string(), "closed");
        assert_eq!(SlimAdmission::Open.to_string(), "open");
    }

    #[test]
    fn slim_admission_from_env_reads_both_variables() {
        use std::env;
        let _guard = crate::auth::lock_slim_auth_env();
        env::remove_var("SHADI_SLIM_ADMISSION");
        env::remove_var("SLIM_MEMBER_DIDS");
        assert_eq!(slim_admission_from_env().unwrap(), SlimAdmission::Closed);

        env::set_var("SHADI_SLIM_ADMISSION", "  ");
        env::set_var("SLIM_MEMBER_DIDS", "did:key:zA");
        assert_eq!(slim_admission_from_env().unwrap(), SlimAdmission::Closed);

        env::set_var("SHADI_SLIM_ADMISSION", " Open ");
        let msg = config_msg(slim_admission_from_env());
        assert!(msg.contains("contradict"), "{msg}");
        env::set_var("SLIM_MEMBER_DIDS", "  ");
        assert_eq!(slim_admission_from_env().unwrap(), SlimAdmission::Open);
        env::remove_var("SLIM_MEMBER_DIDS");
        assert_eq!(slim_admission_from_env().unwrap(), SlimAdmission::Open);

        env::set_var("SHADI_SLIM_ADMISSION", "opne");
        let msg = config_msg(slim_admission_from_env());
        assert!(msg.contains("SHADI_SLIM_ADMISSION"), "{msg}");

        env::remove_var("SHADI_SLIM_ADMISSION");
        env::remove_var("SLIM_MEMBER_DIDS");
    }

    #[cfg(unix)]
    #[test]
    fn slim_admission_from_env_rejects_a_non_unicode_value() {
        use std::os::unix::ffi::OsStrExt;
        let _guard = crate::auth::lock_slim_auth_env();
        std::env::remove_var("SLIM_MEMBER_DIDS");
        std::env::set_var(
            "SHADI_SLIM_ADMISSION",
            std::ffi::OsStr::from_bytes(b"open\xff"),
        );
        let msg = config_msg(slim_admission_from_env());
        assert!(msg.contains("SHADI_SLIM_ADMISSION"), "{msg}");
        assert!(msg.contains("not valid Unicode"), "{msg}");
        std::env::remove_var("SHADI_SLIM_ADMISSION");
    }

    #[test]
    fn allow_list_builders_fail_closed_under_open_and_on_a_bad_switch() {
        use std::env;
        let _guard = crate::auth::lock_slim_auth_env();
        env::set_var("SHADI_SLIM_AUTH", "did");
        env::set_var("SLIM_HUMAN_SEED", "human");
        env::remove_var("SLIM_MEMBER_DIDS");

        // Open: not an allow-list flow, whatever else is configured.
        env::set_var("SHADI_SLIM_ADMISSION", "OPEN");
        match did_auth_from_env("avatar") {
            Some(Err(IdentityError::Config(msg))) => assert_eq!(
                msg,
                "SHADI_SLIM_ADMISSION=open has no member allow-list; this flow does not \
                 support open admission"
            ),
            _ => panic!("open admission must be Some(Err(Config))"),
        }
        match require_did_auth_from_env("avatar") {
            Err(IdentityError::Config(msg)) => {
                assert!(msg.contains("does not support open admission"), "{msg}")
            }
            _ => panic!("open admission must be a config error"),
        }

        // Open + SLIM_MEMBER_DIDS: the conflict, not a fallback to the list.
        let member = AgentIdentity::derive(b"human", "avatar").unwrap().did();
        env::set_var("SLIM_MEMBER_DIDS", &member);
        for r in [
            did_auth_from_env("avatar").expect("did mode"),
            require_did_auth_from_env("avatar"),
        ] {
            match r {
                Err(IdentityError::Config(msg)) => assert!(msg.contains("contradict"), "{msg}"),
                _ => panic!("conflict must be a config error"),
            }
        }

        // A bad value surfaces the same way, even with a valid allow-list.
        env::set_var("SHADI_SLIM_ADMISSION", "opne");
        for r in [
            did_auth_from_env("avatar").expect("did mode"),
            require_did_auth_from_env("avatar"),
        ] {
            match r {
                Err(IdentityError::Config(msg)) => {
                    assert!(msg.contains("SHADI_SLIM_ADMISSION must be"), "{msg}")
                }
                _ => panic!("a bad value must be a config error"),
            }
        }

        // Closed (unset or blank) is unchanged: the allow-list builds.
        for closed in [None, Some(""), Some("  ")] {
            match closed {
                Some(v) => env::set_var("SHADI_SLIM_ADMISSION", v),
                None => env::remove_var("SHADI_SLIM_ADMISSION"),
            }
            let auth = require_did_auth_from_env("avatar").expect("closed");
            assert_eq!(jwks_kids(&auth), vec![member.clone()]);
            assert!(matches!(
                did_auth_from_env("avatar"),
                Some(Ok(SlimAuth::Did { .. }))
            ));
        }
        // Closed without SLIM_MEMBER_DIDS: required, as on main.
        env::remove_var("SLIM_MEMBER_DIDS");
        match require_did_auth_from_env("avatar") {
            Err(IdentityError::Config(msg)) => {
                assert_eq!(msg, "SHADI_SLIM_AUTH=did requires SLIM_MEMBER_DIDS")
            }
            _ => panic!("closed needs SLIM_MEMBER_DIDS"),
        }

        // Outside DID mode the admission switch is not consulted.
        env::set_var("SHADI_SLIM_ADMISSION", "opne");
        env::set_var("SHADI_SLIM_AUTH", "shared-secret");
        assert!(did_auth_from_env("avatar").is_none());

        env::remove_var("SHADI_SLIM_ADMISSION");
        env::remove_var("SHADI_SLIM_AUTH");
        env::remove_var("SLIM_HUMAN_SEED");
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
