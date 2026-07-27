use std::collections::BTreeMap;
use std::path::Path;

use agent_secrets::{AgentVerifier, SecretError, SecretResult, SessionContext};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct MasConfig {
    pub mas: Option<MasSettings>,
    #[serde(default)]
    pub groups: BTreeMap<String, GroupConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MasSettings {
    pub default_group: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupConfig {
    pub moderator_did: Option<String>,
    #[serde(default)]
    pub members: Vec<MemberConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberConfig {
    pub did: String,
    pub role: Option<String>,
}

impl MasConfig {
    pub fn default_group(&self) -> Option<&str> {
        self.mas.as_ref()?.default_group.as_deref()
    }

    pub fn group(&self, name: &str) -> Option<&GroupConfig> {
        self.groups.get(name)
    }
}

pub fn load_config(path: &Path) -> Result<MasConfig, String> {
    let data = std::fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {}", path.display(), err))?;
    toml::from_str(&data).map_err(|err| format!("invalid config {}: {}", path.display(), err))
}

/// Serialize `config` to TOML, in [`load_config`]'s format — the write-side
/// counterpart used to persist a dynamically-resolved [`GroupConfig`] (e.g.
/// from Agent Directory discovery) so `shadictl slim-mas list-members`/
/// `validate` can audit it like any hand-written `mas.toml`.
pub fn to_toml_string(config: &MasConfig) -> Result<String, String> {
    toml::to_string_pretty(config).map_err(|err| format!("failed to serialize config: {}", err))
}

/// Write `config` as TOML to `path` (see [`to_toml_string`]).
pub fn save_config(config: &MasConfig, path: &Path) -> Result<(), String> {
    let data = to_toml_string(config)?;
    std::fs::write(path, data).map_err(|err| format!("failed to write {}: {}", path.display(), err))
}

pub fn resolve_group<'a>(config: &'a MasConfig, group: Option<&'a str>) -> Result<&'a str, String> {
    if let Some(group) = group {
        return Ok(group);
    }
    config
        .default_group()
        .ok_or_else(|| "group is required (no default_group set)".to_string())
}

pub fn is_member_allowed(group: &GroupConfig, did: &str, role: Option<&str>) -> bool {
    group.members.iter().any(|member| {
        if member.did != did {
            return false;
        }
        match (role, member.role.as_deref()) {
            (Some(expected), Some(actual)) => expected == actual,
            (Some(_), None) => false,
            (None, _) => true,
        }
    })
}

/// [`AgentVerifier`] that admits a session only when its DID is on a group's
/// allow-list ([`is_member_allowed`]). The DID is read from
/// [`SessionContext::did`]; a session with no DID, or a DID absent from the
/// group, is rejected.
///
/// This enforces the `slim_mas` membership policy at the application layer. The
/// DID is trusted-by-assertion here; later phases establish it cryptographically
/// from a DID-signed token before it reaches this check.
pub struct DidPolicyVerifier {
    group: GroupConfig,
}

impl DidPolicyVerifier {
    pub fn new(group: GroupConfig) -> Self {
        Self { group }
    }
}

impl AgentVerifier for DidPolicyVerifier {
    fn verify(&self, session: &SessionContext) -> SecretResult<()> {
        let did = session.did.as_deref().ok_or(SecretError::NotAuthorized)?;
        if is_member_allowed(&self.group, did, None) {
            Ok(())
        } else {
            Err(SecretError::NotAuthorized)
        }
    }
}

pub fn resolve_did_ref<F>(did_ref: &str, mut fetch: F) -> Result<String, String>
where
    F: FnMut(&str) -> Result<String, String>,
{
    let prefix = "shadi://";
    if let Some(key) = did_ref.strip_prefix(prefix) {
        if key.is_empty() {
            return Err("empty SHADI key in DID reference".to_string());
        }
        return fetch(key);
    }
    Ok(did_ref.to_string())
}

pub fn resolve_group_dids<F>(group: &GroupConfig, mut fetch: F) -> Result<GroupConfig, String>
where
    F: FnMut(&str) -> Result<String, String>,
{
    let moderator_did = match group.moderator_did.as_deref() {
        Some(did_ref) => Some(resolve_did_ref(did_ref, &mut fetch)?),
        None => None,
    };
    let mut members = Vec::with_capacity(group.members.len());
    for member in &group.members {
        let resolved = resolve_did_ref(&member.did, &mut fetch)?;
        members.push(MemberConfig {
            did: resolved,
            role: member.role.clone(),
        });
    }
    Ok(GroupConfig {
        moderator_did,
        members,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_config(contents: &str) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().expect("tempfile");
        std::fs::write(file.path(), contents).expect("write config");
        file
    }

    #[test]
    fn to_toml_string_round_trips_through_load_config() {
        let mut groups = BTreeMap::new();
        groups.insert(
            "discovered-room".to_string(),
            GroupConfig {
                moderator_did: Some("did:key:moderator".to_string()),
                members: vec![
                    MemberConfig { did: "did:key:a".to_string(), role: None },
                    MemberConfig { did: "did:key:b".to_string(), role: Some("agent".to_string()) },
                ],
            },
        );
        let config = MasConfig {
            mas: Some(MasSettings { default_group: Some("discovered-room".to_string()) }),
            groups,
        };

        let toml_text = to_toml_string(&config).expect("serialize");
        let file = write_config(&toml_text);
        let reloaded = load_config(file.path()).expect("reload");

        assert_eq!(reloaded.default_group(), Some("discovered-room"));
        let group = reloaded.group("discovered-room").expect("group");
        assert_eq!(group.moderator_did.as_deref(), Some("did:key:moderator"));
        assert_eq!(group.members.len(), 2);
        assert_eq!(group.members[1].role.as_deref(), Some("agent"));
    }

    #[test]
    fn save_config_writes_a_file_load_config_can_read_back() {
        let mut groups = BTreeMap::new();
        groups.insert(
            "room".to_string(),
            GroupConfig { moderator_did: None, members: vec![] },
        );
        let config = MasConfig { mas: None, groups };

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("mas.toml");
        save_config(&config, &path).expect("save");

        let reloaded = load_config(&path).expect("load");
        assert!(reloaded.group("room").is_some());
    }

    #[test]
    fn load_config_parses_groups_and_default() {
        let contents = r#"
[mas]
default_group = "team-a"

[groups.team-a]
moderator_did = "did:key:moderator"
members = [
  { did = "did:key:human", role = "human" },
  { did = "did:key:agent", role = "agent" }
]
"#;
        let file = write_config(contents);
        let config = load_config(file.path()).expect("load");
        assert_eq!(config.default_group(), Some("team-a"));
        let group = config.group("team-a").expect("group");
        assert_eq!(group.moderator_did.as_deref(), Some("did:key:moderator"));
        assert_eq!(group.members.len(), 2);
    }

    #[test]
    fn resolve_group_prefers_argument() {
        let config = MasConfig {
            mas: Some(MasSettings {
                default_group: Some("team-a".to_string()),
            }),
            groups: BTreeMap::new(),
        };
        let group = resolve_group(&config, Some("team-b")).expect("group");
        assert_eq!(group, "team-b");
    }

    #[test]
    fn resolve_group_uses_default() {
        let config = MasConfig {
            mas: Some(MasSettings {
                default_group: Some("team-a".to_string()),
            }),
            groups: BTreeMap::new(),
        };
        let group = resolve_group(&config, None).expect("group");
        assert_eq!(group, "team-a");
    }

    #[test]
    fn resolve_group_errors_without_default() {
        let config = MasConfig {
            mas: None,
            groups: BTreeMap::new(),
        };
        let err = resolve_group(&config, None).unwrap_err();
        assert!(err.contains("group is required"));
    }

    #[test]
    fn is_member_allowed_matches_role_when_required() {
        let group = GroupConfig {
            moderator_did: None,
            members: vec![MemberConfig {
                did: "did:key:human".to_string(),
                role: Some("human".to_string()),
            }],
        };
        assert!(is_member_allowed(&group, "did:key:human", Some("human")));
        assert!(!is_member_allowed(&group, "did:key:human", Some("agent")));
    }

    #[test]
    fn is_member_allowed_accepts_when_role_not_required() {
        let group = GroupConfig {
            moderator_did: None,
            members: vec![MemberConfig {
                did: "did:key:agent".to_string(),
                role: None,
            }],
        };
        assert!(is_member_allowed(&group, "did:key:agent", None));
        assert!(!is_member_allowed(&group, "did:key:agent", Some("agent")));
    }

    #[test]
    fn is_member_allowed_rejects_unknown_did() {
        let group = GroupConfig {
            moderator_did: None,
            members: vec![MemberConfig {
                did: "did:key:human".to_string(),
                role: Some("human".to_string()),
            }],
        };
        assert!(!is_member_allowed(&group, "did:key:unknown", None));
    }

    #[test]
    fn resolve_did_ref_returns_literal() {
        let did = resolve_did_ref("did:key:abc", |_| Ok("x".to_string())).expect("did");
        assert_eq!(did, "did:key:abc");
    }

    #[test]
    fn resolve_did_ref_fetches_shadi_key() {
        let did = resolve_did_ref("shadi://github/user/did", |key| Ok(format!("did:{}", key)))
            .expect("did");
        assert_eq!(did, "did:github/user/did");
    }

    #[test]
    fn resolve_did_ref_rejects_empty_key() {
        let err = resolve_did_ref("shadi://", |_| Ok("did".to_string())).unwrap_err();
        assert!(err.contains("empty SHADI key"));
    }

    #[test]
    fn resolve_group_dids_resolves_members() {
        let group = GroupConfig {
            moderator_did: Some("shadi://mod".to_string()),
            members: vec![MemberConfig {
                did: "shadi://member".to_string(),
                role: Some("human".to_string()),
            }],
        };
        let resolved = resolve_group_dids(&group, |key| Ok(format!("did:{}", key))).expect("group");
        assert_eq!(resolved.moderator_did.as_deref(), Some("did:mod"));
        assert_eq!(resolved.members[0].did, "did:member");
    }

    fn single_member_group(did: &str) -> GroupConfig {
        GroupConfig {
            moderator_did: None,
            members: vec![MemberConfig {
                did: did.to_string(),
                role: None,
            }],
        }
    }

    #[test]
    fn did_policy_verifier_admits_allowed_did() {
        let verifier = DidPolicyVerifier::new(single_member_group("did:key:agent"));
        let session = SessionContext::new("agent", "s1").with_did("did:key:agent");
        assert!(verifier.verify(&session).is_ok());
    }

    #[test]
    fn did_policy_verifier_rejects_unknown_did() {
        let verifier = DidPolicyVerifier::new(single_member_group("did:key:agent"));
        let session = SessionContext::new("x", "s1").with_did("did:key:intruder");
        assert!(matches!(
            verifier.verify(&session),
            Err(SecretError::NotAuthorized)
        ));
    }

    #[test]
    fn did_policy_verifier_rejects_session_without_did() {
        let verifier = DidPolicyVerifier::new(single_member_group("did:key:agent"));
        let session = SessionContext::new("x", "s1"); // no DID established
        assert!(matches!(
            verifier.verify(&session),
            Err(SecretError::NotAuthorized)
        ));
    }
}
