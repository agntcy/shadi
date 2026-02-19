use std::path::PathBuf;

#[cfg(test)]
use std::collections::HashMap;
#[cfg(test)]
use std::sync::{Mutex, OnceLock};

use clap::{Parser, Subcommand};

use slim_mas::{is_member_allowed, load_config, resolve_group, resolve_group_dids};

#[derive(Parser, Debug)]
#[command(name = "slim-mas", about = "SHADI SLIM Multi-Agent System moderator")]
struct Cli {
    #[arg(long = "config", value_name = "FILE", default_value = "mas.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Admit {
        #[arg(long = "group", value_name = "GROUP")]
        group: Option<String>,

        #[arg(long = "did", value_name = "DID")]
        did: String,

        #[arg(long = "role", value_name = "ROLE")]
        role: Option<String>,
    },
    ListGroups,
    ListMembers {
        #[arg(long = "group", value_name = "GROUP")]
        group: Option<String>,
    },
    Validate,
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("{}", err);
            std::process::ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<std::process::ExitCode, String> {
    let config = load_config(&cli.config)?;
    let store = default_secret_store();
    let mut fetch = |key: &str| {
        let secret = store.get(key).map_err(|_| format!("keychain lookup failed for {}", key))?;
        let value = secret.expose(|bytes| bytes.to_vec());
        String::from_utf8(value).map_err(|_| "secret is not utf-8".to_string())
    };

    match cli.command {
        Commands::Admit { group, did, role } => {
            let group_name = resolve_group(&config, group.as_deref())?;
            let group_config = config
                .group(group_name)
                .ok_or_else(|| format!("group '{}' not found", group_name))?;
            let group_config = resolve_group_dids(group_config, &mut fetch)?;
            let did = slim_mas::resolve_did_ref(&did, &mut fetch)?;

            if is_member_allowed(&group_config, &did, role.as_deref()) {
                println!("allow");
                Ok(std::process::ExitCode::from(0))
            } else {
                println!("deny");
                Ok(std::process::ExitCode::from(3))
            }
        }
        Commands::ListGroups => {
            for name in config.groups.keys() {
                println!("{}", name);
            }
            Ok(std::process::ExitCode::from(0))
        }
        Commands::ListMembers { group } => {
            let group_name = resolve_group(&config, group.as_deref())?;
            let group_config = config
                .group(group_name)
                .ok_or_else(|| format!("group '{}' not found", group_name))?;
            let group_config = resolve_group_dids(group_config, &mut fetch)?;
            for member in &group_config.members {
                match member.role.as_deref() {
                    Some(role) => println!("{} {}", member.did, role),
                    None => println!("{}", member.did),
                }
            }
            Ok(std::process::ExitCode::from(0))
        }
        Commands::Validate => {
            let _ = resolve_group(&config, None)?;
            Ok(std::process::ExitCode::from(0))
        }
    }
}

#[cfg(test)]
static TEST_SECRET_STORE: OnceLock<Mutex<HashMap<String, Vec<u8>>>> = OnceLock::new();

#[cfg(test)]
fn test_secret_store_map() -> &'static Mutex<HashMap<String, Vec<u8>>> {
    TEST_SECRET_STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(test)]
struct TestSecretStore;

#[cfg(test)]
impl agent_secrets::SecretStore for TestSecretStore {
    fn put(
        &self,
        key: &str,
        secret: &[u8],
        _policy: agent_secrets::SecretPolicy,
    ) -> agent_secrets::SecretResult<()> {
        let mut guard = test_secret_store_map()
            .lock()
            .map_err(|_| agent_secrets::SecretError::StorageFailure)?;
        guard.insert(key.to_string(), secret.to_vec());
        Ok(())
    }

    fn get(&self, key: &str) -> agent_secrets::SecretResult<agent_secrets::SecretBytes> {
        let guard = test_secret_store_map()
            .lock()
            .map_err(|_| agent_secrets::SecretError::StorageFailure)?;
        let value = guard
            .get(key)
            .ok_or(agent_secrets::SecretError::InvalidInput)?
            .clone();
        Ok(agent_secrets::SecretBytes::new(value))
    }

    fn delete(&self, key: &str) -> agent_secrets::SecretResult<()> {
        let mut guard = test_secret_store_map()
            .lock()
            .map_err(|_| agent_secrets::SecretError::StorageFailure)?;
        guard.remove(key);
        Ok(())
    }

    fn list_keys(&self) -> agent_secrets::SecretResult<Vec<String>> {
        let guard = test_secret_store_map()
            .lock()
            .map_err(|_| agent_secrets::SecretError::StorageFailure)?;
        Ok(guard.keys().cloned().collect())
    }
}

#[cfg(test)]
fn default_secret_store() -> Box<dyn agent_secrets::SecretStore> {
    Box::new(TestSecretStore)
}

#[cfg(not(test))]
fn default_secret_store() -> Box<dyn agent_secrets::SecretStore> {
    agent_secrets::default_store()
}

#[cfg(test)]
fn test_store_put(key: &str, value: &[u8]) {
    let mut guard = test_secret_store_map().lock().expect("test store lock");
    guard.insert(key.to_string(), value.to_vec());
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_secrets::{SecretBytes, SecretError, SecretResult, SecretStore};
    use std::collections::HashMap;
    use std::sync::Mutex;

    fn write_config(contents: &str) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().expect("tempfile");
        std::fs::write(file.path(), contents).expect("write config");
        file
    }

    fn sample_config() -> tempfile::NamedTempFile {
        write_config(
            r#"
[mas]
default_group = "team-a"

[groups.team-a]
moderator_did = "did:key:moderator"
members = [
  { did = "did:key:human", role = "human" },
  { did = "did:key:agent", role = "agent" }
]
"#,
        )
    }

    struct MemoryStore {
        entries: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl MemoryStore {
        fn new() -> Self {
            Self {
                entries: Mutex::new(HashMap::new()),
            }
        }
    }

    impl SecretStore for MemoryStore {
        fn put(&self, key: &str, secret: &[u8], _policy: agent_secrets::SecretPolicy) -> SecretResult<()> {
            let mut guard = self.entries.lock().map_err(|_| SecretError::StorageFailure)?;
            guard.insert(key.to_string(), secret.to_vec());
            Ok(())
        }

        fn get(&self, key: &str) -> SecretResult<SecretBytes> {
            let guard = self.entries.lock().map_err(|_| SecretError::StorageFailure)?;
            let value = guard.get(key).ok_or(SecretError::InvalidInput)?.clone();
            Ok(SecretBytes::new(value))
        }

        fn delete(&self, key: &str) -> SecretResult<()> {
            let mut guard = self.entries.lock().map_err(|_| SecretError::StorageFailure)?;
            guard.remove(key);
            Ok(())
        }

        fn list_keys(&self) -> SecretResult<Vec<String>> {
            let guard = self.entries.lock().map_err(|_| SecretError::StorageFailure)?;
            Ok(guard.keys().cloned().collect())
        }
    }

    fn sample_config_with_shadi_refs() -> tempfile::NamedTempFile {
        write_config(
            r#"
[mas]
default_group = "team-a"

[groups.team-a]
moderator_did = "shadi://mod"
members = [
  { did = "shadi://human", role = "human" }
]
"#,
        )
    }

    fn sample_config_with_shadi_refs_named(mod_key: &str, human_key: &str) -> tempfile::NamedTempFile {
        write_config(&format!(
            r#"
[mas]
default_group = "team-a"

[groups.team-a]
moderator_did = "shadi://{}"
members = [
  {{ did = "shadi://{}", role = "human" }}
]
"#,
            mod_key, human_key
        ))
    }

    fn unique_key(prefix: &str) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_nanos();
        format!("{}-{}-{}", prefix, std::process::id(), nanos)
    }

    #[test]
    fn run_lists_groups() {
        let file = sample_config();
        let cli = Cli {
            config: file.path().to_path_buf(),
            command: Commands::ListGroups,
        };
        let code = run(cli).expect("run");
        assert_eq!(code, std::process::ExitCode::from(0));
    }

    #[test]
    fn run_lists_members() {
        let file = sample_config();
        let cli = Cli {
            config: file.path().to_path_buf(),
            command: Commands::ListMembers {
                group: Some("team-a".to_string()),
            },
        };
        let code = run(cli).expect("run");
        assert_eq!(code, std::process::ExitCode::from(0));
    }

    #[test]
    fn run_admit_allows_member() {
        let file = sample_config();
        let cli = Cli {
            config: file.path().to_path_buf(),
            command: Commands::Admit {
                group: Some("team-a".to_string()),
                did: "did:key:human".to_string(),
                role: Some("human".to_string()),
            },
        };
        let code = run(cli).expect("run");
        assert_eq!(code, std::process::ExitCode::from(0));
    }

    #[test]
    fn run_admit_denies_member() {
        let file = sample_config();
        let cli = Cli {
            config: file.path().to_path_buf(),
            command: Commands::Admit {
                group: Some("team-a".to_string()),
                did: "did:key:human".to_string(),
                role: Some("agent".to_string()),
            },
        };
        let code = run(cli).expect("run");
        assert_eq!(code, std::process::ExitCode::from(3));
    }

    #[test]
    fn run_validate_rejects_missing_default_group() {
        let file = write_config(
            r#"
[groups.team-a]
members = [{ did = "did:key:human" }]
"#,
        );
        let cli = Cli {
            config: file.path().to_path_buf(),
            command: Commands::Validate,
        };
        let err = run(cli).unwrap_err();
        assert!(err.contains("default_group"));
    }

    #[test]
    fn run_admit_resolves_shadi_dids() {
        let file = sample_config_with_shadi_refs();
        let store = MemoryStore::new();
        store
            .put("human", b"did:key:human", agent_secrets::SecretPolicy::default())
            .expect("put");
        store
            .put("mod", b"did:key:mod", agent_secrets::SecretPolicy::default())
            .expect("put");

        let mut fetch = |key: &str| {
            let secret = store.get(key).map_err(|_| format!("keychain lookup failed for {}", key))?;
            let value = secret.expose(|bytes| bytes.to_vec());
            String::from_utf8(value).map_err(|_| "secret is not utf-8".to_string())
        };

        let config = load_config(file.path()).expect("load");
        let group_name = resolve_group(&config, None).expect("group");
        let group_config = resolve_group_dids(config.group(group_name).unwrap(), &mut fetch).expect("group");
        let did = slim_mas::resolve_did_ref("shadi://human", &mut fetch).expect("did");

        assert!(is_member_allowed(&group_config, &did, Some("human")));
    }

    #[test]
    fn run_admit_reports_unknown_group() {
        let file = sample_config();
        let cli = Cli {
            config: file.path().to_path_buf(),
            command: Commands::Admit {
                group: Some("missing".to_string()),
                did: "did:key:human".to_string(),
                role: Some("human".to_string()),
            },
        };

        let err = run(cli).unwrap_err();
        assert!(err.contains("group 'missing' not found"));
    }

    #[test]
    fn run_list_members_reports_unknown_group() {
        let file = sample_config();
        let cli = Cli {
            config: file.path().to_path_buf(),
            command: Commands::ListMembers {
                group: Some("missing".to_string()),
            },
        };

        let err = run(cli).unwrap_err();
        assert!(err.contains("group 'missing' not found"));
    }

    #[test]
    fn run_admit_resolves_shadi_dids_via_store() {
        let mod_key = unique_key("mod");
        let human_key = unique_key("human");
        let file = sample_config_with_shadi_refs_named(&mod_key, &human_key);

        test_store_put(&human_key, b"did:key:human");
        test_store_put(&mod_key, b"did:key:mod");

        let cli = Cli {
            config: file.path().to_path_buf(),
            command: Commands::Admit {
                group: None,
                did: format!("shadi://{}", human_key),
                role: Some("human".to_string()),
            },
        };

        let code = run(cli).expect("run");
        assert_eq!(code, std::process::ExitCode::from(0));
    }

    #[test]
    fn run_admit_rejects_non_utf8_secret() {
        let mod_key = unique_key("mod");
        let human_key = unique_key("human");
        let file = sample_config_with_shadi_refs_named(&mod_key, &human_key);

        test_store_put(&mod_key, b"did:key:mod");
        test_store_put(&human_key, &[0xff, 0xfe]);

        let cli = Cli {
            config: file.path().to_path_buf(),
            command: Commands::Admit {
                group: None,
                did: format!("shadi://{}", human_key),
                role: Some("human".to_string()),
            },
        };

        let err = run(cli).unwrap_err();
        assert!(err.contains("secret is not utf-8"));
    }

    #[test]
    fn run_lists_members_without_role() {
        let file = write_config(
            r#"
[mas]
default_group = "team-a"

[groups.team-a]
moderator_did = "did:key:moderator"
members = [
  { did = "did:key:human" }
]
"#,
        );
        let cli = Cli {
            config: file.path().to_path_buf(),
            command: Commands::ListMembers {
                group: Some("team-a".to_string()),
            },
        };

        let code = run(cli).expect("run");
        assert_eq!(code, std::process::ExitCode::from(0));
    }

    #[test]
    fn run_validate_ok_when_default_group_present() {
        let file = sample_config();
        let cli = Cli {
            config: file.path().to_path_buf(),
            command: Commands::Validate,
        };

        let code = run(cli).expect("run");
        assert_eq!(code, std::process::ExitCode::from(0));
    }

    #[test]
    fn test_secret_store_roundtrip() {
        let store = default_secret_store();
        let key = unique_key("slim-mas/store");
        store
            .put(&key, b"value", agent_secrets::SecretPolicy::default())
            .expect("put");
        let keys = store.list_keys().expect("list");
        assert!(keys.iter().any(|item| item == &key));
        store.delete(&key).expect("delete");
    }
}
