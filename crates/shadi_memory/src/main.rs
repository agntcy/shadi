// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use shadi_memory::{MemoryEntry, SqlCipherStore};

#[cfg(test)]
use std::collections::HashMap;
#[cfg(test)]
use std::sync::{Mutex, OnceLock};

#[derive(Parser, Debug)]
#[command(name = "shadi-memory")]
#[command(about = "Encrypted local memory store using SQLCipher")]
struct Cli {
    #[arg(long, env = "SHADI_MEMORY_DB", value_name = "PATH")]
    db: PathBuf,

    #[arg(long, env = "SHADI_MEMORY_KEY")]
    key: Option<String>,

    #[arg(long = "key-name", env = "SHADI_MEMORY_KEY_NAME", default_value = "shadi/memory/sqlcipher_key")]
    key_name: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Init,
    Put {
        #[arg(long)]
        scope: String,
        #[arg(long = "entry-key")]
        entry_key: String,
        #[arg(long)]
        payload: Option<String>,
        #[arg(long = "payload-file")]
        payload_file: Option<PathBuf>,
    },
    Get {
        #[arg(long)]
        scope: String,
        #[arg(long = "entry-key")]
        entry_key: String,
    },
    Search {
        #[arg(long)]
        scope: Option<String>,
        #[arg(long)]
        query: String,
        #[arg(long, default_value = "10")]
        limit: usize,
    },
    List {
        #[arg(long)]
        scope: Option<String>,
        #[arg(long, default_value = "50")]
        limit: usize,
    },
    Delete {
        #[arg(long)]
        scope: String,
        #[arg(long = "entry-key")]
        entry_key: String,
    },
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

    fn get(&self, key: &str) -> agent_secrets::SecretResult<agent_secrets::memory::SecretBytes> {
        let guard = test_secret_store_map()
            .lock()
            .map_err(|_| agent_secrets::SecretError::StorageFailure)?;
        let value = guard
            .get(key)
            .ok_or(agent_secrets::SecretError::InvalidInput)?
            .clone();
        Ok(agent_secrets::memory::SecretBytes::new(value))
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

fn main() -> Result<(), String> {
    let cli = Cli::parse();
    let key = resolve_key(&cli)?;
    let store = SqlCipherStore::open(&cli.db, &key).map_err(|err| err.to_string())?;
    let output = handle_command(&cli, &store)?;
    println!("{}", output);
    Ok(())
}

fn handle_command(cli: &Cli, store: &SqlCipherStore) -> Result<String, String> {
    match &cli.command {
        Command::Init => Ok("ok".to_string()),
        Command::Put {
            scope,
            entry_key,
            payload,
            payload_file,
        } => {
            let payload = read_payload(payload.clone(), payload_file.clone())?;
            let id = store
                .put(scope, entry_key, &payload)
                .map_err(|err| err.to_string())?;
            Ok(serde_json::json!({"status": "saved", "id": id}).to_string())
        }
        Command::Get { scope, entry_key } => {
            let entry = store
                .get_latest(scope, entry_key)
                .map_err(|err| err.to_string())?;
            match entry {
                Some(entry) => serde_json::to_string_pretty(&entry).map_err(|err| err.to_string()),
                None => Ok(serde_json::json!({"found": false}).to_string()),
            }
        }
        Command::Search {
            scope,
            query,
            limit,
        } => {
            let entries = store
                .search(scope.as_deref(), query, *limit)
                .map_err(|err| err.to_string())?;
            format_entries(entries)
        }
        Command::List { scope, limit } => {
            let entries = store
                .list(scope.as_deref(), *limit)
                .map_err(|err| err.to_string())?;
            format_entries(entries)
        }
        Command::Delete { scope, entry_key } => {
            let affected = store
                .delete(scope, entry_key)
                .map_err(|err| err.to_string())?;
            Ok(serde_json::json!({"deleted": affected}).to_string())
        }
    }
}

fn resolve_key(cli: &Cli) -> Result<String, String> {
    if let Some(key) = cli.key.as_ref() {
        if key.is_empty() {
            return Err("SHADI_MEMORY_KEY is empty".to_string());
        }
        return Ok(key.to_string());
    }

    let store = default_secret_store();
    let secret = store
        .get(&cli.key_name)
        .map_err(|_| format!("missing SHADI key: {}", cli.key_name))?;
    let raw = secret.expose(|bytes| bytes.to_vec());
    String::from_utf8(raw).map_err(|_| "SHADI memory key is not utf-8".to_string())
}

fn read_payload(payload: Option<String>, payload_file: Option<PathBuf>) -> Result<String, String> {
    match (payload, payload_file) {
        (Some(text), None) => Ok(text),
        (None, Some(path)) => std::fs::read_to_string(&path)
            .map_err(|err| format!("failed to read payload file: {}", err)),
        (None, None) => Err("payload or payload-file must be provided".to_string()),
        (Some(_), Some(_)) => Err("use either payload or payload-file".to_string()),
    }
}

fn format_entries(entries: Vec<MemoryEntry>) -> Result<String, String> {
    serde_json::to_string_pretty(&entries).map_err(|err| err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use agent_secrets::SecretPolicy;

    fn unique_key(prefix: &str) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_nanos();
        format!("{}-{}-{}", prefix, std::process::id(), nanos)
    }

    fn temp_store() -> SqlCipherStore {
        let file = NamedTempFile::new().expect("tempfile");
        let path = file.path().to_path_buf();
        std::mem::forget(file);
        SqlCipherStore::open(&path, "test-key").expect("open store")
    }

    fn tmp_dir() -> PathBuf {
        PathBuf::from(std::env::var("SHADI_TMP_DIR").unwrap_or_else(|_| "./.tmp".to_string()))
    }

    #[test]
    fn resolve_key_prefers_cli_key() {
        let cli = Cli {
            db: tmp_dir().join("test.db"),
            key: Some("secret".to_string()),
            key_name: "unused".to_string(),
            command: Command::Init,
        };

        let key = resolve_key(&cli).expect("resolve");
        assert_eq!(key, "secret");
    }

    #[test]
    fn resolve_key_rejects_empty_string() {
        let cli = Cli {
            db: tmp_dir().join("test.db"),
            key: Some("".to_string()),
            key_name: "unused".to_string(),
            command: Command::Init,
        };

        let err = resolve_key(&cli).unwrap_err();
        assert!(err.contains("SHADI_MEMORY_KEY is empty"));
    }

    #[test]
    fn resolve_key_reads_from_secret_store() {
        let key_name = unique_key("shadi/memory/key");
        test_store_put(&key_name, b"memory-secret");

        let cli = Cli {
            db: tmp_dir().join("test.db"),
            key: None,
            key_name: key_name.clone(),
            command: Command::Init,
        };

        let key = resolve_key(&cli).expect("resolve");
        assert_eq!(key, "memory-secret");
    }

    #[test]
    fn resolve_key_errors_when_missing_secret() {
        let key_name = unique_key("shadi/memory/missing");
        let cli = Cli {
            db: tmp_dir().join("test.db"),
            key: None,
            key_name,
            command: Command::Init,
        };

        let err = resolve_key(&cli).unwrap_err();
        assert!(err.contains("missing SHADI key"));
    }

    #[test]
    fn resolve_key_errors_on_non_utf8_secret() {
        let key_name = unique_key("shadi/memory/bad");
        test_store_put(&key_name, &[0xff, 0xfe, 0xfd]);

        let cli = Cli {
            db: tmp_dir().join("test.db"),
            key: None,
            key_name,
            command: Command::Init,
        };

        let err = resolve_key(&cli).unwrap_err();
        assert!(err.contains("not utf-8"));
    }

    #[test]
    fn test_secret_store_roundtrip() {
        let store = default_secret_store();
        let key = unique_key("shadi/memory/store");

        store
            .put(&key, b"value", SecretPolicy::default())
            .expect("put");

        let keys = store.list_keys().expect("list");
        assert!(keys.iter().any(|item| item == &key));

        store.delete(&key).expect("delete");
    }

    #[test]
    fn read_payload_from_file() {
        let file = NamedTempFile::new().expect("tempfile");
        std::fs::write(file.path(), "payload").expect("write");
        let payload = read_payload(None, Some(file.path().to_path_buf())).expect("read");
        assert_eq!(payload, "payload");
    }

    #[test]
    fn read_payload_errors_on_missing_inputs() {
        let err = read_payload(None, None).unwrap_err();
        assert!(err.contains("payload or payload-file"));
    }

    #[test]
    fn read_payload_errors_when_both_inputs_provided() {
        let err = read_payload(Some("one".to_string()), Some(tmp_dir())).unwrap_err();
        assert!(err.contains("either payload or payload-file"));
    }

    #[test]
    fn read_payload_errors_when_file_missing() {
        let err = read_payload(None, Some(tmp_dir().join("does-not-exist"))).unwrap_err();
        assert!(err.contains("failed to read payload file"));
    }

    #[test]
    fn handle_command_put_get_delete_roundtrip() {
        let store = temp_store();
        let cli = Cli {
            db: tmp_dir().join("test.db"),
            key: Some("secret".to_string()),
            key_name: "unused".to_string(),
            command: Command::Put {
                scope: "secops".to_string(),
                entry_key: "report".to_string(),
                payload: Some("payload".to_string()),
                payload_file: None,
            },
        };

        let output = handle_command(&cli, &store).expect("put");
        assert!(output.contains("saved"));

        let get_cli = Cli {
            command: Command::Get {
                scope: "secops".to_string(),
                entry_key: "report".to_string(),
            },
            ..cli
        };
        let output = handle_command(&get_cli, &store).expect("get");
        assert!(output.contains("payload"));

        let del_cli = Cli {
            command: Command::Delete {
                scope: "secops".to_string(),
                entry_key: "report".to_string(),
            },
            ..get_cli
        };
        let output = handle_command(&del_cli, &store).expect("delete");
        assert!(output.contains("deleted"));
    }

    #[test]
    fn handle_command_init_returns_ok() {
        let store = temp_store();
        let cli = Cli {
            db: tmp_dir().join("test.db"),
            key: Some("secret".to_string()),
            key_name: "unused".to_string(),
            command: Command::Init,
        };
        let output = handle_command(&cli, &store).expect("init");
        assert_eq!(output, "ok");
    }

    #[test]
    fn handle_command_get_missing_returns_false() {
        let store = temp_store();
        let cli = Cli {
            db: tmp_dir().join("test.db"),
            key: Some("secret".to_string()),
            key_name: "unused".to_string(),
            command: Command::Get {
                scope: "secops".to_string(),
                entry_key: "missing".to_string(),
            },
        };
        let output = handle_command(&cli, &store).expect("get");
        assert!(output.contains("\"found\":false"));
    }

    #[test]
    fn handle_command_list_and_search() {
        let store = temp_store();
        store
            .put("secops", "alert", "dependabot")
            .expect("put");

        let list_cli = Cli {
            db: tmp_dir().join("test.db"),
            key: Some("secret".to_string()),
            key_name: "unused".to_string(),
            command: Command::List {
                scope: Some("secops".to_string()),
                limit: 10,
            },
        };
        let output = handle_command(&list_cli, &store).expect("list");
        assert!(output.contains("dependabot"));

        let search_cli = Cli {
            command: Command::Search {
                scope: Some("secops".to_string()),
                query: "dependabot".to_string(),
                limit: 10,
            },
            ..list_cli
        };
        let output = handle_command(&search_cli, &store).expect("search");
        assert!(output.contains("dependabot"));
    }

    #[test]
    fn format_entries_serializes_json() {
        let entries = vec![MemoryEntry {
            id: 1,
            scope: "secops".to_string(),
            entry_key: "report".to_string(),
            payload: "ok".to_string(),
            created_at: "2026-02-14T00:00:00Z".to_string(),
        }];

        let output = format_entries(entries).expect("format");
        assert!(output.contains("\"secops\""));
        assert!(output.contains("\"report\""));
    }
}
