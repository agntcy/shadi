// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::io::Read;
use std::process::{Command, Stdio};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::Deserialize;

use crate::memory::SecretBytes;
use crate::policy::SecretPolicy;
use crate::{SecretError, SecretResult, SecretStore};

const SHADI_TAG: &str = "shadi";

pub struct OnePasswordStore {
    vault: String,
    account: Option<String>,
    op_binary: String,
}

#[derive(Deserialize)]
struct OpItem {
    #[allow(dead_code)]
    id: String,
    title: String,
}

#[derive(Deserialize)]
struct OpFieldEntry {
    id: String,
    value: Option<String>,
}

#[derive(Deserialize)]
struct OpItemDetail {
    fields: Option<Vec<OpFieldEntry>>,
}

impl OnePasswordStore {
    pub fn new(vault: Option<String>, account: Option<String>) -> Self {
        let vault = vault
            .or_else(|| env::var("SHADI_OP_VAULT").ok())
            .unwrap_or_else(|| "shadi".to_string());
        let account = account.or_else(|| env::var("SHADI_OP_ACCOUNT").ok());
        let op_binary = env::var("SHADI_OP_BINARY").unwrap_or_else(|_| "op".to_string());
        Self {
            vault,
            account,
            op_binary,
        }
    }

    fn make_cmd(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(&self.op_binary);
        cmd.args(args);
        cmd.arg("--vault");
        cmd.arg(&self.vault);
        if let Some(account) = &self.account {
            cmd.arg("--account");
            cmd.arg(account);
        }
        cmd
    }

    fn run_cmd(&self, mut cmd: Command) -> Result<String, SecretError> {
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        let mut child = cmd.spawn().map_err(|e| {
            eprintln!("failed to spawn `op`: {}", e);
            SecretError::NotSupported
        })?;
        let mut stdout = String::new();
        child
            .stdout
            .as_mut()
            .unwrap()
            .read_to_string(&mut stdout)
            .map_err(|e| {
                eprintln!("failed to read `op` stdout: {}", e);
                SecretError::StorageFailure
            })?;
        let mut stderr = String::new();
        child
            .stderr
            .as_mut()
            .unwrap()
            .read_to_string(&mut stderr)
            .map_err(|e| {
                eprintln!("failed to read `op` stderr: {}", e);
                SecretError::StorageFailure
            })?;
        let status = child.wait().map_err(|e| {
            eprintln!("failed to wait for `op`: {}", e);
            SecretError::StorageFailure
        })?;
        if !status.success() {
            return Err(classify_op_error(&stderr));
        }
        Ok(stdout)
    }

    fn item_exists(&self, key: &str) -> Result<bool, SecretError> {
        let cmd = self.make_cmd(&["item", "get", key, "--format", "json"]);
        match self.run_cmd(cmd) {
            Ok(_) => Ok(true),
            Err(SecretError::InvalidInput) => Ok(false),
            Err(e) => Err(e),
        }
    }
}

fn classify_op_error(stderr: &str) -> SecretError {
    let lower = stderr.to_lowercase();
    if lower.contains("not found")
        || lower.contains("no item found")
        || lower.contains("isn't an item")
    {
        SecretError::InvalidInput
    } else if lower.contains("not currently signed in")
        || lower.contains("authentication required")
        || lower.contains("unauthorized")
        || lower.contains("session expired")
    {
        SecretError::NotAuthorized
    } else {
        eprintln!("op error: {}", stderr.trim());
        SecretError::StorageFailure
    }
}

fn decode_item_secret(output: &str) -> SecretResult<SecretBytes> {
    let detail: OpItemDetail = serde_json::from_str(output).map_err(|e| {
        eprintln!("failed to parse op item get JSON: {}", e);
        SecretError::StorageFailure
    })?;
    let fields = detail.fields.unwrap_or_default();
    let notes_field = fields
        .iter()
        .find(|f| f.id == "notesPlain")
        .and_then(|f| f.value.as_deref())
        .ok_or(SecretError::InvalidInput)?;
    let decoded = BASE64.decode(notes_field).map_err(|e| {
        eprintln!("failed to decode base64 from 1Password item: {}", e);
        SecretError::StorageFailure
    })?;
    Ok(SecretBytes::new(decoded))
}

fn parse_item_titles(output: &str) -> SecretResult<Vec<String>> {
    if output.trim().is_empty() {
        return Ok(Vec::new());
    }
    let items: Vec<OpItem> = serde_json::from_str(output).map_err(|e| {
        eprintln!("failed to parse op item list JSON: {}", e);
        SecretError::StorageFailure
    })?;
    Ok(items.into_iter().map(|item| item.title).collect())
}

impl SecretStore for OnePasswordStore {
    fn put(&self, key: &str, secret: &[u8], _policy: SecretPolicy) -> SecretResult<()> {
        let encoded = BASE64.encode(secret);
        if self.item_exists(key)? {
            let field_arg = format!("notesPlain={}", encoded);
            let cmd = self.make_cmd(&["item", "edit", key, &field_arg]);
            self.run_cmd(cmd)?;
        } else {
            let field_arg = format!("notesPlain={}", encoded);
            let cmd = self.make_cmd(&[
                "item",
                "create",
                "--category",
                "Secure Note",
                "--title",
                key,
                "--tags",
                SHADI_TAG,
                &field_arg,
            ]);
            self.run_cmd(cmd)?;
        }
        Ok(())
    }

    fn get(&self, key: &str) -> SecretResult<SecretBytes> {
        let cmd = self.make_cmd(&["item", "get", key, "--format", "json"]);
        let output = self.run_cmd(cmd)?;
        decode_item_secret(&output)
    }

    fn delete(&self, key: &str) -> SecretResult<()> {
        let cmd = self.make_cmd(&["item", "delete", key]);
        self.run_cmd(cmd)?;
        Ok(())
    }

    fn list_keys(&self) -> SecretResult<Vec<String>> {
        let cmd = self.make_cmd(&["item", "list", "--tags", SHADI_TAG, "--format", "json"]);
        let output = self.run_cmd(cmd)?;
        parse_item_titles(&output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn classify_not_found_error() {
        assert!(matches!(
            classify_op_error("item not found"),
            SecretError::InvalidInput
        ));
        assert!(matches!(
            classify_op_error("[ERROR] \"example\" isn't an item"),
            SecretError::InvalidInput
        ));
    }

    #[test]
    fn classify_auth_error() {
        assert!(matches!(
            classify_op_error("not currently signed in"),
            SecretError::NotAuthorized
        ));
        assert!(matches!(
            classify_op_error("session expired"),
            SecretError::NotAuthorized
        ));
    }

    #[test]
    fn classify_unknown_error() {
        assert!(matches!(
            classify_op_error("something unexpected"),
            SecretError::StorageFailure
        ));
    }

    #[test]
    fn parse_item_list_json() {
        let json = r#"[{"id":"abc123","title":"secops/github_token"},{"id":"def456","title":"secops/llm/key"}]"#;
        let items: Vec<OpItem> = serde_json::from_str(json).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].title, "secops/github_token");
        assert_eq!(items[1].title, "secops/llm/key");
    }

    #[test]
    fn parse_item_detail_json() {
        let json = r#"{"id":"abc123","title":"test","fields":[{"id":"notesPlain","value":"aGVsbG8="},{"id":"other","value":"x"}]}"#;
        let detail: OpItemDetail = serde_json::from_str(json).unwrap();
        let fields = detail.fields.unwrap();
        let notes = fields.iter().find(|f| f.id == "notesPlain").unwrap();
        let decoded = BASE64.decode(notes.value.as_deref().unwrap()).unwrap();
        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn parse_empty_item_list() {
        let json = "[]";
        let items: Vec<OpItem> = serde_json::from_str(json).unwrap();
        assert!(items.is_empty());
    }

    #[test]
    fn default_vault_name() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let store = OnePasswordStore::new(None, None);
        assert!(!store.vault.is_empty());
    }

    #[test]
    fn explicit_vault_name() {
        let store = OnePasswordStore::new(Some("my-vault".to_string()), None);
        assert_eq!(store.vault, "my-vault");
    }

    #[test]
    fn explicit_account() {
        let store = OnePasswordStore::new(None, Some("my-account".to_string()));
        assert_eq!(store.account.as_deref(), Some("my-account"));
    }

    #[test]
    fn make_cmd_includes_vault_and_account_flags() {
        let store = OnePasswordStore::new(
            Some("test-vault".to_string()),
            Some("test-account".to_string()),
        );
        let cmd = store.make_cmd(&["item", "list"]);
        let args = cmd
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        assert_eq!(args, vec!["item", "list", "--vault", "test-vault", "--account", "test-account"]);
    }

    #[test]
    fn make_cmd_omits_account_when_unset() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let prior_account = std::env::var("SHADI_OP_ACCOUNT").ok();
        std::env::remove_var("SHADI_OP_ACCOUNT");

        let store = OnePasswordStore::new(Some("test-vault".to_string()), None);
        let cmd = store.make_cmd(&["item", "list"]);
        let args = cmd
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        assert_eq!(args, vec!["item", "list", "--vault", "test-vault"]);

        if let Some(account) = prior_account {
            std::env::set_var("SHADI_OP_ACCOUNT", account);
        }
    }

    #[test]
    fn make_cmd_restore_branch_executes_when_prior_account_exists() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        std::env::set_var("SHADI_OP_ACCOUNT", "restore-me");

        let prior_account = std::env::var("SHADI_OP_ACCOUNT").ok();
        std::env::remove_var("SHADI_OP_ACCOUNT");

        let store = OnePasswordStore::new(Some("test-vault".to_string()), None);
        let cmd = store.make_cmd(&["item", "list"]);
        let args = cmd
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        assert_eq!(args, vec!["item", "list", "--vault", "test-vault"]);

        if let Some(account) = prior_account {
            std::env::set_var("SHADI_OP_ACCOUNT", account);
        }
        std::env::remove_var("SHADI_OP_ACCOUNT");
    }

    #[test]
    fn runtime_methods_fail_cleanly_with_missing_binary() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        std::env::set_var("SHADI_OP_BINARY", "__shadi_missing_op_binary__");
        let store = OnePasswordStore::new(Some("test-vault".to_string()), None);
        std::env::remove_var("SHADI_OP_BINARY");

        assert!(matches!(store.list_keys(), Err(SecretError::NotSupported)));
        assert!(matches!(store.get("test-key"), Err(SecretError::NotSupported)));
        assert!(matches!(store.delete("test-key"), Err(SecretError::NotSupported)));
        assert!(matches!(
            store.put("test-key", b"value", SecretPolicy::default()),
            Err(SecretError::NotSupported)
        ));
    }

    #[test]
    fn decode_item_secret_success() {
        let secret = decode_item_secret(
            r#"{"fields":[{"id":"notesPlain","value":"aGVsbG8="}]}"#,
        )
        .expect("decode");
        assert_eq!(secret.expose(|bytes| bytes.to_vec()), b"hello".to_vec());
    }

    #[test]
    fn decode_item_secret_rejects_invalid_json() {
        assert!(matches!(
            decode_item_secret("not-json"),
            Err(SecretError::StorageFailure)
        ));
    }

    #[test]
    fn decode_item_secret_requires_notes_field() {
        assert!(matches!(
            decode_item_secret(r#"{"fields":[{"id":"other","value":"aGVsbG8="}]}"#),
            Err(SecretError::InvalidInput)
        ));
    }

    #[test]
    fn decode_item_secret_rejects_invalid_base64() {
        assert!(matches!(
            decode_item_secret(r#"{"fields":[{"id":"notesPlain","value":"%%%"}]}"#),
            Err(SecretError::StorageFailure)
        ));
    }

    #[test]
    fn parse_item_titles_handles_empty_and_json() {
        assert_eq!(parse_item_titles("   ").expect("empty"), Vec::<String>::new());
        assert_eq!(
            parse_item_titles(r#"[{"id":"1","title":"a"},{"id":"2","title":"b"}]"#)
                .expect("titles"),
            vec!["a".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn parse_item_titles_rejects_invalid_json() {
        assert!(matches!(
            parse_item_titles("{oops"),
            Err(SecretError::StorageFailure)
        ));
    }
}
