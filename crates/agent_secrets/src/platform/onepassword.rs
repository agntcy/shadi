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
        Self { vault, account }
    }

    fn make_cmd(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new("op");
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
        let detail: OpItemDetail = serde_json::from_str(&output).map_err(|e| {
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

    fn delete(&self, key: &str) -> SecretResult<()> {
        let cmd = self.make_cmd(&["item", "delete", key]);
        self.run_cmd(cmd)?;
        Ok(())
    }

    fn list_keys(&self) -> SecretResult<Vec<String>> {
        let cmd = self.make_cmd(&["item", "list", "--tags", SHADI_TAG, "--format", "json"]);
        let output = self.run_cmd(cmd)?;
        if output.trim().is_empty() {
            return Ok(Vec::new());
        }
        let items: Vec<OpItem> = serde_json::from_str(&output).map_err(|e| {
            eprintln!("failed to parse op item list JSON: {}", e);
            SecretError::StorageFailure
        })?;
        Ok(items.into_iter().map(|item| item.title).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
