// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Verifiable credentials, in their own table beside `memory_entries`.
//!
//! VC-shaped columns in this crate rather than a second SQLCipher crate: only
//! one `links = "sqlite3"` crate may be linked, and the `rusqlite` pin here has
//! an external reason (SLIM), so a second opener would be a second place to
//! hold in lockstep. A separate *table* is what matters — `memory_entries` is
//! readable by `shadictl memory list`/`search` across all scopes, which would
//! defeat the vault's rule that claim values are never printed.

use rusqlite::{params, Row};
use serde::{Deserialize, Serialize};

use crate::{MemoryError, SqlCipherStore};

/// One stored credential. `raw` is the issued credential verbatim, disclosures
/// included; the other columns are lifted from it at import so queries never
/// re-parse it.
///
/// Nothing here names a credential format: `format` says how to read `raw`,
/// which is what lets a second format land without touching this table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRecord {
    pub id: String,
    pub agent_did: String,
    pub issuer: String,
    /// `vct` for SD-JWT VC, `doctype` for an mdoc — whatever the format calls
    /// the thing a query selects on.
    pub credential_type: String,
    /// How to read `raw`, e.g. `dc+sd-jwt`.
    pub format: String,
    pub raw: String,
    pub created_at: i64,
    /// `None` when the credential carries no expiry — treated as non-expiring.
    pub expires_at: Option<i64>,
}

pub(crate) const CREATE_CREDENTIALS_TABLE: &str = "
    CREATE TABLE IF NOT EXISTS credentials (
        id              TEXT PRIMARY KEY,
        agent_did       TEXT NOT NULL,
        issuer          TEXT NOT NULL,
        credential_type TEXT NOT NULL,
        format          TEXT NOT NULL,
        raw             TEXT NOT NULL,
        created_at      INTEGER NOT NULL,
        expires_at      INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_credentials_valid
        ON credentials(agent_did, issuer, credential_type, expires_at);
    ";

const SELECT_COLUMNS: &str = "id, agent_did, issuer, credential_type, format, raw, \
     created_at, expires_at FROM credentials";

fn row_to_record(row: &Row<'_>) -> rusqlite::Result<CredentialRecord> {
    Ok(CredentialRecord {
        id: row.get(0)?,
        agent_did: row.get(1)?,
        issuer: row.get(2)?,
        credential_type: row.get(3)?,
        format: row.get(4)?,
        raw: row.get(5)?,
        created_at: row.get(6)?,
        expires_at: row.get(7)?,
    })
}

impl SqlCipherStore {
    /// Store a credential, replacing any record under the same id.
    pub fn put_credential(&self, record: &CredentialRecord) -> Result<(), MemoryError> {
        let conn = self.conn.lock().map_err(|_| MemoryError::Lock)?;
        conn.execute(
            "INSERT OR REPLACE INTO credentials
                (id, agent_did, issuer, credential_type, format, raw, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                record.id,
                record.agent_did,
                record.issuer,
                record.credential_type,
                record.format,
                record.raw,
                record.created_at,
                record.expires_at,
            ],
        )?;
        Ok(())
    }

    pub fn get_credential(&self, id: &str) -> Result<Option<CredentialRecord>, MemoryError> {
        let conn = self.conn.lock().map_err(|_| MemoryError::Lock)?;
        let mut stmt = conn.prepare(&format!("SELECT {SELECT_COLUMNS} WHERE id = ?1"))?;
        let mut rows = stmt.query(params![id])?;
        match rows.next()? {
            Some(row) => Ok(Some(row_to_record(row)?)),
            None => Ok(None),
        }
    }

    pub fn list_credentials(&self) -> Result<Vec<CredentialRecord>, MemoryError> {
        let conn = self.conn.lock().map_err(|_| MemoryError::Lock)?;
        let mut stmt =
            conn.prepare(&format!("SELECT {SELECT_COLUMNS} ORDER BY created_at DESC"))?;
        let rows = stmt.query_map([], row_to_record)?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row?);
        }
        Ok(records)
    }

    pub fn delete_credential(&self, id: &str) -> Result<usize, MemoryError> {
        let conn = self.conn.lock().map_err(|_| MemoryError::Lock)?;
        Ok(conn.execute("DELETE FROM credentials WHERE id = ?1", params![id])?)
    }

    /// Credentials this agent can actually present: bound to its own key (a
    /// credential is key-bound to one agent), from a trusted issuer, of the
    /// requested type, and not expired. An indexed query, not a scan.
    pub fn find_valid_credentials(
        &self,
        agent_did: &str,
        issuer: &str,
        credential_type: &str,
        now: i64,
    ) -> Result<Vec<CredentialRecord>, MemoryError> {
        let conn = self.conn.lock().map_err(|_| MemoryError::Lock)?;
        let mut stmt = conn.prepare(&format!(
            "SELECT {SELECT_COLUMNS}
             WHERE agent_did = ?1 AND issuer = ?2 AND credential_type = ?3
               AND (expires_at IS NULL OR expires_at > ?4)
             ORDER BY created_at DESC"
        ))?;
        let rows = stmt.query_map(
            params![agent_did, issuer, credential_type, now],
            row_to_record,
        )?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row?);
        }
        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn open_store() -> SqlCipherStore {
        let file = NamedTempFile::new().expect("tempfile");
        let path = file.path().to_path_buf();
        std::mem::forget(file);
        SqlCipherStore::open(&path, "test-key").expect("open store")
    }

    fn record(id: &str) -> CredentialRecord {
        CredentialRecord {
            id: id.to_string(),
            agent_did: "did:key:zAgent".to_string(),
            issuer: "https://idp.example/realms/eng".to_string(),
            credential_type: "urn:shadi:agent-admission:1".to_string(),
            format: "dc+sd-jwt".to_string(),
            raw: "opaque-credential-bytes".to_string(),
            created_at: 1_000,
            expires_at: Some(2_000),
        }
    }

    #[test]
    fn put_get_round_trip() {
        let store = open_store();
        let record = record("cred-1");
        store.put_credential(&record).expect("put");
        let found = store
            .get_credential("cred-1")
            .expect("get")
            .expect("record");
        assert_eq!(found, record);
    }

    #[test]
    fn put_over_existing_id_replaces_rather_than_accumulating() {
        let store = open_store();
        store.put_credential(&record("cred-1")).expect("put");
        let mut updated = record("cred-1");
        updated.credential_type = "urn:shadi:other:1".to_string();
        store.put_credential(&updated).expect("put again");

        let all = store.list_credentials().expect("list");
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].credential_type, "urn:shadi:other:1");
    }

    #[test]
    fn find_valid_excludes_expired_wrong_issuer_and_other_agents() {
        let store = open_store();
        store.put_credential(&record("ok")).expect("put");

        let mut expired = record("expired");
        expired.expires_at = Some(500);
        store.put_credential(&expired).expect("put");

        let mut other_issuer = record("other-issuer");
        other_issuer.issuer = "https://evil.example".to_string();
        store.put_credential(&other_issuer).expect("put");

        let mut other_agent = record("other-agent");
        other_agent.agent_did = "did:key:zOther".to_string();
        store.put_credential(&other_agent).expect("put");

        let mut other_type = record("other-type");
        other_type.credential_type = "urn:shadi:other:1".to_string();
        store.put_credential(&other_type).expect("put");

        let found = store
            .find_valid_credentials(
                "did:key:zAgent",
                "https://idp.example/realms/eng",
                "urn:shadi:agent-admission:1",
                1_500,
            )
            .expect("find");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "ok");
    }

    #[test]
    fn find_valid_keeps_a_credential_without_exp() {
        let store = open_store();
        let mut forever = record("forever");
        forever.expires_at = None;
        store.put_credential(&forever).expect("put");

        let found = store
            .find_valid_credentials(
                "did:key:zAgent",
                "https://idp.example/realms/eng",
                "urn:shadi:agent-admission:1",
                i64::MAX,
            )
            .expect("find");
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn delete_removes_the_record() {
        let store = open_store();
        store.put_credential(&record("cred-1")).expect("put");
        assert_eq!(store.delete_credential("cred-1").expect("delete"), 1);
        assert!(store.get_credential("cred-1").expect("get").is_none());
        assert_eq!(store.delete_credential("cred-1").expect("delete"), 0);
    }

    /// The property that reusing `memory_entries` would have silently broken:
    /// `memory list`/`search` with no scope must not reach the vault.
    #[test]
    fn credentials_are_invisible_to_the_memory_commands() {
        let store = open_store();
        store.put_credential(&record("cred-1")).expect("put");

        assert!(store.list(None, 50).expect("list").is_empty());
        assert!(store
            .search(None, "did:key:zAgent", 50)
            .expect("search")
            .is_empty());
        assert!(store
            .search(None, "header.payload.sig", 50)
            .expect("search")
            .is_empty());
    }
}
