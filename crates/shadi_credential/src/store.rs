// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! The credential table and the SQLCipher vault built on it.
//!
//! Its own database file rather than a table beside `memory_entries`: the
//! processes that read credentials do not read memory, and one file would mean
//! handing them the memory key.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OpenFlags, Row};
use serde::{Deserialize, Serialize};

use crate::vault::CredentialVault;
use crate::CredentialError;

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

const CREATE_CREDENTIALS_TABLE: &str = "
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

impl From<rusqlite::Error> for CredentialError {
    fn from(err: rusqlite::Error) -> Self {
        Self::Storage(err.to_string())
    }
}

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

/// The path every Linux developer, every container and every CI run takes,
/// because the keychain backend is a no-op off macOS.
pub struct SqlCipherVault {
    // `Connection` is `Send` but not `Sync` — it caches prepared statements in
    // a `RefCell` — and the vault is shared across threads.
    conn: Mutex<Connection>,
}

impl SqlCipherVault {
    pub fn open(path: &Path, key: &str) -> Result<Self, CredentialError> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.pragma_update(None, "key", key)?;
        conn.pragma_update(None, "cipher_compatibility", 4)?;
        conn.execute_batch(CREATE_CREDENTIALS_TABLE)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn conn(&self) -> Result<std::sync::MutexGuard<'_, Connection>, CredentialError> {
        self.conn
            .lock()
            .map_err(|_| CredentialError::Storage("database connection lock poisoned".to_string()))
    }
}

impl CredentialVault for SqlCipherVault {
    fn put(&self, record: &CredentialRecord) -> Result<(), CredentialError> {
        self.conn()?.execute(
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

    fn get(&self, id: &str) -> Result<Option<CredentialRecord>, CredentialError> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(&format!("SELECT {SELECT_COLUMNS} WHERE id = ?1"))?;
        let mut rows = stmt.query(params![id])?;
        match rows.next()? {
            Some(row) => Ok(Some(row_to_record(row)?)),
            None => Ok(None),
        }
    }

    fn list(&self) -> Result<Vec<CredentialRecord>, CredentialError> {
        let conn = self.conn()?;
        let mut stmt =
            conn.prepare(&format!("SELECT {SELECT_COLUMNS} ORDER BY created_at DESC"))?;
        let rows = stmt.query_map([], row_to_record)?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row?);
        }
        Ok(records)
    }

    fn delete(&self, id: &str) -> Result<bool, CredentialError> {
        let affected = self
            .conn()?
            .execute("DELETE FROM credentials WHERE id = ?1", params![id])?;
        Ok(affected > 0)
    }

    fn find_valid(
        &self,
        agent_did: &str,
        issuer: &str,
        credential_type: &str,
        now: i64,
    ) -> Result<Vec<CredentialRecord>, CredentialError> {
        let conn = self.conn()?;
        // Indexed, not a scan: see idx_credentials_valid.
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
