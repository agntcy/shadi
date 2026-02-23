// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use rusqlite::{params, Connection, OpenFlags};
use thiserror::Error;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

#[derive(Debug, Error)]
pub enum MemoryError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("time formatting error: {0}")]
    Time(#[from] time::error::Format),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MemoryEntry {
    pub id: i64,
    pub scope: String,
    pub entry_key: String,
    pub payload: String,
    pub created_at: String,
}

pub struct SqlCipherStore {
    conn: Connection,
}

impl SqlCipherStore {
    pub fn open(path: &Path, key: &str) -> Result<Self, MemoryError> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.pragma_update(None, "key", &key)?;
        conn.pragma_update(None, "cipher_compatibility", &4)?;
        conn.pragma_update(None, "foreign_keys", &"ON")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS memory_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scope TEXT NOT NULL,
                entry_key TEXT NOT NULL,
                payload TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_memory_scope_key
                ON memory_entries(scope, entry_key);
            CREATE INDEX IF NOT EXISTS idx_memory_created_at
                ON memory_entries(created_at);
            ",
        )?;
        Ok(Self { conn })
    }

    pub fn put(&self, scope: &str, entry_key: &str, payload: &str) -> Result<i64, MemoryError> {
        let created_at = OffsetDateTime::now_utc().format(&Rfc3339)?;
        self.conn.execute(
            "INSERT INTO memory_entries (scope, entry_key, payload, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![scope, entry_key, payload, created_at],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn get_latest(
        &self,
        scope: &str,
        entry_key: &str,
    ) -> Result<Option<MemoryEntry>, MemoryError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, scope, entry_key, payload, created_at
             FROM memory_entries
             WHERE scope = ?1 AND entry_key = ?2
             ORDER BY created_at DESC
             LIMIT 1",
        )?;
        let mut rows = stmt.query(params![scope, entry_key])?;
        if let Some(row) = rows.next()? {
            Ok(Some(MemoryEntry {
                id: row.get(0)?,
                scope: row.get(1)?,
                entry_key: row.get(2)?,
                payload: row.get(3)?,
                created_at: row.get(4)?,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn search(
        &self,
        scope: Option<&str>,
        query: &str,
        limit: usize,
    ) -> Result<Vec<MemoryEntry>, MemoryError> {
        let pattern = format!("%{}%", query);
        let mut entries = Vec::new();

        if let Some(scope) = scope {
            let mut stmt = self.conn.prepare(
                "SELECT id, scope, entry_key, payload, created_at
                 FROM memory_entries
                 WHERE scope = ?1 AND (entry_key LIKE ?2 OR payload LIKE ?2)
                 ORDER BY created_at DESC
                 LIMIT ?3",
            )?;
            let rows = stmt.query_map(params![scope, pattern, limit as i64], |row| {
                Ok(MemoryEntry {
                    id: row.get(0)?,
                    scope: row.get(1)?,
                    entry_key: row.get(2)?,
                    payload: row.get(3)?,
                    created_at: row.get(4)?,
                })
            })?;
            for row in rows {
                entries.push(row?);
            }
            return Ok(entries);
        }

        let mut stmt = self.conn.prepare(
            "SELECT id, scope, entry_key, payload, created_at
             FROM memory_entries
             WHERE entry_key LIKE ?1 OR payload LIKE ?1
             ORDER BY created_at DESC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![pattern, limit as i64], |row| {
            Ok(MemoryEntry {
                id: row.get(0)?,
                scope: row.get(1)?,
                entry_key: row.get(2)?,
                payload: row.get(3)?,
                created_at: row.get(4)?,
            })
        })?;
        for row in rows {
            entries.push(row?);
        }
        Ok(entries)
    }

    pub fn list(&self, scope: Option<&str>, limit: usize) -> Result<Vec<MemoryEntry>, MemoryError> {
        let mut entries = Vec::new();
        if let Some(scope) = scope {
            let mut stmt = self.conn.prepare(
                "SELECT id, scope, entry_key, payload, created_at
                 FROM memory_entries
                 WHERE scope = ?1
                 ORDER BY created_at DESC
                 LIMIT ?2",
            )?;
            let rows = stmt.query_map(params![scope, limit as i64], |row| {
                Ok(MemoryEntry {
                    id: row.get(0)?,
                    scope: row.get(1)?,
                    entry_key: row.get(2)?,
                    payload: row.get(3)?,
                    created_at: row.get(4)?,
                })
            })?;
            for row in rows {
                entries.push(row?);
            }
            return Ok(entries);
        }

        let mut stmt = self.conn.prepare(
            "SELECT id, scope, entry_key, payload, created_at
             FROM memory_entries
             ORDER BY created_at DESC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(MemoryEntry {
                id: row.get(0)?,
                scope: row.get(1)?,
                entry_key: row.get(2)?,
                payload: row.get(3)?,
                created_at: row.get(4)?,
            })
        })?;
        for row in rows {
            entries.push(row?);
        }
        Ok(entries)
    }

    pub fn delete(&self, scope: &str, entry_key: &str) -> Result<usize, MemoryError> {
        let affected = self.conn.execute(
            "DELETE FROM memory_entries WHERE scope = ?1 AND entry_key = ?2",
            params![scope, entry_key],
        )?;
        Ok(affected)
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

    #[test]
    fn put_get_latest_round_trip() {
        let store = open_store();
        let id = store
            .put("secops", "security_report", "payload-1")
            .expect("put");
        assert!(id > 0);

        let entry = store
            .get_latest("secops", "security_report")
            .expect("get")
            .expect("entry");
        assert_eq!(entry.payload, "payload-1");
        assert_eq!(entry.scope, "secops");
        assert_eq!(entry.entry_key, "security_report");
    }

    #[test]
    fn search_filters_by_scope_and_query() {
        let store = open_store();
        store
            .put("secops", "security_report", "dependabot alert")
            .expect("put");
        store
            .put("secops", "notes", "weekly summary")
            .expect("put");
        store
            .put("other", "notes", "dependabot triage")
            .expect("put");

        let entries = store
            .search(Some("secops"), "dependabot", 10)
            .expect("search");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].scope, "secops");
        assert_eq!(entries[0].entry_key, "security_report");
    }

    #[test]
    fn list_returns_latest_first() {
        let store = open_store();
        store
            .put("secops", "k1", "payload-1")
            .expect("put");
        store
            .put("secops", "k2", "payload-2")
            .expect("put");

        let entries = store.list(Some("secops"), 10).expect("list");
        assert_eq!(entries.len(), 2);
        assert!(entries[0].created_at >= entries[1].created_at);
    }

    #[test]
    fn list_without_scope_returns_entries() {
        let store = open_store();
        store
            .put("secops", "k1", "payload-1")
            .expect("put");
        let entries = store.list(None, 10).expect("list");
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn search_without_scope_matches_payload() {
        let store = open_store();
        store
            .put("secops", "k1", "dependabot")
            .expect("put");
        let entries = store.search(None, "dependabot", 10).expect("search");
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn delete_removes_entries() {
        let store = open_store();
        store
            .put("secops", "k1", "payload-1")
            .expect("put");
        let removed = store.delete("secops", "k1").expect("delete");
        assert_eq!(removed, 1);

        let entry = store
            .get_latest("secops", "k1")
            .expect("get");
        assert!(entry.is_none());
    }

    #[test]
    fn get_latest_returns_none_when_missing() {
        let store = open_store();
        let entry = store.get_latest("secops", "missing").expect("get");
        assert!(entry.is_none());
    }

    #[test]
    fn delete_returns_zero_when_missing() {
        let store = open_store();
        let removed = store.delete("secops", "missing").expect("delete");
        assert_eq!(removed, 0);
    }
}
