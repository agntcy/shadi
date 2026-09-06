// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! On-host registry of agentbridge listeners started by `register`.
//!
//! `list --local` cannot ask a dataplane SLIM client for "who is listening"
//! (that needs the controller channel). Instead each `register --slim-endpoint`
//! writes a lease under `$SHADI_TMP_DIR/agentbridge-local` (or the process
//! temp dir). `list --local` reads those files and drops any whose pid is
//! gone, so a killed listener does not stay listed.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::member_source::{CandidateMember, MemberSource};

const REGISTRY_DIRNAME: &str = "agentbridge-local";

/// One locally registered SLIM listener.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalAdapterRecord {
    pub name: String,
    pub did: String,
    pub slim_endpoint: String,
    pub pid: u32,
}

/// Directory of listener lease files.
#[derive(Debug, Clone)]
pub struct LocalAdapterRegistry {
    dir: PathBuf,
}

/// Removes the lease file when the registering process exits cleanly.
pub struct LocalAdapterLease {
    path: PathBuf,
}

impl Drop for LocalAdapterLease {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

impl LocalAdapterRegistry {
    /// `$SHADI_TMP_DIR/agentbridge-local`, else `<temp>/agentbridge-local`.
    /// Prefer `SHADI_TMP_DIR` so a sandboxed `register` can write the lease
    /// under the same `--read` root as its mTLS material.
    pub fn from_env() -> Self {
        let root = std::env::var_os("SHADI_TMP_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        Self::with_dir(root.join(REGISTRY_DIRNAME))
    }

    pub fn with_dir(dir: PathBuf) -> Self {
        Self { dir }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Write a lease for `record`. Replaces a previous lease for the same
    /// name+pid. The returned guard deletes the file on drop.
    pub fn publish(&self, record: &LocalAdapterRecord) -> Result<LocalAdapterLease, String> {
        if !is_safe_agent_name(&record.name) {
            return Err(format!("unsafe agent name '{}'", record.name));
        }
        if record.did.is_empty() || record.slim_endpoint.is_empty() {
            return Err("local adapter record needs a DID and slim_endpoint".to_string());
        }
        fs::create_dir_all(&self.dir).map_err(|err| {
            format!("create local adapter registry {}: {err}", self.dir.display())
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700));
        }
        let path = self.dir.join(record_filename(&record.name, record.pid)?);
        let body = serde_json::to_vec_pretty(record)
            .map_err(|err| format!("serialize local adapter record: {err}"))?;
        fs::write(&path, body)
            .map_err(|err| format!("write local adapter lease {}: {err}", path.display()))?;
        Ok(LocalAdapterLease { path })
    }

    /// Live listeners only: skip unreadable files and delete leases whose
    /// process is gone.
    pub fn list_live(&self) -> Result<Vec<LocalAdapterRecord>, String> {
        let mut records = Vec::new();
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(records),
            Err(err) => {
                return Err(format!(
                    "read local adapter registry {}: {err}",
                    self.dir.display()
                ));
            }
        };
        for entry in entries {
            let entry = entry.map_err(|err| format!("read registry entry: {err}"))?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !looks_like_lease_filename(name) {
                continue;
            }
            let Ok(bytes) = fs::read(&path) else {
                continue;
            };
            let Ok(record) = serde_json::from_slice::<LocalAdapterRecord>(&bytes) else {
                continue;
            };
            if !is_safe_agent_name(&record.name) || record.did.is_empty() {
                let _ = fs::remove_file(&path);
                continue;
            }
            if !pid_is_alive(record.pid) {
                let _ = fs::remove_file(&path);
                continue;
            }
            records.push(record);
        }
        records.sort_by(|a, b| a.name.cmp(&b.name).then(a.pid.cmp(&b.pid)));
        Ok(records)
    }
}

/// [`MemberSource`] over the on-host lease directory.
pub struct LocalRegistrySource {
    pub registry: LocalAdapterRegistry,
}

impl MemberSource for LocalRegistrySource {
    fn resolve(&self) -> Result<Vec<CandidateMember>, String> {
        Ok(self
            .registry
            .list_live()?
            .into_iter()
            .map(|record| CandidateMember {
                name: record.name,
                did: record.did,
                slim_endpoint: Some(record.slim_endpoint),
            })
            .collect())
    }
}

fn is_safe_agent_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('-')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn record_filename(name: &str, pid: u32) -> Result<String, String> {
    if !is_safe_agent_name(name) {
        return Err(format!("unsafe agent name '{name}'"));
    }
    Ok(format!("{name}-{pid}.json"))
}

fn looks_like_lease_filename(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(".json") else {
        return false;
    };
    let Some((agent, pid)) = stem.rsplit_once('-') else {
        return false;
    };
    is_safe_agent_name(agent) && pid.chars().all(|c| c.is_ascii_digit())
}

#[cfg(unix)]
fn pid_is_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    // SAFETY: signal 0 only probes existence; ESRCH means gone, EPERM means
    // the pid exists but we cannot signal it (still live).
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(windows)]
fn pid_is_alive(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ACCESS_DENIED};
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    if pid == 0 {
        return false;
    }
    // SAFETY: OpenProcess returns null when the pid is gone; the handle is
    // closed exactly once when non-null.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if !handle.is_null() {
            CloseHandle(handle);
            return true;
        }
        GetLastError() == ERROR_ACCESS_DENIED
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_registry() -> (tempfile::TempDir, LocalAdapterRegistry) {
        let dir = tempfile::tempdir().unwrap();
        let registry = LocalAdapterRegistry::with_dir(dir.path().to_path_buf());
        (dir, registry)
    }

    fn sample(name: &str, pid: u32) -> LocalAdapterRecord {
        LocalAdapterRecord {
            name: name.to_string(),
            did: "did:key:zTest".to_string(),
            slim_endpoint: "127.0.0.1:47357".to_string(),
            pid,
        }
    }

    #[test]
    fn publish_then_list_sees_this_process() {
        let (_dir, registry) = temp_registry();
        let record = sample("copilot", std::process::id());
        let _lease = registry.publish(&record).unwrap();
        assert_eq!(registry.list_live().unwrap(), vec![record]);
    }

    #[test]
    fn list_live_drops_dead_pids() {
        let (_dir, registry) = temp_registry();
        let mut child = dead_child();
        let pid = child.id();
        let _ = child.wait();
        let path = registry
            .dir
            .join(record_filename("codex", pid).unwrap());
        fs::create_dir_all(&registry.dir).unwrap();
        fs::write(
            &path,
            serde_json::to_vec(&sample("codex", pid)).unwrap(),
        )
        .unwrap();
        assert!(registry.list_live().unwrap().is_empty());
        assert!(!path.exists());
    }

    #[test]
    fn lease_drop_removes_file() {
        let (_dir, registry) = temp_registry();
        let record = sample("claude-code", std::process::id());
        {
            let _lease = registry.publish(&record).unwrap();
            assert_eq!(registry.list_live().unwrap().len(), 1);
        }
        assert!(registry.list_live().unwrap().is_empty());
    }

    #[test]
    fn publish_rejects_path_traversal_name() {
        let (_dir, registry) = temp_registry();
        let err = match registry.publish(&sample("../evil", std::process::id())) {
            Ok(_) => panic!("path traversal name must be rejected"),
            Err(err) => err,
        };
        assert!(err.contains("unsafe"), "{err}");
    }

    #[test]
    fn local_registry_source_maps_to_candidates() {
        let (_dir, registry) = temp_registry();
        let record = sample("cursor-agent", std::process::id());
        let _lease = registry.publish(&record).unwrap();
        let source = LocalRegistrySource { registry };
        let members = source.resolve().unwrap();
        assert_eq!(
            members,
            vec![CandidateMember {
                name: "cursor-agent".to_string(),
                did: "did:key:zTest".to_string(),
                slim_endpoint: Some("127.0.0.1:47357".to_string()),
            }]
        );
    }

    fn dead_child() -> std::process::Child {
        #[cfg(unix)]
        {
            std::process::Command::new("true").spawn().unwrap()
        }
        #[cfg(windows)]
        {
            let mut cmd = std::process::Command::new("cmd");
            cmd.args(["/C", "exit", "0"]);
            cmd.spawn().unwrap()
        }
    }
}
