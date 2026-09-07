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
    /// under the same `--write` root as its mTLS material.
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
            format!(
                "create local adapter registry {}: {err}",
                self.dir.display()
            )
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
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_ACCESS_DENIED, STILL_ACTIVE,
    };
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    if pid == 0 {
        return false;
    }
    // SAFETY: OpenProcess can succeed after exit while any handle (including
    // this process's Child) is still open. GetExitCodeProcess distinguishes
    // STILL_ACTIVE from a real exit. The handle is closed exactly once.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return GetLastError() == ERROR_ACCESS_DENIED;
        }
        let mut code = 0u32;
        let ok = GetExitCodeProcess(handle, &mut code);
        CloseHandle(handle);
        ok != 0 && code == STILL_ACTIVE as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

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
        drop(child);
        let path = registry.dir.join(record_filename("codex", pid).unwrap());
        fs::create_dir_all(&registry.dir).unwrap();
        fs::write(&path, serde_json::to_vec(&sample("codex", pid)).unwrap()).unwrap();
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
    fn publish_rejects_empty_did_or_endpoint() {
        let (_dir, registry) = temp_registry();
        let pid = std::process::id();
        let mut no_did = sample("copilot", pid);
        no_did.did.clear();
        let err = match registry.publish(&no_did) {
            Ok(_) => panic!("empty DID must be rejected"),
            Err(err) => err,
        };
        assert!(err.contains("DID"), "{err}");
        let mut no_ep = sample("copilot", pid);
        no_ep.slim_endpoint.clear();
        let err = match registry.publish(&no_ep) {
            Ok(_) => panic!("empty endpoint must be rejected"),
            Err(err) => err,
        };
        assert!(err.contains("slim_endpoint"), "{err}");
    }

    #[test]
    fn publish_rejects_dash_prefix_and_empty_name() {
        let (_dir, registry) = temp_registry();
        assert!(registry
            .publish(&sample("-copilot", std::process::id()))
            .is_err());
        assert!(registry.publish(&sample("", std::process::id())).is_err());
    }

    #[test]
    fn publish_fails_when_registry_parent_is_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let blocked = dir.path().join("blocked");
        fs::write(&blocked, b"x").unwrap();
        let registry = LocalAdapterRegistry::with_dir(blocked.join("nested"));
        let err = match registry.publish(&sample("copilot", std::process::id())) {
            Ok(_) => panic!("file-as-parent must fail"),
            Err(err) => err,
        };
        assert!(err.contains("create local adapter registry"), "{err}");
    }

    #[test]
    fn from_env_uses_shadi_tmp_dir() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let tmp = tempfile::tempdir().unwrap();
        let prev = std::env::var_os("SHADI_TMP_DIR");
        std::env::set_var("SHADI_TMP_DIR", tmp.path());
        let registry = LocalAdapterRegistry::from_env();
        if let Some(value) = prev {
            std::env::set_var("SHADI_TMP_DIR", value);
        } else {
            std::env::remove_var("SHADI_TMP_DIR");
        }
        assert_eq!(registry.dir(), tmp.path().join("agentbridge-local"));
    }

    #[test]
    fn list_live_missing_dir_is_empty() {
        let registry = LocalAdapterRegistry::with_dir(std::path::PathBuf::from(
            "/no/such/agentbridge-local-test-dir",
        ));
        assert!(registry.list_live().unwrap().is_empty());
    }

    #[test]
    fn list_live_errors_when_registry_path_is_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-a-dir");
        fs::write(&path, b"x").unwrap();
        let registry = LocalAdapterRegistry::with_dir(path);
        let err = registry.list_live().unwrap_err();
        assert!(err.contains("read local adapter registry"), "{err}");
    }

    #[test]
    fn list_live_skips_junk_and_deletes_empty_did() {
        let (_dir, registry) = temp_registry();
        fs::create_dir_all(registry.dir()).unwrap();
        fs::write(registry.dir().join("readme.txt"), b"ignore").unwrap();
        fs::write(registry.dir().join("copilot.json"), b"{}").unwrap();
        fs::write(registry.dir().join("copilot-abc.json"), b"{}").unwrap();
        fs::create_dir(registry.dir().join("subdir")).unwrap();
        fs::write(registry.dir().join("copilot-1.json"), b"not-json").unwrap();
        let empty_did = registry.dir().join("ghost-1.json");
        fs::write(
            &empty_did,
            serde_json::to_vec(&LocalAdapterRecord {
                name: "ghost".to_string(),
                did: String::new(),
                slim_endpoint: "127.0.0.1:1".to_string(),
                pid: 1,
            })
            .unwrap(),
        )
        .unwrap();
        let zero = registry.dir().join("zero-0.json");
        fs::write(&zero, serde_json::to_vec(&sample("zero", 0)).unwrap()).unwrap();
        assert!(registry.list_live().unwrap().is_empty());
        assert!(!empty_did.exists());
        assert!(!zero.exists());
    }

    #[test]
    fn lease_filename_helpers_reject_junk() {
        assert!(record_filename("../evil", 1).is_err());
        assert!(!looks_like_lease_filename("readme.md"));
        assert!(!looks_like_lease_filename("copilot.json"));
        assert!(!looks_like_lease_filename("copilot-abc.json"));
        assert!(looks_like_lease_filename("copilot-12.json"));
        assert!(!pid_is_alive(0));
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
