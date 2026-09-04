// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Sandbox session management (agntcy/shadi#115) — replaces `shadictl shell`'s
//! `/status`, `/attach`, `/detach`, `/kill`, `/sessions`.
//!
//! Two kinds of session appear here. **Discovered** ones were started by
//! `shadictl --watch-policy` somewhere else and are reached through their
//! control socket, using the client in `shadi_sandbox::control` that shadictl
//! itself uses. **Launched** ones this app started with `spawn_sandboxed`;
//! they have no control socket, because serving one is shadictl's job, so the
//! app keeps the child handle and answers from it. `session_id` tells them
//! apart: a socket path for the first, `pid:<n>` for the second.
//!
//! Every command hops onto a blocking thread. The control client is blocking
//! socket I/O, and listing probes each endpoint in turn, so leaving it on a
//! Tauri async worker would stall unrelated commands behind a dead socket.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use shadi_sandbox::{control, spawn_sandboxed, SandboxPolicy, SandboxProfile, SandboxedChild};

use super::policy::PolicyConfig;

/// Prefix marking a session this app launched rather than discovered.
const LAUNCHED_PREFIX: &str = "pid:";

/// A discovered or launched SHADI sandbox session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxSession {
    pub name: String,
    /// Control socket path for a discovered session, `pid:<n>` for one this
    /// app launched.
    pub session_id: String,
    pub pid: Option<u32>,
    /// Whether this app owns the process, and so can report its command line
    /// and uptime.
    pub launched_here: bool,
}

/// Live status of a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxStatus {
    pub session: SandboxSession,
    pub running: bool,
    /// Only known for sessions this app launched; a control socket does not
    /// report when its process started.
    pub uptime_secs: Option<u64>,
    /// Likewise only known for sessions this app launched.
    pub command: Vec<String>,
    /// Resident set size, when the session answers a resource query.
    pub rss_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchSandboxRequest {
    pub command: Vec<String>,
    pub policy: PolicyConfig,
    pub session_name: Option<String>,
}

struct Launched {
    child: SandboxedChild,
    command: Vec<String>,
    started: Instant,
    name: String,
}

/// Sandboxed processes this app started, keyed by `pid:<n>`.
#[derive(Default)]
pub struct SandboxState(Arc<Mutex<HashMap<String, Launched>>>);

impl SandboxState {
    fn handle(&self) -> Arc<Mutex<HashMap<String, Launched>>> {
        Arc::clone(&self.0)
    }
}

/// Run blocking sandbox work off the async runtime.
async fn blocking<T, F>(f: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|err| format!("sandbox task failed: {err}"))?
}

/// Build a [`SandboxPolicy`] through the same layering shadictl uses, so a
/// sandbox launched here and one launched from the command line resolve the
/// same way.
fn policy_from_config(config: &PolicyConfig) -> Result<SandboxPolicy, String> {
    let profile = match config.profile.as_deref() {
        Some(name) => Some(SandboxProfile::from_name(name).ok_or_else(|| {
            format!("unknown profile '{name}'; expected strict, balanced or connected")
        })?),
        None => None,
    };

    let overrides = shadi_sandbox::PolicyOverrides {
        profile,
        allow: config.allow.iter().map(PathBuf::from).collect(),
        read: config.read.iter().map(PathBuf::from).collect(),
        write: config.write.iter().map(PathBuf::from).collect(),
        net_block: config.net_block,
        net_allow: config.net_allow.clone(),
        allow_command: Vec::new(),
    };

    shadi_sandbox::resolve_policy(&overrides, &shadi_sandbox::PolicyFileValues::default())
        .map(|resolved| resolved.policy)
}

/// Launch a sandboxed process (mirrors `shadictl <flags> -- <command>`).
#[tauri::command]
pub async fn sandbox_launch(
    request: LaunchSandboxRequest,
    state: tauri::State<'_, SandboxState>,
) -> Result<SandboxSession, String> {
    let sessions = state.handle();
    blocking(move || {
        let (program, args) = request
            .command
            .split_first()
            .ok_or_else(|| "command is empty".to_string())?;

        let policy = policy_from_config(&request.policy)?;
        let mut cmd = Command::new(program);
        cmd.args(args);

        let child = spawn_sandboxed(&mut cmd, &policy)
            .map_err(|err| format!("failed to launch sandboxed process: {err}"))?;

        let pid = child.id();
        let session_id = format!("{LAUNCHED_PREFIX}{pid}");
        let name = request
            .session_name
            .map(|n| control::sanitize_session_name(&n))
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| pid.to_string());

        let session = SandboxSession {
            name: name.clone(),
            session_id: session_id.clone(),
            pid: Some(pid),
            launched_here: true,
        };

        sessions.lock().map_err(lock_poisoned)?.insert(
            session_id,
            Launched {
                child,
                command: request.command,
                started: Instant::now(),
                name,
            },
        );

        Ok(session)
    })
    .await
}

/// Discover running sandbox sessions (`/sessions`), plus any this app launched.
#[tauri::command]
pub async fn sandbox_list_sessions(
    state: tauri::State<'_, SandboxState>,
) -> Result<Vec<SandboxSession>, String> {
    let sessions = state.handle();
    blocking(move || {
        // classify rather than prune: this list refreshes on a timer, and
        // deleting endpoints as a side effect of looking at them would be a
        // surprise from a panel.
        let dir = control::socket_dir();
        let mut found: Vec<SandboxSession> = control::classify_sockets(control::discover_sockets(&dir))
            .into_iter()
            .filter(|(_, reachable)| *reachable)
            .map(|(path, _)| SandboxSession {
                name: control::session_name_from_path(&path),
                session_id: path.to_string_lossy().into_owned(),
                pid: None,
                launched_here: false,
            })
            .collect();

        let mut owned = sessions.lock().map_err(lock_poisoned)?;
        owned.retain(|_, launched| launched.child.try_wait().ok().flatten().is_none());
        for (session_id, launched) in owned.iter() {
            found.push(SandboxSession {
                name: launched.name.clone(),
                session_id: session_id.clone(),
                pid: session_pid(session_id),
                launched_here: true,
            });
        }

        found.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(found)
    })
    .await
}

/// Attach to a session by name or socket path (`/attach`).
///
/// The control client is stateless, so attaching is a reachability check that
/// hands back the first status; the panel holds the selection.
#[tauri::command]
pub async fn sandbox_attach(
    session_id: String,
    state: tauri::State<'_, SandboxState>,
) -> Result<SandboxStatus, String> {
    let resolved = if session_id.starts_with(LAUNCHED_PREFIX) {
        session_id
    } else {
        control::resolve_session_socket(&session_id)
            .to_string_lossy()
            .into_owned()
    };
    sandbox_status(resolved, state).await
}

/// Detach from a session without terminating it (`/detach`).
///
/// Nothing to tear down: the client opens a connection per request and the
/// panel drops its selection. A session this app launched keeps running, and
/// stays listed so it can be killed later.
#[tauri::command]
pub async fn sandbox_detach(session_id: String) -> Result<(), String> {
    let _ = session_id;
    Ok(())
}

/// Terminate a session's sandboxed process (`/kill`).
#[tauri::command]
pub async fn sandbox_kill(
    session_id: String,
    state: tauri::State<'_, SandboxState>,
) -> Result<(), String> {
    let sessions = state.handle();
    blocking(move || {
        if session_id.starts_with(LAUNCHED_PREFIX) {
            let mut owned = sessions.lock().map_err(lock_poisoned)?;
            let mut launched = owned
                .remove(&session_id)
                .ok_or_else(|| format!("no launched session {session_id}"))?;
            return launched
                .child
                .kill()
                .map_err(|err| format!("failed to terminate {session_id}: {err}"));
        }

        control::send_terminate(&PathBuf::from(&session_id)).map(|_| ())
    })
    .await
}

/// Live status of a session (`/status`).
#[tauri::command]
pub async fn sandbox_status(
    session_id: String,
    state: tauri::State<'_, SandboxState>,
) -> Result<SandboxStatus, String> {
    let sessions = state.handle();
    blocking(move || {
        if session_id.starts_with(LAUNCHED_PREFIX) {
            let mut owned = sessions.lock().map_err(lock_poisoned)?;
            let launched = owned
                .get_mut(&session_id)
                .ok_or_else(|| format!("no launched session {session_id}"))?;
            let running = launched.child.try_wait().ok().flatten().is_none();
            return Ok(SandboxStatus {
                session: SandboxSession {
                    name: launched.name.clone(),
                    session_id: session_id.clone(),
                    pid: session_pid(&session_id),
                    launched_here: true,
                },
                running,
                uptime_secs: Some(launched.started.elapsed().as_secs()),
                command: launched.command.clone(),
                rss_bytes: None,
            });
        }

        let path = PathBuf::from(&session_id);
        // A policy query is the reachability check; resources are a bonus the
        // session may decline to answer.
        control::query_policy(&path)?;
        let resources = control::query_resources(&path).ok();

        Ok(SandboxStatus {
            session: SandboxSession {
                name: control::session_name_from_path(&path),
                session_id: session_id.clone(),
                pid: resources.as_ref().map(|r| r.pid),
                launched_here: false,
            },
            running: true,
            uptime_secs: None,
            command: Vec::new(),
            rss_bytes: resources.and_then(|r| r.rss_bytes),
        })
    })
    .await
}

fn session_pid(session_id: &str) -> Option<u32> {
    session_id.strip_prefix(LAUNCHED_PREFIX)?.parse().ok()
}

fn lock_poisoned<T>(_: T) -> String {
    "sandbox session registry is poisoned".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> PolicyConfig {
        PolicyConfig {
            allow: Vec::new(),
            read: Vec::new(),
            write: Vec::new(),
            net_block: false,
            net_allow: Vec::new(),
            profile: None,
        }
    }

    #[test]
    fn an_unknown_profile_is_rejected_by_name() {
        let mut c = config();
        c.profile = Some("paranoid".to_string());
        let err = policy_from_config(&c).unwrap_err();
        assert!(err.contains("unknown profile 'paranoid'"), "{err}");
        assert!(err.contains("strict, balanced or connected"), "{err}");
    }

    #[test]
    fn every_documented_profile_resolves() {
        for name in ["strict", "balanced", "connected", "STRICT"] {
            let mut c = config();
            c.profile = Some(name.to_string());
            assert!(policy_from_config(&c).is_ok(), "{name} should resolve");
        }
    }

    #[test]
    fn a_nonexistent_path_names_the_axis_that_rejected_it() {
        let mut c = config();
        c.write = vec!["/nonexistent-shadi-path".to_string()];
        let err = policy_from_config(&c).unwrap_err();
        assert!(err.starts_with("invalid write path /nonexistent-shadi-path"), "{err}");
    }

    #[test]
    fn session_pid_reads_back_only_launched_ids() {
        assert_eq!(session_pid("pid:4321"), Some(4321));
        assert_eq!(session_pid("/tmp/shadi-ctl-agent.sock"), None);
        assert_eq!(session_pid("pid:not-a-number"), None);
    }

    #[test]
    fn explicit_paths_layer_on_top_of_a_profile() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut c = config();
        c.profile = Some("strict".to_string());
        c.write = vec![dir.path().to_string_lossy().into_owned()];

        // Strict blocks the network; an explicit writable path must not undo
        // that, and must not fail to resolve either.
        assert!(policy_from_config(&c).is_ok());
    }
}
