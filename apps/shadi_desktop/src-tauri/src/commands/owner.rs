// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! The channel owner's view (agntcy/shadi#421): the rooms this Desktop
//! moderates are the human's, and agents ask to let someone in over A2A.
//! Standing rules decide most requests; the rest wait here for allow or deny.
//!
//! The rules live in `owner-policy.json` and every decision is appended to
//! `owner-audit.jsonl`, both in the app data dir.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use agentbridge::owner::{Owner, OwnerPolicy, PendingAsk};
use agentbridge::owner_intake::{Inviter, OwnerExecutor};
use serde::Serialize;
use tauri::Manager;

use super::slim::{RoomInviter, SlimState};

const POLICY_FILE: &str = "owner-policy.json";
const AUDIT_FILE: &str = "owner-audit.jsonl";
const AUDIT_SHOWN: usize = 500;

/// Registered with `.manage(...)`; `None` until `owner_start`.
#[derive(Default)]
pub struct OwnerState(Mutex<Option<Running>>);

struct Running {
    owner: Arc<Mutex<Owner>>,
    inviter: Arc<RoomInviter>,
    owner_did: String,
    service: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OwnerStatus {
    pub running: bool,
    pub owner_did: Option<String>,
    /// The SLIM name agents send requests to.
    pub service: Option<String>,
    /// The rooms this Desktop moderates, which the owner holds.
    pub channels: Vec<String>,
}

fn data_file(app: &tauri::AppHandle, name: &str) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map(|dir| dir.join(name))
        .map_err(|e| format!("no app data dir: {e}"))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn load_policy(path: &PathBuf) -> Result<OwnerPolicy, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => OwnerPolicy::from_json(&text).map_err(|e| e.to_string()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(OwnerPolicy::default()),
        Err(err) => Err(format!("{}: {err}", path.display())),
    }
}

/// Run `f` on the running owner, after holding exactly the rooms this Desktop
/// moderates now: a room created or forgotten since the last call counts.
fn with_owner<T>(
    owner: &OwnerState,
    slim: &SlimState,
    f: impl FnOnce(&Running, &mut Owner) -> Result<T, String>,
) -> Result<T, String> {
    let running = owner.0.lock().map_err(|_| "owner state poisoned")?;
    let running = running
        .as_ref()
        .ok_or_else(|| "the owner service isn't running; start it first".to_string())?;
    let mut core = running.owner.lock().map_err(|_| "owner poisoned")?;
    core.hold_only(slim.moderated_channels()?);
    f(running, &mut core)
}

fn status(owner: &OwnerState, slim: &SlimState) -> Result<OwnerStatus, String> {
    let running = owner
        .0
        .lock()
        .map_err(|_| "owner state poisoned")?
        .is_some();
    if !running {
        return Ok(OwnerStatus {
            running: false,
            owner_did: None,
            service: None,
            channels: slim.moderated_channels()?,
        });
    }
    with_owner(owner, slim, |running, core| {
        Ok(OwnerStatus {
            running: true,
            owner_did: Some(running.owner_did.clone()),
            service: Some(running.service.clone()),
            channels: core.held().map(str::to_string).collect(),
        })
    })
}

/// Start serving requests as the owner of the rooms this Desktop moderates.
#[tauri::command]
pub async fn owner_start(
    app: tauri::AppHandle,
    slim: tauri::State<'_, SlimState>,
    owner: tauri::State<'_, OwnerState>,
) -> Result<OwnerStatus, String> {
    if owner
        .0
        .lock()
        .map_err(|_| "owner state poisoned")?
        .is_none()
    {
        let policy = load_policy(&data_file(&app, POLICY_FILE)?)?;
        let identity = slim.owner_identity()?;
        let owner_did = identity.did();
        let mut core = Owner::new(identity, policy, Some(data_file(&app, AUDIT_FILE)?));
        core.hold_only(slim.moderated_channels()?);
        let core = Arc::new(Mutex::new(core));
        let inviter = Arc::new(slim.room_inviter(owner_did.clone()));
        let executor = OwnerExecutor::new(core.clone(), inviter.clone());

        let handle = slim.inner().clone();
        let service = tauri::async_runtime::spawn_blocking(move || handle.serve_owner(executor))
            .await
            .map_err(|e| format!("task failed: {e}"))??;
        *owner.0.lock().map_err(|_| "owner state poisoned")? = Some(Running {
            owner: core,
            inviter,
            owner_did,
            service,
        });
    }
    status(&owner, &slim)
}

#[tauri::command]
pub async fn owner_status(
    slim: tauri::State<'_, SlimState>,
    owner: tauri::State<'_, OwnerState>,
) -> Result<OwnerStatus, String> {
    status(&owner, &slim)
}

/// Asks waiting for the owner, after denying those that timed out.
#[tauri::command]
pub async fn owner_pending(
    slim: tauri::State<'_, SlimState>,
    owner: tauri::State<'_, OwnerState>,
) -> Result<Vec<PendingAsk>, String> {
    with_owner(&owner, &slim, |_, core| {
        core.expire(now()).map_err(|e| e.to_string())?;
        Ok(core.pending().cloned().collect())
    })
}

/// Allow an ask: sign its grant and send the invite.
#[tauri::command]
pub async fn owner_approve(
    slim: tauri::State<'_, SlimState>,
    owner: tauri::State<'_, OwnerState>,
    ask_id: u64,
) -> Result<(), String> {
    let (grant, request, inviter) = with_owner(&owner, &slim, |running, core| {
        let request = core
            .pending()
            .find(|ask| ask.id == ask_id)
            .map(|ask| ask.request.clone())
            .ok_or_else(|| format!("no pending ask {ask_id}"))?;
        let grant = core.approve(ask_id, now()).map_err(|e| e.to_string())?;
        Ok((grant, request, running.inviter.clone()))
    })?;
    // The invite blocks on SLIM, which an async worker can't enter.
    tauri::async_runtime::spawn_blocking(move || inviter.invite(&grant, &request))
        .await
        .map_err(|e| format!("task failed: {e}"))?
}

#[tauri::command]
pub async fn owner_deny(
    slim: tauri::State<'_, SlimState>,
    owner: tauri::State<'_, OwnerState>,
    ask_id: u64,
) -> Result<(), String> {
    with_owner(&owner, &slim, |_, core| {
        core.deny(ask_id, now()).map_err(|e| e.to_string())
    })
}

/// The standing rules as saved, or `{}` (ask for everything) before any save.
#[tauri::command]
pub async fn owner_policy_get(app: tauri::AppHandle) -> Result<String, String> {
    let path = data_file(&app, POLICY_FILE)?;
    match std::fs::read_to_string(&path) {
        Ok(text) => Ok(text),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok("{}\n".to_string()),
        Err(err) => Err(format!("{}: {err}", path.display())),
    }
}

/// Validate and save the standing rules, applying them at once when the
/// owner service runs. An invalid policy is refused and the old one stays.
#[tauri::command]
pub async fn owner_policy_set(
    app: tauri::AppHandle,
    owner: tauri::State<'_, OwnerState>,
    policy: String,
) -> Result<(), String> {
    let parsed = OwnerPolicy::from_json(&policy).map_err(|e| e.to_string())?;
    let path = data_file(&app, POLICY_FILE)?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    std::fs::write(&path, &policy).map_err(|e| format!("{}: {e}", path.display()))?;
    if let Some(running) = owner.0.lock().map_err(|_| "owner state poisoned")?.as_ref() {
        running
            .owner
            .lock()
            .map_err(|_| "owner poisoned")?
            .set_policy(parsed);
    }
    Ok(())
}

/// The audit trail, newest first.
#[tauri::command]
pub async fn owner_audit(app: tauri::AppHandle) -> Result<Vec<serde_json::Value>, String> {
    let path = data_file(&app, AUDIT_FILE)?;
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(format!("{}: {err}", path.display())),
    };
    Ok(text
        .lines()
        .rev()
        .take(AUDIT_SHOWN)
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_policy_file_means_ask_and_a_bad_one_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(POLICY_FILE);
        assert_eq!(load_policy(&path).unwrap(), OwnerPolicy::default());
        std::fs::write(&path, r#"{"default": "maybe"}"#).unwrap();
        assert!(load_policy(&path).is_err());
        std::fs::write(&path, r#"{"default": "allow"}"#).unwrap();
        assert_ne!(load_policy(&path).unwrap(), OwnerPolicy::default());
    }

    #[test]
    fn nothing_runs_until_the_owner_service_starts() {
        let owner = OwnerState::default();
        let slim = SlimState::default();
        let err = with_owner(&owner, &slim, |_, _| Ok(())).unwrap_err();
        assert!(err.contains("start it first"), "{err}");
        let idle = status(&owner, &slim).unwrap();
        assert!(!idle.running && idle.owner_did.is_none());
    }
}
