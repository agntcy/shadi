// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! SLIM operations (agntcy/shadi#118) — the admin surface for collaboration
//! rooms. A SLIM group is a persistent room whose members are humans and
//! agents; the sustained message exchange between them happens over SLIM via
//! each member's own agentic harness, continuously. This panel administers
//! who is in a room, not what they say.
//!
//! Links `slim_bindings`/`shadi_identity` directly rather than shelling out to
//! `shadictl`, whose `slim_shell`/`slim_controller` modules are private to
//! that binary. The call sequences here mirror those modules.
//!
//! Unlike `shadictl shell`, which deliberately holds a single active session
//! (creating or joining a second channel deletes the first), this panel tracks
//! every room it created or joined in [`SlimState::rooms`] — a rooms overview
//! is the whole point of a collaboration surface. Rooms are live sessions, so
//! the map is in-memory only: it reflects what this process is currently
//! joined to, and is empty on a fresh launch until rooms are re-joined.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use slim_bindings::{
    App, CaSource, ClientConfig, MlsSettings, Name, ServerConfig, Service, Session, SessionConfig,
    SessionType, TlsClientConfig, TlsServerConfig, TlsSource,
};
use slim_config::client::ClientConfig as CoreClientConfig;
use slim_config::grpc::client::TransportChannel;
use slim_config::tls::client::TlsClientConfig as CoreTlsClientConfig;
use slim_config::tls::common::{
    CaSource as CoreCaSource, Config as CoreTlsConfig, TlsSource as CoreTlsSource,
};
use slim_proto::controller::proto::v1::{
    control_message, controller_service_client::ControllerServiceClient, ConnectionListRequest,
    ConnectionListResponse, ControlMessage, RouteListRequest, RouteListResponse,
};
use slim_proto::dataplane::proto::v1::{Name as ProtoName, NameId};
use tokio::runtime::Builder as TokioRuntimeBuilder;

const DEFAULT_SLIM_ENDPOINT: &str = "127.0.0.1:47357";
const DEFAULT_LOCAL_ORG: &str = "agntcy";
const DEFAULT_LOCAL_NAMESPACE: &str = "shadi";
const DEFAULT_LOCAL_APP: &str = "agent";
const CONTROLLER_TIMEOUT_SECONDS: u64 = 10;

// --- IPC types ---------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlimNodeStatus {
    pub running: bool,
    pub endpoint: Option<String>,
}

/// A room member. `kind` is `"human"` or `"agent"`.
///
/// Nothing in the stack can derive this: a `did:key` is a bare Ed25519 public
/// key with no document, issuer, or claims to inspect. It is declared when the
/// member is admitted — Directory-discovered candidates default to `"agent"`,
/// hand-named ones to `"human"` — matching the free-text `role` convention
/// `slim_mas::MemberConfig` already uses in `mas.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlimGroupMember {
    pub name: String,
    pub did: String,
    pub endpoint: Option<String>,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlimGroupInfo {
    pub channel: String,
    /// "moderator" | "participant".
    pub role: String,
    /// Whether a live SLIM session backs this room right now. A known room
    /// restored from disk is `false` until rejoined: its roster is readable,
    /// but it cannot be invited into or removed from.
    pub connected: bool,
    pub members: Vec<SlimGroupMember>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlimConnection {
    pub id: String,
    pub endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlimRoute {
    pub destination: String,
    pub via: String,
}

// --- Managed state -----------------------------------------------------------

struct Room {
    /// `None` for a room that is *known* but not currently *connected* — it was
    /// restored from disk, or its session hasn't been re-established since
    /// launch. Invites and removals need a live session; the roster does not.
    session: Option<Arc<Session>>,
    moderator: bool,
    /// Members this process admitted, keyed by SLIM name. `participants_list`
    /// reports names only, so DID/endpoint/kind are carried here from
    /// admission-time resolution — and are what a disconnected room shows.
    admitted: HashMap<String, SlimGroupMember>,
}

/// The on-disk form of a [`Room`] (agntcy/shadi#138). Only metadata: sessions
/// and credentials are never written, and a `did:key` is a public key, so
/// nothing here is secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedRoom {
    channel: String,
    moderator: bool,
    #[serde(default)]
    members: Vec<SlimGroupMember>,
}

#[derive(Default)]
struct Inner {
    node_service: Option<Service>,
    client_service: Option<Service>,
    connection_id: Option<u64>,
    app: Option<Arc<App>>,
    local_name: Option<Arc<Name>>,
    node_started: bool,
    rooms: HashMap<String, Room>,
    subscribed_channels: Vec<String>,
    /// Where known rooms are persisted. `None` until `lib.rs`'s setup hook
    /// resolves the app data dir, which also makes this harmless in tests.
    store_path: Option<PathBuf>,
}

/// Registered with `.manage(...)` in `lib.rs`; the SLIM node/session lifecycle
/// spans commands, so unlike the other panels this one cannot be stateless.
///
/// The state is behind an `Arc` so [`with_state`] can move a handle onto a
/// blocking thread — see that function for why every command must.
#[derive(Default)]
pub struct SlimState(Arc<Mutex<Inner>>);

/// Run `f` against the SLIM state on a blocking thread.
///
/// Every blocking `slim_bindings` entry point this module uses — `run_server`,
/// `connect`, `create_session_and_wait`, `subscribe`, `set_route`,
/// `listen_for_session`, `invite_and_wait`, `remove_and_wait`,
/// `participants_list`, `delete_session_and_wait` — is a
/// `get_runtime().block_on(..)` wrapper. Calling one directly from an
/// `async` command runs it on a Tauri async worker and panics with "Cannot
/// start a runtime from within a runtime", killing the command. So the work
/// has to leave the async runtime first; `spawn_blocking` is what does that.
///
/// The lock is held for the whole closure, which serializes room operations.
/// That is intended: they mutate one shared node/app/session graph.
async fn with_state<T, F>(state: &tauri::State<'_, SlimState>, f: F) -> Result<T, String>
where
    F: FnOnce(&mut Inner) -> Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    let state = state.0.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let mut inner = state.lock().map_err(|_| "SLIM state poisoned".to_string())?;
        f(&mut inner)
    })
    .await
    .map_err(|e| format!("task failed: {e}"))?
}

impl SlimState {
    /// Point the state at its on-disk room store and load whatever is already
    /// there. Called once from `lib.rs`'s setup hook, where the app data dir is
    /// first available. A load failure is reported but not fatal — a corrupt or
    /// unreadable store must not stop the app from starting.
    pub fn init_store(&self, path: PathBuf) -> Result<(), String> {
        let mut inner = self.0.lock().map_err(|_| "SLIM state poisoned")?;
        inner.store_path = Some(path.clone());
        if !path.is_file() {
            return Ok(());
        }
        let data = std::fs::read_to_string(&path)
            .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        let stored: Vec<PersistedRoom> = serde_json::from_str(&data)
            .map_err(|e| format!("invalid room store {}: {e}", path.display()))?;
        for room in stored {
            inner.rooms.insert(
                room.channel,
                Room {
                    session: None,
                    moderator: room.moderator,
                    admitted: room
                        .members
                        .into_iter()
                        .map(|m| (m.name.clone(), m))
                        .collect(),
                },
            );
        }
        Ok(())
    }
}

impl Inner {
    fn ensure_connection(&mut self) -> Result<u64, String> {
        if let Some(id) = self.connection_id {
            return Ok(id);
        }
        let config = build_client_config()?;
        let id = self
            .client_service_mut()
            .connect(config)
            .map_err(slim_err)?;
        self.connection_id = Some(id);
        Ok(id)
    }

    fn local_name(&mut self) -> Result<Arc<Name>, String> {
        if let Some(name) = &self.local_name {
            return Ok(name.clone());
        }
        let name = Arc::new(parse_name(&resolve_local_name()?)?);
        self.local_name = Some(name.clone());
        Ok(name)
    }

    fn ensure_app(&mut self) -> Result<Arc<App>, String> {
        if let Some(app) = &self.app {
            return Ok(app.clone());
        }
        let connection_id = self.ensure_connection()?;
        let local_name = self.local_name()?;
        // DID derivation uses the app (last) component of the local name.
        let agent_id = local_name.components().last().cloned().unwrap_or_default();
        let auth = shadi_identity::did_auth_from_env(&agent_id)
            .ok_or_else(|| {
                "SLIM group administration requires DID auth; set SHADI_SLIM_AUTH=did \
                 (a room's trust set is meaningless under shared-secret auth)"
                    .to_string()
            })?
            .map_err(|e| e.to_string())?;
        let app = shadi_identity::create_app(self.client_service_mut(), local_name.clone(), &auth)
            .map_err(slim_err)?;
        app.subscribe(local_name, Some(connection_id))
            .map_err(slim_err)?;
        self.app = Some(app.clone());
        Ok(app)
    }

    /// Subscribing enables *receiving*. Joining also needs a route to the
    /// channel or this member's own broadcasts never reach the group.
    fn ensure_channel_subscription(&mut self, channel: &str) -> Result<(), String> {
        if self.subscribed_channels.iter().any(|c| c == channel) {
            return Ok(());
        }
        let connection_id = self.ensure_connection()?;
        let app = self.ensure_app()?;
        app.subscribe(Arc::new(parse_name(channel)?), Some(connection_id))
            .map_err(slim_err)?;
        self.subscribed_channels.push(channel.to_string());
        Ok(())
    }

    fn room(&self, channel: &str) -> Result<&Room, String> {
        self.rooms
            .get(channel)
            .ok_or_else(|| format!("no room '{channel}'; create or join it first"))
    }

    /// The live session for a room, or an error naming what to do about it —
    /// a known-but-disconnected room needs rejoining before it can be modified.
    fn live_session(&self, channel: &str) -> Result<Arc<Session>, String> {
        self.room(channel)?.session.clone().ok_or_else(|| {
            format!("room '{channel}' is known but not connected; rejoin it first")
        })
    }

    /// Write every known room's metadata to the store. Called after each
    /// mutation. A write failure is surfaced to the caller rather than
    /// swallowed — silently losing rooms is what this feature exists to stop.
    fn persist(&self) -> Result<(), String> {
        let Some(path) = &self.store_path else {
            return Ok(());
        };
        let mut stored: Vec<PersistedRoom> = self
            .rooms
            .iter()
            .map(|(channel, room)| PersistedRoom {
                channel: channel.clone(),
                moderator: room.moderator,
                members: room.admitted.values().cloned().collect(),
            })
            .collect();
        // Stable order so the file doesn't churn between writes.
        stored.sort_by(|a, b| a.channel.cmp(&b.channel));
        for room in &mut stored {
            room.members.sort_by(|a, b| a.name.cmp(&b.name));
        }

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
        }
        let data = serde_json::to_string_pretty(&stored)
            .map_err(|e| format!("failed to serialize rooms: {e}"))?;
        std::fs::write(path, data)
            .map_err(|e| format!("failed to write {}: {e}", path.display()))
    }

    fn node_service_mut(&mut self) -> &mut Service {
        self.node_service
            .get_or_insert_with(|| Service::new(node_service_name()))
    }

    fn client_service_mut(&mut self) -> &mut Service {
        self.client_service
            .get_or_insert_with(|| Service::new(client_service_name()))
    }

    /// Roster for a room. Connected: live `participants_list` names, enriched
    /// with admission-time DID/endpoint/kind where this process knows them.
    /// Disconnected: the last-known admitted members, so a restored room still
    /// shows who belongs to it.
    fn roster(&self, channel: &str) -> Result<Vec<SlimGroupMember>, String> {
        let room = self.room(channel)?;
        let Some(session) = &room.session else {
            let mut members: Vec<SlimGroupMember> = room.admitted.values().cloned().collect();
            members.sort_by(|a, b| a.name.cmp(&b.name));
            return Ok(members);
        };
        let participants = session.participants_list().map_err(slim_err)?;
        Ok(participants
            .into_iter()
            .map(|name| {
                let name = name.to_string();
                room.admitted.get(&name).cloned().unwrap_or(SlimGroupMember {
                    name,
                    did: String::new(),
                    endpoint: None,
                    kind: "agent".to_string(),
                })
            })
            .collect())
    }

    fn group_info(&self, channel: &str) -> Result<SlimGroupInfo, String> {
        let room = self.room(channel)?;
        Ok(SlimGroupInfo {
            channel: channel.to_string(),
            role: if room.moderator {
                "moderator".to_string()
            } else {
                "participant".to_string()
            },
            connected: room.session.is_some(),
            members: self.roster(channel)?,
        })
    }
}

// --- Node --------------------------------------------------------------------

/// Start a local native SLIM node with SHADI mTLS defaults (`/slim start-node`).
#[tauri::command]
pub async fn slim_node_start(state: tauri::State<'_, SlimState>) -> Result<SlimNodeStatus, String> {
    with_state(&state, |inner| {
        if !inner.node_started {
            let config = build_server_config()?;
            inner
                .node_service_mut()
                .run_server(config)
                .map_err(slim_err)?;
            inner.node_started = true;
        }
        Ok(SlimNodeStatus {
            running: true,
            endpoint: Some(resolve_endpoint()),
        })
    })
    .await
}

#[tauri::command]
pub async fn slim_node_status(state: tauri::State<'_, SlimState>) -> Result<SlimNodeStatus, String> {
    with_state(&state, |inner| {
        Ok(SlimNodeStatus {
            running: inner.node_started,
            endpoint: Some(resolve_endpoint()),
        })
    })
    .await
}

// --- Rooms -------------------------------------------------------------------

/// Create a room with members resolved from Agent Directory discovery and/or
/// named explicitly (`/slim create-group`, `member_specs` in the
/// `skill:<skill>` | `did:<did>` | `explicit:<name>=<did>[@<endpoint>]` shape).
///
/// Resolved DIDs are unioned into the `SLIM_MEMBER_DIDS` trust set, matching
/// `shadictl slim create-group`.
#[tauri::command]
pub async fn slim_group_create(
    state: tauri::State<'_, SlimState>,
    channel: String,
    member_specs: Vec<String>,
    dir_server: String,
) -> Result<SlimGroupInfo, String> {
    with_state(&state, move |inner| {
        // Directory resolution shells out to `dirctl`, so it belongs on the
        // blocking thread too.
        let candidates = resolve_candidates(&member_specs, &dir_server)?;
        admit_dids_to_trust_set(candidates.iter().map(|(m, _)| m.did.as_str()));

        let channel_name = Arc::new(parse_name(&channel)?);
        let app = inner.ensure_app()?;
        let session = app
            .create_session_and_wait(group_session_config(), channel_name.clone())
            .map_err(slim_err)?;

        inner.rooms.insert(
            channel_name.to_string(),
            Room {
                session: Some(session),
                moderator: true,
                admitted: candidates
                    .into_iter()
                    .map(|(member, _)| (member.name.clone(), member))
                    .collect(),
            },
        );
        inner.persist()?;
        inner.group_info(&channel_name.to_string())
    })
    .await
}

/// Invite a member into a room (`/slim invite`, `/slim invite-from`).
///
/// A `skill:`/`did:`/`explicit:` spec is resolved through the Directory and
/// admitted with its DID; a bare `org/ns/app` name is invited directly.
///
/// `kind` overrides the human/agent default. Callers that already know what
/// they are admitting should always pass it: adding a Directory-discovered
/// agent by its known `{name, did, endpoint}` uses an `explicit:` spec, whose
/// prefix-based default would otherwise mislabel it as human.
#[tauri::command]
pub async fn slim_group_invite(
    state: tauri::State<'_, SlimState>,
    channel: String,
    member_spec: String,
    dir_server: Option<String>,
    kind: Option<String>,
) -> Result<SlimGroupInfo, String> {
    with_state(&state, move |inner| {
        let mut resolved = if is_member_spec(&member_spec) {
            // Only Directory-backed specs need a server; `explicit:` carries its
            // own DID and resolves locally.
            let dir_server = if spec_needs_directory(&member_spec) {
                dir_server.ok_or_else(|| {
                    format!(
                        "member spec '{member_spec}' needs a Directory server to resolve against"
                    )
                })?
            } else {
                dir_server.unwrap_or_default()
            };
            resolve_candidates(std::slice::from_ref(&member_spec), &dir_server)?
        } else {
            vec![(
                SlimGroupMember {
                    name: member_spec.clone(),
                    did: String::new(),
                    endpoint: None,
                    kind: "human".to_string(),
                },
                None,
            )]
        };
        if resolved.is_empty() {
            return Err(format!(
                "member spec '{member_spec}' resolved to no candidates"
            ));
        }
        if let Some(kind) = kind {
            for (member, _) in &mut resolved {
                member.kind = kind.clone();
            }
        }
        admit_dids_to_trust_set(
            resolved
                .iter()
                .map(|(m, _)| m.did.as_str())
                .filter(|d| !d.is_empty()),
        );

        let connection_id = inner.ensure_connection()?;
        let app = inner.ensure_app()?;
        let session = inner.live_session(&channel)?;

        for (member, _) in &resolved {
            let name = Arc::new(parse_name(&member.name)?);
            app.set_route(name.clone(), connection_id).map_err(slim_err)?;
            session.invite_and_wait(name).map_err(slim_err)?;
        }

        let room = inner
            .rooms
            .get_mut(&channel)
            .ok_or_else(|| format!("no room '{channel}'"))?;
        for (member, _) in resolved {
            room.admitted.insert(member.name.clone(), member);
        }
        inner.persist()?;
        inner.group_info(&channel)
    })
    .await
}

/// Join a room created by a moderator (`/slim join`), or rejoin a known one.
///
/// Rejoining reattaches the live session to the existing record, keeping the
/// role and admitted-member metadata a restored room already carries — losing
/// that on rejoin would defeat persisting it.
#[tauri::command]
pub async fn slim_group_join(
    state: tauri::State<'_, SlimState>,
    channel: String,
    timeout_secs: Option<u64>,
) -> Result<SlimGroupInfo, String> {
    with_state(&state, move |inner| {
    let expected = parse_name(&channel)?;
    inner.ensure_channel_subscription(&channel)?;
    let connection_id = inner.ensure_connection()?;
    let app = inner.ensure_app()?;
    // Subscribing only enables receiving; a route is what lets this member
    // broadcast back to the room.
    app.set_route(Arc::new(parse_name(&channel)?), connection_id)
        .map_err(slim_err)?;

    let session = app
        .listen_for_session(timeout_secs.map(Duration::from_secs))
        .map_err(slim_err)?;
    let actual = session.destination().map_err(slim_err)?.to_string();
    if actual != expected.to_string() {
        let _ = app.delete_session_and_wait(session);
        return Err(format!(
            "received session for {actual} while waiting for {expected}"
        ));
    }

    match inner.rooms.get_mut(&actual) {
        // Rejoin: keep the role and roster this room already carries.
        Some(room) => room.session = Some(session),
        None => {
            inner.rooms.insert(
                actual.clone(),
                Room {
                    session: Some(session),
                    moderator: false,
                    admitted: HashMap::new(),
                },
            );
        }
    }
    inner.persist()?;
    inner.group_info(&actual)
    })
    .await
}

/// Every known room, moderator or participant, connected or not — rooms
/// restored from the store appear here with `connected: false`.
///
/// Has no `shadictl` equivalent — the shell holds one session slot and has no
/// notion of a rooms overview.
#[tauri::command]
pub async fn slim_group_list(
    state: tauri::State<'_, SlimState>,
) -> Result<Vec<SlimGroupInfo>, String> {
    with_state(&state, |inner| {
        let mut channels: Vec<&String> = inner.rooms.keys().collect();
        channels.sort();
        channels
            .into_iter()
            .map(|channel| inner.group_info(channel))
            .collect()
    })
    .await
}

/// Re-read a room's membership roster on demand.
#[tauri::command]
pub async fn slim_group_roster(
    state: tauri::State<'_, SlimState>,
    channel: String,
) -> Result<Vec<SlimGroupMember>, String> {
    with_state(&state, move |inner| inner.roster(&channel)).await
}

/// Remove a member from a room. Moderator-only.
#[tauri::command]
pub async fn slim_group_remove_member(
    state: tauri::State<'_, SlimState>,
    channel: String,
    member_name: String,
) -> Result<SlimGroupInfo, String> {
    with_state(&state, move |inner| {
    if !inner.room(&channel)?.moderator {
        return Err(format!(
            "only the moderator of '{channel}' can remove members"
        ));
    }
    inner
        .live_session(&channel)?
        .remove_and_wait(Arc::new(parse_name(&member_name)?))
        .map_err(slim_err)?;

    if let Some(room) = inner.rooms.get_mut(&channel) {
        room.admitted.remove(&member_name);
    }
    inner.persist()?;
    inner.group_info(&channel)
    })
    .await
}

/// Drop a room from the known list, tearing down its session if connected.
///
/// Persisting rooms means they otherwise accumulate with no way to remove one.
/// This is local bookkeeping — it does not remove anyone else from the group.
#[tauri::command]
pub async fn slim_group_forget(
    state: tauri::State<'_, SlimState>,
    channel: String,
) -> Result<Vec<SlimGroupInfo>, String> {
    with_state(&state, move |inner| {
        let room = inner
            .rooms
            .remove(&channel)
            .ok_or_else(|| format!("no room '{channel}'"))?;

        // Best-effort teardown: the room is already gone from the list, so a
        // failure here must not resurrect it or fail the call.
        if let (Some(session), Some(app)) = (room.session, inner.app.clone()) {
            let _ = app.delete_session_and_wait(session);
        }
        inner.subscribed_channels.retain(|c| c != &channel);

        inner.persist()?;
        let mut channels: Vec<String> = inner.rooms.keys().cloned().collect();
        channels.sort();
        channels
            .iter()
            .map(|channel| inner.group_info(channel))
            .collect()
    })
    .await
}

// --- Controller --------------------------------------------------------------

/// List connections known to a controller endpoint.
#[tauri::command]
pub async fn slim_controller_list_connections(
    endpoint: String,
) -> Result<Vec<SlimConnection>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let request = ControlMessage {
            message_id: uuid::Uuid::new_v4().to_string(),
            payload: Some(control_message::Payload::ConnectionListRequest(
                ConnectionListRequest {},
            )),
        };
        match controller_request(&endpoint, request)?.payload {
            Some(control_message::Payload::ConnectionListResponse(list)) => {
                Ok(connection_rows(&list))
            }
            Some(other) => Err(format!("unexpected response payload: {other:?}")),
            None => Err("controller returned an empty response".to_string()),
        }
    })
    .await
    .map_err(|e| format!("task failed: {e}"))?
}

/// List routes known to a controller endpoint.
#[tauri::command]
pub async fn slim_controller_list_routes(endpoint: String) -> Result<Vec<SlimRoute>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let request = ControlMessage {
            message_id: uuid::Uuid::new_v4().to_string(),
            payload: Some(control_message::Payload::RouteListRequest(
                RouteListRequest {},
            )),
        };
        match controller_request(&endpoint, request)?.payload {
            Some(control_message::Payload::RouteListResponse(list)) => Ok(route_rows(&list)),
            Some(other) => Err(format!("unexpected response payload: {other:?}")),
            None => Err("controller returned an empty response".to_string()),
        }
    })
    .await
    .map_err(|e| format!("task failed: {e}"))?
}

fn connection_rows(list: &ConnectionListResponse) -> Vec<SlimConnection> {
    list.entries
        .iter()
        .map(|entry| SlimConnection {
            id: entry.id.to_string(),
            endpoint: entry.link_id.clone().unwrap_or_default(),
        })
        .collect()
}

/// One row per (route, connection) pair — a route can be reachable via several
/// connections, and `SlimRoute` carries a single `via`.
fn route_rows(list: &RouteListResponse) -> Vec<SlimRoute> {
    list.entries
        .iter()
        .flat_map(|entry| {
            let destination = entry
                .name
                .as_ref()
                .map(describe_proto_name)
                .unwrap_or_else(|| "<unknown>".to_string());
            entry.connections.iter().map(move |c| SlimRoute {
                destination: destination.clone(),
                via: c.id.to_string(),
            })
        })
        .collect()
}

fn controller_request(
    endpoint: &str,
    request: ControlMessage,
) -> Result<ControlMessage, String> {
    let runtime = TokioRuntimeBuilder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| format!("failed to create tokio runtime: {err}"))?;

    // rustls needs one process-level CryptoProvider. Use slim_config's own
    // `Once`-guarded installer — the SLIM stack assumes aws-lc-rs and two
    // backends racing to install first breaks other rustls connections.
    slim_config::tls::provider::initialize_crypto_provider();

    let endpoint = endpoint.to_string();
    runtime.block_on(async move {
        let config = build_core_client_config(&endpoint)?;
        let channel = match config
            .to_channel()
            .await
            .map_err(|err| format!("failed to build controller channel: {err}"))?
        {
            TransportChannel::Grpc(channel) => channel,
            TransportChannel::Websocket(_) => {
                return Err("controller endpoint must be a gRPC endpoint".to_string())
            }
        };

        let mut client = ControllerServiceClient::new(channel);
        let mut inbound = client
            .open_control_channel(futures::stream::once(async move { request }))
            .await
            .map_err(|err| format!("failed to open control channel: {err}"))?
            .into_inner();

        tokio::time::timeout(
            Duration::from_secs(CONTROLLER_TIMEOUT_SECONDS),
            futures::StreamExt::next(&mut inbound),
        )
        .await
        .map_err(|_| {
            format!("timed out after {CONTROLLER_TIMEOUT_SECONDS}s waiting for controller response")
        })?
        .ok_or_else(|| "controller closed the stream without a response".to_string())?
        .map_err(|status| format!("controller returned an error: {status}"))
    })
}

fn describe_proto_name(name: &ProtoName) -> String {
    let Some(s) = name.str_name.as_ref() else {
        return "<encoded-name>".to_string();
    };
    let base = format!(
        "{}/{}/{}",
        s.str_component_0, s.str_component_1, s.str_component_2
    );
    match name.name.as_ref().map(|encoded| encoded.id()) {
        Some(id) if id != NameId::NULL_COMPONENT => format!("{base}/{id}"),
        _ => base,
    }
}

// --- Member resolution -------------------------------------------------------

fn is_member_spec(spec: &str) -> bool {
    spec.starts_with("skill:") || spec.starts_with("did:") || spec.starts_with("explicit:")
}

/// Whether a spec has to be resolved against the Agent Directory. `explicit:`
/// already names `{name, did, endpoint}`, so it resolves without a server.
fn spec_needs_directory(spec: &str) -> bool {
    spec.starts_with("skill:") || spec.starts_with("did:")
}


/// Resolve `--members`-style specs into members. Directory-discovered
/// candidates are agents; an `explicit:` entry names a member by hand and is
/// treated as human — see [`SlimGroupMember::kind`].
fn resolve_candidates(
    specs: &[String],
    dir_server: &str,
) -> Result<Vec<(SlimGroupMember, Option<String>)>, String> {
    use agentbridge::member_source::{resolve_members, DirLookupOptions};

    let mut out = Vec::new();
    for spec in specs {
        let kind = if spec.starts_with("explicit:") {
            "human"
        } else {
            "agent"
        };
        let candidates = resolve_members(
            std::slice::from_ref(spec),
            &DirLookupOptions {
                server_addr: dir_server.to_string(),
                gh_token: std::env::var("GITHUB_TOKEN").ok(),
                limit: 20,
            },
        )?;
        out.extend(candidates.into_iter().map(|c| {
            (
                SlimGroupMember {
                    name: c.name,
                    did: c.did,
                    endpoint: c.slim_endpoint.clone(),
                    kind: kind.to_string(),
                },
                c.slim_endpoint,
            )
        }));
    }
    Ok(out)
}

/// Union DIDs into the `SLIM_MEMBER_DIDS` allow-list, as `shadictl slim
/// create-group` does.
///
/// This mutates process-global env, which the CLI gets away with because each
/// invocation is a fresh process. Here it is shared by every command in the
/// app; it is only ever additive (union, never replace) so concurrent
/// admissions cannot drop each other's DIDs.
fn admit_dids_to_trust_set<'a>(dids: impl Iterator<Item = &'a str>) {
    let mut all: Vec<String> = std::env::var("SLIM_MEMBER_DIDS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    all.extend(dids.filter(|d| !d.is_empty()).map(str::to_owned));
    all.sort();
    all.dedup();
    if !all.is_empty() {
        std::env::set_var("SLIM_MEMBER_DIDS", all.join(","));
    }
}

// --- Config / TLS ------------------------------------------------------------

struct TlsMaterial {
    cert: PathBuf,
    key: PathBuf,
    ca: PathBuf,
}

fn group_session_config() -> SessionConfig {
    SessionConfig {
        session_type: SessionType::Group,
        mls_settings: Some(MlsSettings::default()),
        max_retries: Some(5),
        interval: Some(Duration::from_secs(5)),
        metadata: HashMap::new(),
    }
}

fn build_client_config() -> Result<ClientConfig, String> {
    let tls = resolve_client_tls_material()?;
    Ok(ClientConfig {
        endpoint: client_endpoint_value(&resolve_endpoint()),
        tls: TlsClientConfig {
            insecure: false,
            insecure_skip_verify: false,
            source: TlsSource::File {
                cert: tls.cert.display().to_string(),
                key: tls.key.display().to_string(),
            },
            ca_source: CaSource::File {
                path: tls.ca.display().to_string(),
            },
            include_system_ca_certs_pool: false,
            tls_version: "tls1.3".to_string(),
        },
        ..Default::default()
    })
}

fn build_server_config() -> Result<ServerConfig, String> {
    let dir = slim_tls_dir();
    let tls = TlsMaterial {
        cert: dir.join("server.crt"),
        key: dir.join("server.key"),
        ca: dir.join("ca.crt"),
    };
    ensure_file_exists(&tls.cert, "SLIM server certificate")?;
    ensure_file_exists(&tls.key, "SLIM server key")?;
    ensure_file_exists(&tls.ca, "SLIM client CA")?;

    Ok(ServerConfig {
        endpoint: resolve_endpoint(),
        tls: TlsServerConfig {
            insecure: false,
            source: TlsSource::File {
                cert: tls.cert.display().to_string(),
                key: tls.key.display().to_string(),
            },
            client_ca: CaSource::File {
                path: tls.ca.display().to_string(),
            },
            include_system_ca_certs_pool: Some(false),
            tls_version: Some("tls1.3".to_string()),
            reload_client_ca_file: Some(false),
        },
        ..Default::default()
    })
}

fn build_core_client_config(endpoint: &str) -> Result<CoreClientConfig, String> {
    let tls = resolve_client_tls_material()?;
    Ok(
        CoreClientConfig::with_endpoint(&client_endpoint_value(endpoint)).with_tls_setting(
            CoreTlsClientConfig {
                config: CoreTlsConfig {
                    source: CoreTlsSource::File {
                        cert: tls.cert.display().to_string(),
                        key: tls.key.display().to_string(),
                    },
                    ca_source: CoreCaSource::File {
                        path: tls.ca.display().to_string(),
                    },
                    include_system_ca_certs_pool: false,
                    tls_version: "tls1.3".to_string(),
                    reload_interval: None,
                },
                insecure: false,
                insecure_skip_verify: false,
            },
        ),
    )
}

fn resolve_client_tls_material() -> Result<TlsMaterial, String> {
    let cert_override = std::env::var_os("SLIM_TLS_CERT").map(PathBuf::from);
    let key_override = std::env::var_os("SLIM_TLS_KEY").map(PathBuf::from);
    let ca = std::env::var_os("SLIM_TLS_CA")
        .map(PathBuf::from)
        .unwrap_or_else(|| slim_tls_dir().join("ca.crt"));
    let agent_id = std::env::var("SHADI_AGENT_ID")
        .ok()
        .filter(|v| !v.trim().is_empty());

    let (cert, key) = match (cert_override, key_override) {
        (Some(cert), Some(key)) => (cert, key),
        (Some(_), None) | (None, Some(_)) => {
            return Err("SLIM_TLS_CERT and SLIM_TLS_KEY must be set together".to_string())
        }
        (None, None) => {
            let dir = slim_tls_dir();
            client_identity_candidates(&dir, agent_id.as_deref())
                .into_iter()
                .find(|(cert, key)| cert.is_file() && key.is_file())
                .ok_or_else(|| {
                    let checked = client_identity_candidates(&dir, agent_id.as_deref())
                        .into_iter()
                        .map(|(c, k)| format!("{} + {}", c.display(), k.display()))
                        .collect::<Vec<_>>()
                        .join(", ");
                    format!(
                        "no SLIM client certificate found; checked {checked}. Set SHADI_AGENT_ID \
                         or SLIM_TLS_CERT/SLIM_TLS_KEY explicitly"
                    )
                })?
        }
    };

    ensure_file_exists(&cert, "SLIM client certificate")?;
    ensure_file_exists(&key, "SLIM client key")?;
    ensure_file_exists(&ca, "SLIM client CA")?;
    Ok(TlsMaterial { cert, key, ca })
}

fn client_identity_candidates(dir: &Path, agent_id: Option<&str>) -> Vec<(PathBuf, PathBuf)> {
    let mut candidates = Vec::new();
    if let Some(agent_id) = agent_id {
        candidates.push((
            dir.join(format!("client-{agent_id}.crt")),
            dir.join(format!("client-{agent_id}.key")),
        ));
    }
    candidates.push((dir.join("client.crt"), dir.join("client.key")));
    candidates
}

// --- Small helpers -----------------------------------------------------------

fn slim_err(err: slim_bindings::SlimError) -> String {
    err.to_string()
}

fn node_service_name() -> String {
    format!("shadi-desktop-node-{}", std::process::id())
}

fn client_service_name() -> String {
    format!("shadi-desktop-client-{}", std::process::id())
}

fn resolve_endpoint() -> String {
    std::env::var("SLIM_ENDPOINT").unwrap_or_else(|_| DEFAULT_SLIM_ENDPOINT.to_string())
}

fn client_endpoint_value(endpoint: &str) -> String {
    if endpoint.contains("://") {
        endpoint.to_string()
    } else {
        format!("https://{endpoint}")
    }
}

fn resolve_local_name() -> Result<String, String> {
    if let Ok(custom) = std::env::var("SHADI_SLIM_LOCAL_NAME") {
        if custom.trim().is_empty() {
            return Err("SHADI_SLIM_LOCAL_NAME cannot be empty".to_string());
        }
        return Ok(custom);
    }
    let app = std::env::var("SHADI_AGENT_ID")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_LOCAL_APP.to_string());
    Ok(format!("{DEFAULT_LOCAL_ORG}/{DEFAULT_LOCAL_NAMESPACE}/{app}"))
}

fn parse_name(raw: &str) -> Result<Name, String> {
    Name::from_string(raw.to_string()).map_err(|err| {
        format!("invalid SLIM name {raw}: {err} (expected organization/namespace/application)")
    })
}

fn slim_tls_dir() -> PathBuf {
    std::env::var_os("SHADI_TMP_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".tmp"))
        .join("shadi-slim-mtls")
}

fn ensure_file_exists(path: &Path, label: &str) -> Result<(), String> {
    if path.is_file() {
        Ok(())
    } else {
        Err(format!("{label} not found at {}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(name: &str, kind: &str) -> SlimGroupMember {
        SlimGroupMember {
            name: name.to_string(),
            did: format!("did:key:z6Mk{name}"),
            endpoint: Some("127.0.0.1:47357".to_string()),
            kind: kind.to_string(),
        }
    }

    fn room_with(moderator: bool, members: Vec<SlimGroupMember>) -> Room {
        Room {
            // No live session: exactly the shape a restored room has.
            session: None,
            moderator,
            admitted: members
                .into_iter()
                .map(|m| (m.name.clone(), m))
                .collect(),
        }
    }

    fn store_path() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "shadi-desktop-rooms-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir.join("nested").join("rooms.json")
    }

    /// The core of agntcy/shadi#138: a room written before "restart" comes
    /// back with its role and roster intact, and reports itself disconnected.
    #[test]
    fn known_rooms_survive_a_restart() {
        let path = store_path();
        let _ = std::fs::remove_file(&path);

        let before = SlimState::default();
        {
            let mut inner = before.0.lock().unwrap_or_else(|e| e.into_inner());
            inner.store_path = Some(path.clone());
            inner.rooms.insert(
                "agntcy/shadi/review".to_string(),
                room_with(true, vec![member("agntcy/shadi/bot", "agent")]),
            );
            inner.rooms.insert(
                "agntcy/shadi/standup".to_string(),
                room_with(false, vec![member("agntcy/shadi/lead", "human")]),
            );
            // Writes through a directory that doesn't exist yet.
            inner.persist().expect("persist");
        }

        let after = SlimState::default();
        after.init_store(path.clone()).expect("init store");
        let inner = after.0.lock().unwrap_or_else(|e| e.into_inner());

        let review = inner.group_info("agntcy/shadi/review").expect("review room");
        assert_eq!(review.role, "moderator");
        assert!(!review.connected, "a restored room has no live session");
        assert_eq!(review.members.len(), 1);
        assert_eq!(review.members[0].name, "agntcy/shadi/bot");
        assert_eq!(review.members[0].kind, "agent");
        assert_eq!(review.members[0].did, "did:key:z6Mkagntcy/shadi/bot");
        assert_eq!(
            review.members[0].endpoint.as_deref(),
            Some("127.0.0.1:47357"),
            "endpoint must survive — coordinate specs are built from it"
        );

        // Role and the human/agent label are per-room, not global.
        let standup = inner.group_info("agntcy/shadi/standup").expect("standup room");
        assert_eq!(standup.role, "participant");
        assert_eq!(standup.members[0].kind, "human");

        std::fs::remove_file(&path).ok();
    }

    /// A disconnected room is readable but not modifiable: `live_session`
    /// gates invite/remove, and says what to do about it.
    #[test]
    fn disconnected_room_is_readable_but_not_modifiable() {
        let state = SlimState::default();
        let mut inner = state.0.lock().unwrap_or_else(|e| e.into_inner());
        inner.rooms.insert(
            "agntcy/shadi/review".to_string(),
            room_with(true, vec![member("agntcy/shadi/bot", "agent")]),
        );

        // Roster works without a session.
        assert_eq!(inner.roster("agntcy/shadi/review").unwrap().len(), 1);

        // `unwrap_err` would require the Ok type (Arc<Session>) to be Debug.
        let err = match inner.live_session("agntcy/shadi/review") {
            Ok(_) => panic!("a room with no session must not yield one"),
            Err(err) => err,
        };
        assert!(err.contains("not connected"), "unexpected: {err}");
        assert!(err.contains("rejoin"), "should say how to fix it: {err}");
    }

    #[test]
    fn unknown_room_is_distinguished_from_disconnected_one() {
        let state = SlimState::default();
        let inner = state.0.lock().unwrap_or_else(|e| e.into_inner());
        let err = match inner.room("agntcy/shadi/nope") {
            Ok(_) => panic!("unknown room must not resolve"),
            Err(err) => err,
        };
        assert!(err.contains("no room"), "unexpected: {err}");
    }

    /// Persisting with no store configured must not fail — that is the state
    /// during tests and if the app data dir can't be resolved.
    #[test]
    fn persist_without_a_store_is_a_no_op() {
        let state = SlimState::default();
        let mut inner = state.0.lock().unwrap_or_else(|e| e.into_inner());
        inner
            .rooms
            .insert("agntcy/shadi/review".to_string(), room_with(true, vec![]));
        assert!(inner.persist().is_ok());
    }

    /// A missing store is a first launch, not an error.
    #[test]
    fn init_store_tolerates_a_missing_file() {
        let state = SlimState::default();
        let missing = std::env::temp_dir().join("shadi-desktop-definitely-absent.json");
        let _ = std::fs::remove_file(&missing);
        assert!(state.init_store(missing).is_ok());
        assert!(state.0.lock().unwrap_or_else(|e| e.into_inner()).rooms.is_empty());
    }

    /// Pins the invariant that makes this whole module work.
    ///
    /// Every blocking `slim_bindings` call is `get_runtime().block_on(..)`.
    /// Invoked straight from an `async` command it lands on a Tauri async
    /// worker and panics — "Cannot start a runtime from within a runtime" —
    /// which made the panel compile, pass its tests, and then die on the first
    /// real SLIM call. `with_state` exists to move that work off the runtime.
    ///
    /// Needs no node: connecting nowhere must come back as `Err`, and the point
    /// is that it comes back at all instead of unwinding.
    #[test]
    fn blocking_slim_calls_survive_inside_an_async_runtime() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build runtime");

        rt.block_on(async {
            let outcome = tokio::task::spawn_blocking(|| {
                let service = Service::new("shadi-desktop-runtime-invariant".to_string());
                service.connect(ClientConfig::default()).is_err()
            })
            .await;

            match outcome {
                Ok(errored) => assert!(errored, "connecting to nowhere should return Err"),
                Err(join) if join.is_panic() => panic!(
                    "blocking SLIM call panicked inside the async runtime — the \
                     spawn_blocking hop in with_state is missing or ineffective"
                ),
                Err(join) => panic!("blocking task failed: {join}"),
            }
        });
    }

    /// Live end-to-end coverage of the room admin surface against a real SLIM
    /// node with real DID auth — create a room as moderator, invite two waiting
    /// agents, read the roster, then reload the store as a restart would.
    ///
    /// Ignored by default: needs a running node, mTLS material and the DID env
    /// contract, so CI skips it. `docs/content/demos/desktop-room-e2e.sh` sets
    /// all of that up and runs it.
    ///
    /// This is the coverage whose absence let the runtime panic ship: the panel
    /// compiled with a green suite and still died on its first real SLIM call.
    #[test]
    #[ignore = "needs a live SLIM node; run docs/content/demos/desktop-room-e2e.sh"]
    fn live_moderator_creates_room_invites_two_agents_and_sees_the_roster() {
        let channel = std::env::var("SHADI_E2E_ROOM").expect("SHADI_E2E_ROOM");
        let members: Vec<String> = std::env::var("SHADI_E2E_MEMBERS")
            .expect("SHADI_E2E_MEMBERS")
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        assert_eq!(members.len(), 2, "expects exactly two agents");

        let store = std::env::temp_dir().join("shadi-desktop-e2e-rooms.json");
        let _ = std::fs::remove_file(&store);

        let state = SlimState::default();
        {
            let mut inner = state.0.lock().unwrap_or_else(|e| e.into_inner());
            inner.store_path = Some(store.clone());

            // slim_group_create's core: DID connect, build app, open the group.
            let channel_name = Arc::new(parse_name(&channel).expect("channel name"));
            let app = inner.ensure_app().expect("ensure_app: DID auth + connect");
            let session = app
                .create_session_and_wait(group_session_config(), channel_name.clone())
                .expect("create group session");
            inner.rooms.insert(
                channel_name.to_string(),
                Room {
                    session: Some(session),
                    moderator: true,
                    admitted: HashMap::new(),
                },
            );
            inner.persist().expect("persist after create");

            let info = inner.group_info(&channel).expect("group info");
            assert_eq!(info.role, "moderator");
            assert!(info.connected, "a freshly created room is connected");

            // Participants can only be invited once they're already listening;
            // the harness starts them right after this test creates the room.
            std::thread::sleep(Duration::from_secs(12));

            // slim_group_invite's core.
            let connection_id = inner.ensure_connection().expect("connection");
            for member in &members {
                let name = Arc::new(parse_name(member).expect("member name"));
                let session = inner.live_session(&channel).expect("live session");
                app.set_route(name.clone(), connection_id).expect("set route");
                session
                    .invite_and_wait(name)
                    .unwrap_or_else(|e| panic!("invite {member} failed: {e}"));
                inner.rooms.get_mut(&channel).unwrap().admitted.insert(
                    member.clone(),
                    SlimGroupMember {
                        name: member.clone(),
                        did: String::new(),
                        endpoint: None,
                        kind: "agent".to_string(),
                    },
                );
            }
            inner.persist().expect("persist after invites");

            // Roster reads the live session's participants_list.
            let roster = inner.roster(&channel).expect("roster");
            let names: Vec<&str> = roster.iter().map(|m| m.name.as_str()).collect();
            for member in &members {
                assert!(
                    names.iter().any(|n| n == member),
                    "{member} missing from live roster {names:?}"
                );
            }
        }

        // Reload as a restart would (#138): known, not connected, roster intact.
        let restarted = SlimState::default();
        restarted.init_store(store.clone()).expect("reload store");
        let inner = restarted.0.lock().unwrap_or_else(|e| e.into_inner());
        let restored = inner.group_info(&channel).expect("restored room");
        assert!(!restored.connected, "a restored room has no live session");
        assert_eq!(restored.role, "moderator");
        let restored_names: Vec<&str> = restored.members.iter().map(|m| m.name.as_str()).collect();
        for member in &members {
            assert!(
                restored_names.iter().any(|n| n == member),
                "{member} did not survive the restart: {restored_names:?}"
            );
        }

        let _ = std::fs::remove_file(&store);
    }

    #[test]
    fn member_specs_are_recognised() {
        assert!(is_member_spec("skill:agent_orchestration/agent_coordination"));
        assert!(is_member_spec("did:key:z6Mk"));
        assert!(is_member_spec("explicit:alice=did:key:z6Mk"));
        assert!(!is_member_spec("agntcy/shadi/reviewer"));
    }

    #[test]
    fn only_directory_backed_specs_need_a_server() {
        assert!(spec_needs_directory("skill:agent_orchestration/x"));
        assert!(spec_needs_directory("did:key:z6Mk"));
        // `explicit:` already carries the DID — requiring a DIR server for it
        // would block admitting an already-discovered candidate.
        assert!(!spec_needs_directory("explicit:alice=did:key:z6Mk"));
        assert!(!spec_needs_directory("agntcy/shadi/reviewer"));
    }

    /// Guards the wire format the frontend's `explicitMemberSpec`
    /// (`src/shared/rooms.tsx`) emits when admitting a discovered adapter: it
    /// must resolve locally, DID and endpoint intact, with no Directory server.
    /// Keep these literals in step with that function.
    #[test]
    fn frontend_explicit_spec_format_resolves_without_a_directory() {
        use agentbridge::member_source::{parse_member_spec, DirLookupOptions};

        let dir = DirLookupOptions {
            server_addr: String::new(),
            gh_token: None,
            limit: 1,
        };

        let with_endpoint = "explicit:agntcy/shadi/reviewer=did:key:z6MkTest@127.0.0.1:47357";
        let resolved = parse_member_spec(with_endpoint, &dir)
            .expect("spec parses")
            .resolve()
            .expect("explicit source resolves locally");
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].name, "agntcy/shadi/reviewer");
        assert_eq!(resolved[0].did, "did:key:z6MkTest");
        assert_eq!(resolved[0].slim_endpoint.as_deref(), Some("127.0.0.1:47357"));

        // Endpoint is omitted entirely when unknown, not left as a bare `@`.
        let no_endpoint = "explicit:agntcy/shadi/reviewer=did:key:z6MkTest";
        let resolved = parse_member_spec(no_endpoint, &dir)
            .expect("spec parses")
            .resolve()
            .expect("explicit source resolves locally");
        assert_eq!(resolved[0].did, "did:key:z6MkTest");
        assert!(resolved[0].slim_endpoint.is_none());
    }

    #[test]
    fn parse_name_requires_three_components() {
        assert!(parse_name("agntcy/shadi/reviewer").is_ok());
        assert!(parse_name("not-a-name").is_err());
    }

    #[test]
    fn client_endpoint_value_adds_scheme_once() {
        assert_eq!(client_endpoint_value("127.0.0.1:47357"), "https://127.0.0.1:47357");
        assert_eq!(client_endpoint_value("https://host:1"), "https://host:1");
    }

    #[test]
    fn agent_id_specific_client_cert_is_preferred() {
        let candidates = client_identity_candidates(Path::new("/certs"), Some("reviewer"));
        assert_eq!(candidates[0].0, Path::new("/certs/client-reviewer.crt"));
        assert_eq!(candidates[1].0, Path::new("/certs/client.crt"));
    }

    #[test]
    fn local_name_defaults_to_agntcy_shadi_agent() {
        // Only valid when neither env var is set; assert the shape it builds.
        let name = format!("{DEFAULT_LOCAL_ORG}/{DEFAULT_LOCAL_NAMESPACE}/{DEFAULT_LOCAL_APP}");
        assert_eq!(name, "agntcy/shadi/agent");
    }
}
