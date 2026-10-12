// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Rooms owned through a SLIM channel manager (agntcy/shadi#442).
//!
//! With a channel manager configured, the Desktop creates rooms through its
//! API as their owner: create and delete requests are signed with the owner
//! key, so the channel manager records the owner's `did:key` and checks the
//! grants it signs, the owner's own adds and removes included. When someone
//! else asks to add or remove a participant, the channel manager calls the
//! owner's `ChannelOwnerApproval/RequestApproval` over SlimRPC from its
//! approval identity; the standing rules and inbox decide, as for an agent's
//! A2A ask.

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentbridge::owner::{InviteRequest, Outcome, Owner};
use prost::Message as _;
use serde::{Deserialize, Serialize};
use shadi_identity::channel_request::{sign_create, sign_delete, ChannelCreation};
use shadi_identity::{issue_grant, AgentIdentity, GrantAction, GrantRole};
use slim_auth::jwt::{Algorithm, Key, KeyData, KeyFormat};
use slim_config::auth::jwt::{Claims, Config as JwtConfig, JwtKey};
use slim_config::client::{AuthenticationConfig, ClientConfig};
use slim_config::grpc::client::TransportChannel;
use slim_config::tls::client::TlsClientConfig;
use slim_proto::channel_manager::proto::v1 as cm;
use tauri::Manager;
use tokio::sync::oneshot;

use super::slim::SlimState;

const CONFIG_FILE: &str = "channel-manager.json";
pub const APPROVAL_SERVICE: &str = "channel_manager.proto.v1.ChannelOwnerApproval";
pub const APPROVAL_METHOD: &str = "RequestApproval";
/// The channel manager treats an owner who hasn't answered in 60 s as a
/// denial, so an ask is answered before then.
const ANSWER_WITHIN_SECONDS: u64 = 55;
const API_TIMEOUT: Duration = Duration::from_secs(10);
/// A participant change can wait the channel manager's 60 s for the owner,
/// then for the invite.
const PARTICIPANT_TIMEOUT: Duration = Duration::from_secs(90);
const TOKEN_TTL: Duration = Duration::from_secs(300);
/// How long a signed request or the owner's own grant is good for.
const SIGNED_FOR_SECONDS: u64 = 300;

/// Where the channel manager is. Saved in `channel-manager.json`, or given as
/// `SHADI_CHANNEL_MANAGER_ENDPOINT`, `SHADI_CHANNEL_MANAGER_NAME` and
/// `SHADI_CHANNEL_MANAGER_APPROVAL_DID`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelManagerConfig {
    /// Its API, e.g. `http://127.0.0.1:10356`.
    pub endpoint: String,
    /// Its SLIM `local-name`. Approval requests come from `<name>-approval`.
    pub name: String,
    /// A CA to verify a TLS API with; an `http://` endpoint needs none.
    #[serde(default)]
    pub ca_file: Option<String>,
    /// The `did:key` it logs as its "Owner approval identity". Approval
    /// requests from any other identity are refused.
    #[serde(default)]
    pub approval_did: Option<String>,
    /// Its `audience`, when not its `name`: what signed requests name.
    #[serde(default)]
    pub audience: Option<String>,
    /// A bearer token for its API. Without one, API calls carry a token
    /// signed with the owner key.
    #[serde(default)]
    pub api_token_file: Option<String>,
}

impl ChannelManagerConfig {
    fn validate(&self) -> Result<(), String> {
        if !(self.endpoint.starts_with("http://") || self.endpoint.starts_with("https://")) {
            return Err(format!(
                "endpoint {:?} must be an http:// or https:// URL",
                self.endpoint
            ));
        }
        let parts: Vec<&str> = self.name.split('/').collect();
        if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
            return Err(format!("name {:?} is not org/namespace/app", self.name));
        }
        let did = self.approval_did.as_deref().ok_or_else(|| {
            "set its approval identity, the did:key it logs at startup".to_string()
        })?;
        shadi_identity::parse_did_key(did)
            .map_err(|e| format!("approval identity {did:?}: {e}"))?;
        if self.audience.as_deref().is_some_and(str::is_empty) {
            return Err("audience is empty".to_string());
        }
        Ok(())
    }

    fn audience(&self) -> &str {
        self.audience.as_deref().unwrap_or(&self.name)
    }

    fn from_env() -> Option<Self> {
        let endpoint = std::env::var("SHADI_CHANNEL_MANAGER_ENDPOINT").ok()?;
        let name = std::env::var("SHADI_CHANNEL_MANAGER_NAME").ok()?;
        let var = |key: &str| std::env::var(key).ok();
        Some(Self {
            endpoint,
            name,
            ca_file: var("SHADI_CHANNEL_MANAGER_CA"),
            approval_did: var("SHADI_CHANNEL_MANAGER_APPROVAL_DID"),
            audience: var("SHADI_CHANNEL_MANAGER_AUDIENCE"),
            api_token_file: var("SHADI_CHANNEL_MANAGER_TOKEN_FILE"),
        })
    }
}

/// Registered with `.manage(...)`.
#[derive(Default)]
pub struct ChannelManagerState {
    config: Mutex<Option<ChannelManagerConfig>>,
    path: Mutex<Option<PathBuf>>,
    /// The channels the channel manager last listed with this owner, so the
    /// owner holds them between listings.
    owned: Mutex<BTreeSet<String>>,
}

impl ChannelManagerState {
    /// Load the saved config; the environment wins when it is set.
    pub fn init(&self, dir: PathBuf) -> Result<(), String> {
        let path = dir.join(CONFIG_FILE);
        let config = match ChannelManagerConfig::from_env() {
            Some(config) => Some(config),
            None => match std::fs::read_to_string(&path) {
                Ok(text) => Some(
                    serde_json::from_str(&text)
                        .map_err(|e| format!("invalid {}: {e}", path.display()))?,
                ),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
                Err(err) => return Err(format!("{}: {err}", path.display())),
            },
        };
        *self.path.lock().map_err(|_| "state poisoned")? = Some(path);
        *self.config.lock().map_err(|_| "state poisoned")? = config;
        Ok(())
    }

    pub fn config(&self) -> Option<ChannelManagerConfig> {
        self.config.lock().ok()?.clone()
    }

    fn require(&self) -> Result<ChannelManagerConfig, String> {
        self.config()
            .ok_or_else(|| "no channel manager is configured".to_string())
    }

    pub fn owned(&self) -> Vec<String> {
        self.owned
            .lock()
            .map(|owned| owned.iter().cloned().collect())
            .unwrap_or_default()
    }

    fn set_owned(&self, channels: impl IntoIterator<Item = String>) {
        if let Ok(mut owned) = self.owned.lock() {
            *owned = channels.into_iter().collect();
        }
    }
}

// --- API ---------------------------------------------------------------------

enum Call {
    Create(cm::CreateChannelRequest),
    Delete(cm::DeleteChannelRequest),
    Add(cm::AddParticipantRequest),
    Remove(cm::DeleteParticipantRequest),
    ListChannels,
    ListParticipants(String),
}

enum Reply {
    Done,
    Channels(Vec<cm::ChannelInfo>),
    Participants(Vec<String>),
}

fn api_client_config(
    config: &ChannelManagerConfig,
    owner: &AgentIdentity,
) -> Result<ClientConfig, String> {
    let tls = match &config.ca_file {
        Some(ca) => TlsClientConfig::new().with_ca_file(ca),
        None => TlsClientConfig::insecure(),
    };
    let client = ClientConfig::with_endpoint(&config.endpoint).with_tls_setting(tls);
    if let Some(file) = &config.api_token_file {
        return Ok(client.with_auth(AuthenticationConfig::StaticJwt(
            slim_config::auth::static_jwt::Config::with_file(file),
        )));
    }
    let did = owner.did();
    let key = Key {
        algorithm: Algorithm::EdDSA,
        format: KeyFormat::Pem,
        key: KeyData::Data(owner.to_pkcs8_pem().map_err(|e| e.to_string())?),
    };
    // Self-issued, like a SHADI DID-JWT. It only authenticates the call:
    // ownership comes from the signed requests.
    let claims = Claims::new(None, Some(did.clone()), Some(did), None);
    Ok(client.with_auth(AuthenticationConfig::Jwt(JwtConfig::new(
        claims,
        TOKEN_TTL,
        JwtKey::Encoding(key),
    ))))
}

/// One API call as the owner. Blocks, so call it off the async runtime.
fn api(config: &ChannelManagerConfig, owner: &AgentIdentity, call: Call) -> Result<Reply, String> {
    let client_config = api_client_config(config, owner)?;
    let timeout = match call {
        Call::Add(_) | Call::Remove(_) => PARTICIPANT_TIMEOUT,
        _ => API_TIMEOUT,
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("failed to create tokio runtime: {e}"))?;
    slim_config::tls::provider::initialize_crypto_provider();
    runtime.block_on(async move {
        let channel = match client_config
            .to_channel()
            .await
            .map_err(|e| format!("channel manager: {e}"))?
        {
            TransportChannel::Grpc(channel) => channel,
            TransportChannel::Websocket(_) => {
                return Err("the channel manager API is gRPC".to_string());
            }
        };
        let mut client =
            cm::channel_manager_service_client::ChannelManagerServiceClient::new(channel);
        let status = |e: tonic::Status| format!("channel manager: {}", e.message());
        let done = |response: cm::CommandResponse| {
            if response.success {
                Ok(Reply::Done)
            } else {
                Err(response.error_msg.unwrap_or_else(|| "refused".to_string()))
            }
        };
        let reply = async {
            match call {
                Call::Create(r) => {
                    done(client.create_channel(r).await.map_err(status)?.into_inner())
                }
                Call::Delete(r) => {
                    done(client.delete_channel(r).await.map_err(status)?.into_inner())
                }
                Call::Add(r) => done(
                    client
                        .add_participant(r)
                        .await
                        .map_err(status)?
                        .into_inner(),
                ),
                Call::Remove(r) => done(
                    client
                        .delete_participant(r)
                        .await
                        .map_err(status)?
                        .into_inner(),
                ),
                Call::ListChannels => {
                    let list = client
                        .list_channels(cm::ListChannelsRequest {})
                        .await
                        .map_err(status)?
                        .into_inner();
                    if !list.success {
                        return Err(list.error_msg.unwrap_or_else(|| "refused".to_string()));
                    }
                    Ok(Reply::Channels(list.channels))
                }
                Call::ListParticipants(channel_name) => {
                    let list = client
                        .list_participants(cm::ListParticipantsRequest { channel_name })
                        .await
                        .map_err(status)?
                        .into_inner();
                    if !list.success {
                        return Err(list.error_msg.unwrap_or_else(|| "refused".to_string()));
                    }
                    Ok(Reply::Participants(list.participant_name))
                }
            }
        };
        tokio::time::timeout(timeout, reply)
            .await
            .map_err(|_| "the channel manager didn't answer in time".to_string())?
    })
}

/// The channels the channel manager lists with `owner_did` as their owner.
fn owned_channels(
    config: &ChannelManagerConfig,
    owner: &AgentIdentity,
) -> Result<Vec<cm::ChannelInfo>, String> {
    let did = owner.did();
    match api(config, owner, Call::ListChannels)? {
        Reply::Channels(channels) => Ok(channels
            .into_iter()
            .filter(|c| c.owner.as_deref() == Some(did.as_str()))
            .collect()),
        _ => Err("unexpected reply".to_string()),
    }
}

/// A create request signed by `owner`, who becomes the room's owner.
fn create_request(
    config: &ChannelManagerConfig,
    owner: &AgentIdentity,
    channel: &str,
    ttl_seconds: Option<u64>,
    callback: &str,
) -> Result<cm::CreateChannelRequest, String> {
    let creation = ChannelCreation {
        audience: config.audience(),
        channel,
        mls_enabled: true,
        ttl_seconds,
        owner_callback_name: Some(callback),
    };
    let owner_proof =
        sign_create(owner, &creation, now() + SIGNED_FOR_SECONDS).map_err(|e| e.to_string())?;
    Ok(cm::CreateChannelRequest {
        channel_name: channel.to_string(),
        mls_enabled: true,
        owner_callback_name: Some(callback.to_string()),
        ttl_seconds,
        owner_proof: Some(owner_proof),
    })
}

fn delete_request(
    config: &ChannelManagerConfig,
    owner: &AgentIdentity,
    channel: &str,
) -> Result<cm::DeleteChannelRequest, String> {
    let owner_proof = sign_delete(
        owner,
        config.audience(),
        channel,
        now() + SIGNED_FOR_SECONDS,
    )
    .map_err(|e| e.to_string())?;
    Ok(cm::DeleteChannelRequest {
        channel_name: channel.to_string(),
        owner_proof: Some(owner_proof),
    })
}

/// Adding (`present`) or removing `participant`, with `owner`'s grant.
fn participant_call(
    owner: &AgentIdentity,
    channel: &str,
    participant: &str,
    present: bool,
) -> Result<Call, String> {
    let action = if present {
        GrantAction::Add
    } else {
        GrantAction::Delete
    };
    let grant = issue_grant(
        owner,
        channel,
        participant,
        action,
        GrantRole::Member,
        now() + SIGNED_FOR_SECONDS,
    )
    .map_err(|e| e.to_string())?;
    let (channel_name, participant_name) = (channel.to_string(), participant.to_string());
    Ok(if present {
        Call::Add(cm::AddParticipantRequest {
            channel_name,
            participant_name,
            grant: Some(grant),
        })
    } else {
        Call::Remove(cm::DeleteParticipantRequest {
            channel_name,
            participant_name,
            grant: Some(grant),
        })
    })
}

// --- Owner approval ------------------------------------------------------------

/// How an approval ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    Grant(Vec<u8>),
    Denied(String),
}

impl From<Answer> for cm::ApprovalResponse {
    fn from(answer: Answer) -> Self {
        let decision = match answer {
            Answer::Grant(grant) => cm::approval_response::Decision::Grant(grant),
            Answer::Denied(reason) => cm::approval_response::Decision::Denied(reason),
        };
        cm::ApprovalResponse {
            decision: Some(decision),
        }
    }
}

/// The channel manager's request as an owner request, or why it is refused.
fn owner_request(request: &cm::ApprovalRequest) -> Result<InviteRequest, String> {
    let action = match cm::ParticipantAction::try_from(request.action) {
        Ok(cm::ParticipantAction::Add) => GrantAction::Add,
        Ok(cm::ParticipantAction::Delete) => GrantAction::Delete,
        _ => return Err(format!("unknown action {}", request.action)),
    };
    Ok(InviteRequest {
        channel: request.channel_name.clone(),
        invitee_name: request.participant_name.clone(),
        invitee_did: None,
        action,
        requester: request
            .requester
            .clone()
            .filter(|r| !r.is_empty())
            .unwrap_or_else(|| "unknown".to_string()),
        requester_human_did: None,
    })
}

/// Whether `caller` (org/namespace/app, plus an id) is the approval app of
/// the channel manager named `name`.
fn is_approval_caller(caller: &str, name: &str) -> bool {
    let caller: Vec<&str> = caller.split('/').take(3).collect();
    caller.join("/") == format!("{name}-approval")
}

/// Refuses an approval request unless it comes from the channel manager's
/// approval app, and the session's verified identity, `peer`, is its approval
/// `did:key`.
fn check_approval_caller(
    config: &ChannelManagerConfig,
    caller: &str,
    peer: Option<&str>,
) -> Result<(), String> {
    if !is_approval_caller(caller, &config.name) {
        return Err(format!("{caller} is not {}-approval", config.name));
    }
    let Some(approval_did) = config.approval_did.as_deref() else {
        return Err("the channel manager's approval identity is not set".to_string());
    };
    match peer {
        Some(peer) if peer == approval_did => Ok(()),
        Some(peer) => Err(format!(
            "{peer} is not the channel manager's approval identity"
        )),
        None => Err("the caller's identity is not verified".to_string()),
    }
}

/// Answers the channel manager for the owner, holding an ask until the owner
/// allows or denies it in the inbox or it runs out of time.
pub struct Approvals {
    owner: Arc<Mutex<Owner>>,
    waiting: Mutex<HashMap<u64, oneshot::Sender<Answer>>>,
    answer_within: u64,
}

impl Approvals {
    pub fn new(owner: Arc<Mutex<Owner>>) -> Self {
        Self {
            owner,
            waiting: Mutex::new(HashMap::new()),
            answer_within: ANSWER_WITHIN_SECONDS,
        }
    }

    /// Whether the channel manager is waiting on `ask_id`.
    pub fn is_waiting(&self, ask_id: u64) -> bool {
        self.waiting
            .lock()
            .map(|waiting| waiting.contains_key(&ask_id))
            .unwrap_or(false)
    }

    /// Answer a waiting ask; false when the channel manager isn't waiting on it.
    pub fn answer(&self, ask_id: u64, answer: Answer) -> bool {
        let sender = self
            .waiting
            .lock()
            .ok()
            .and_then(|mut waiting| waiting.remove(&ask_id));
        sender.is_some_and(|sender| sender.send(answer).is_ok())
    }

    /// Decide `request` for a channel this owner holds per the channel
    /// manager.
    pub async fn decide(&self, request: InviteRequest) -> Answer {
        let asked_at = now();
        let outcome = {
            let mut owner = match self.owner.lock() {
                Ok(owner) => owner,
                Err(_) => return Answer::Denied("the owner is unavailable".to_string()),
            };
            owner.hold(request.channel.clone());
            owner.request_until(request, asked_at, asked_at + self.answer_within)
        };
        let (ask_id, expires_at) = match outcome {
            Ok(Outcome::Granted(grant)) => return Answer::Grant(grant),
            Ok(Outcome::Refused(reason)) => return Answer::Denied(reason),
            Ok(Outcome::Pending { ask_id, expires_at }) => (ask_id, expires_at),
            Err(err) => return Answer::Denied(err.to_string()),
        };
        let (sender, receiver) = oneshot::channel();
        if let Ok(mut waiting) = self.waiting.lock() {
            waiting.insert(ask_id, sender);
        }
        let wait = Duration::from_secs(expires_at.saturating_sub(asked_at));
        match tokio::time::timeout(wait, receiver).await {
            Ok(Ok(answer)) => answer,
            _ => {
                if let Ok(mut waiting) = self.waiting.lock() {
                    waiting.remove(&ask_id);
                }
                if let Ok(mut owner) = self.owner.lock() {
                    let _ = owner.expire(expires_at.max(now()));
                }
                Answer::Denied("the owner didn't answer in time".to_string())
            }
        }
    }
}

/// Serve `RequestApproval` on `server`. The channel manager config and owner
/// key come from `slim` and `channel_manager` on each call, so a config saved
/// later applies without restarting the owner service.
pub fn register_approval(
    server: &slim_rpc::Server,
    approvals: Arc<Approvals>,
    channel_manager: Arc<ChannelManagerState>,
    slim: SlimState,
) {
    server.register_unary_unary(
        APPROVAL_SERVICE,
        APPROVAL_METHOD,
        move |bytes: Vec<u8>, ctx: slim_rpc::Context| {
            let (approvals, channel_manager, slim) =
                (approvals.clone(), channel_manager.clone(), slim.clone());
            async move {
                let caller = ctx.session().destination().to_string();
                let peer = ctx.peer_subject();
                let answer = approve(
                    &approvals,
                    &channel_manager,
                    &slim,
                    &caller,
                    peer.as_deref(),
                    &bytes,
                )
                .await;
                Ok(cm::ApprovalResponse::from(answer).encode_to_vec())
            }
        },
    );
}

async fn approve(
    approvals: &Approvals,
    channel_manager: &Arc<ChannelManagerState>,
    slim: &SlimState,
    caller: &str,
    peer: Option<&str>,
    bytes: &[u8],
) -> Answer {
    let Some(config) = channel_manager.config() else {
        return Answer::Denied("this owner uses no channel manager".to_string());
    };
    if let Err(err) = check_approval_caller(&config, caller, peer) {
        return Answer::Denied(err);
    }
    let request = match cm::ApprovalRequest::decode(bytes)
        .map_err(|e| e.to_string())
        .and_then(|r| owner_request(&r))
    {
        Ok(request) => request,
        Err(err) => return Answer::Denied(err),
    };
    // Hold only what the channel manager itself lists with this owner, so a
    // caller can't get a grant for a channel the owner doesn't have there.
    let owner = match slim.owner_identity() {
        Ok(owner) => owner,
        Err(err) => return Answer::Denied(err),
    };
    let lookup = {
        let config = config.clone();
        tokio::task::spawn_blocking(move || owned_channels(&config, &owner)).await
    };
    let owned = match lookup {
        Ok(Ok(owned)) => owned,
        Ok(Err(err)) => return Answer::Denied(err),
        Err(err) => return Answer::Denied(err.to_string()),
    };
    channel_manager.set_owned(owned.iter().map(|c| c.channel_name.clone()));
    if !owned.iter().any(|c| c.channel_name == request.channel) {
        return Answer::Denied(format!(
            "{} is not a channel this owner holds",
            request.channel
        ));
    }
    approvals.decide(request).await
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// --- Commands ----------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct ChannelManagerSetup {
    pub config: Option<ChannelManagerConfig>,
    /// The `did:key` the channel manager records as the owner.
    pub owner_did: Option<String>,
    /// A channel manager `api-server.auth`, as JSON (valid YAML), that
    /// verifies the tokens API calls carry when no token file is set.
    pub api_auth: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ManagedRoom {
    pub channel: String,
    pub expires_at: Option<u64>,
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| format!("task failed: {e}"))?
}

fn api_auth_json(owner: &AgentIdentity) -> Result<String, String> {
    let jwks = shadi_identity::jwks_from_dids([owner.did().as_str()]).map_err(|e| e.to_string())?;
    let auth = slim_config::grpc::server::AuthenticationConfig::Jwt(JwtConfig::new(
        Claims::default(),
        TOKEN_TTL,
        JwtKey::Decoding(Key {
            algorithm: Algorithm::EdDSA,
            format: KeyFormat::Jwks,
            key: KeyData::Data(jwks),
        }),
    ));
    serde_json::to_string_pretty(&auth).map_err(|e| e.to_string())
}

/// The config, plus what the channel manager needs to know about this owner.
#[tauri::command]
pub async fn channel_manager_setup(
    slim: tauri::State<'_, SlimState>,
    channel_manager: tauri::State<'_, Arc<ChannelManagerState>>,
) -> Result<ChannelManagerSetup, String> {
    let owner = slim.owner_identity().ok();
    Ok(ChannelManagerSetup {
        config: channel_manager.config(),
        owner_did: owner.as_ref().map(AgentIdentity::did),
        api_auth: owner.as_ref().map(api_auth_json).transpose()?,
    })
}

/// Save the channel manager config, or clear it with `None`.
#[tauri::command]
pub async fn channel_manager_configure(
    channel_manager: tauri::State<'_, Arc<ChannelManagerState>>,
    config: Option<ChannelManagerConfig>,
) -> Result<(), String> {
    let path = channel_manager
        .path
        .lock()
        .map_err(|_| "state poisoned")?
        .clone()
        .ok_or_else(|| "no app data dir".to_string())?;
    match &config {
        Some(config) => {
            config.validate()?;
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
            }
            let text = serde_json::to_string_pretty(config).map_err(|e| e.to_string())?;
            std::fs::write(&path, text).map_err(|e| format!("{}: {e}", path.display()))?;
        }
        None => match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(format!("{}: {err}", path.display())),
        },
    }
    *channel_manager
        .config
        .lock()
        .map_err(|_| "state poisoned")? = config;
    channel_manager.set_owned(Vec::new());
    Ok(())
}

/// The rooms the channel manager lists with this owner.
#[tauri::command]
pub async fn channel_manager_rooms(
    slim: tauri::State<'_, SlimState>,
    channel_manager: tauri::State<'_, Arc<ChannelManagerState>>,
) -> Result<Vec<ManagedRoom>, String> {
    let config = channel_manager.require()?;
    let owner = slim.owner_identity()?;
    let owned = blocking(move || owned_channels(&config, &owner)).await?;
    channel_manager.set_owned(owned.iter().map(|c| c.channel_name.clone()));
    Ok(owned
        .into_iter()
        .map(|c| ManagedRoom {
            channel: c.channel_name,
            expires_at: c.expires_at,
        })
        .collect())
}

/// Create a room through the channel manager. Others' requests to join it
/// come to the owner service, which must be running.
#[tauri::command]
pub async fn channel_manager_room_create(
    slim: tauri::State<'_, SlimState>,
    owner: tauri::State<'_, super::owner::OwnerState>,
    channel_manager: tauri::State<'_, Arc<ChannelManagerState>>,
    channel: String,
    ttl_seconds: Option<u64>,
) -> Result<(), String> {
    let config = channel_manager.require()?;
    let callback = owner.service()?.ok_or_else(|| {
        "start the owner service first, so the channel manager can ask you".to_string()
    })?;
    let identity = slim.owner_identity()?;
    let request = create_request(&config, &identity, &channel, ttl_seconds, &callback)?;
    blocking(move || api(&config, &identity, Call::Create(request)).map(|_| ())).await?;
    channel_manager
        .owned
        .lock()
        .map_err(|_| "state poisoned")?
        .insert(channel);
    Ok(())
}

#[tauri::command]
pub async fn channel_manager_room_delete(
    slim: tauri::State<'_, SlimState>,
    channel_manager: tauri::State<'_, Arc<ChannelManagerState>>,
    channel: String,
) -> Result<(), String> {
    let config = channel_manager.require()?;
    let identity = slim.owner_identity()?;
    let request = delete_request(&config, &identity, &channel)?;
    blocking(move || api(&config, &identity, Call::Delete(request)).map(|_| ())).await?;
    channel_manager
        .owned
        .lock()
        .map_err(|_| "state poisoned")?
        .remove(&channel);
    Ok(())
}

#[tauri::command]
pub async fn channel_manager_participants(
    slim: tauri::State<'_, SlimState>,
    channel_manager: tauri::State<'_, Arc<ChannelManagerState>>,
    channel: String,
) -> Result<Vec<String>, String> {
    let config = channel_manager.require()?;
    let identity = slim.owner_identity()?;
    match blocking(move || api(&config, &identity, Call::ListParticipants(channel))).await? {
        Reply::Participants(names) => Ok(names),
        _ => Err("unexpected reply".to_string()),
    }
}

/// Add or remove a participant with the owner's own grant.
#[tauri::command]
pub async fn channel_manager_participant_set(
    slim: tauri::State<'_, SlimState>,
    channel_manager: tauri::State<'_, Arc<ChannelManagerState>>,
    channel: String,
    participant: String,
    present: bool,
) -> Result<(), String> {
    let config = channel_manager.require()?;
    let identity = slim.owner_identity()?;
    let call = participant_call(&identity, &channel, &participant, present)?;
    blocking(move || api(&config, &identity, call).map(|_| ())).await
}

/// The app data dir file the config lives in.
pub fn init(app: &tauri::AppHandle) -> Result<(), String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("no app data dir: {e}"))?;
    app.state::<Arc<ChannelManagerState>>().init(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentbridge::owner::OwnerPolicy;

    const ROOM: &str = "agntcy/shadi/managed-room";
    const PEER: &str = "agntcy/shadi/copilot";

    fn approval(action: cm::ParticipantAction) -> cm::ApprovalRequest {
        cm::ApprovalRequest {
            channel_name: ROOM.to_string(),
            participant_name: PEER.to_string(),
            action: action as i32,
            requester: Some("agntcy/shadi/codex".to_string()),
        }
    }

    fn approvals(policy: &str, answer_within: u64) -> (Approvals, AgentIdentity) {
        let key = AgentIdentity::generate().unwrap();
        let signer = AgentIdentity::from_signing_key_bytes(&key.signing_key_bytes());
        let owner = Owner::new(signer, OwnerPolicy::from_json(policy).unwrap(), None);
        let mut approvals = Approvals::new(Arc::new(Mutex::new(owner)));
        approvals.answer_within = answer_within;
        (approvals, key)
    }

    #[test]
    fn a_request_maps_its_action_and_an_unknown_one_is_refused() {
        let add = owner_request(&approval(cm::ParticipantAction::Add)).unwrap();
        assert_eq!(
            (add.action, add.invitee_name.as_str()),
            (GrantAction::Add, PEER)
        );
        assert_eq!(add.requester, "agntcy/shadi/codex");
        let delete = owner_request(&approval(cm::ParticipantAction::Delete)).unwrap();
        assert_eq!(delete.action, GrantAction::Delete);
        assert!(owner_request(&approval(cm::ParticipantAction::Unspecified)).is_err());
    }

    #[test]
    fn only_the_channel_managers_approval_app_is_a_caller() {
        let cm = "agntcy/ns/channel-manager";
        assert!(is_approval_caller(
            "agntcy/ns/channel-manager-approval/42",
            cm
        ));
        assert!(is_approval_caller("agntcy/ns/channel-manager-approval", cm));
        assert!(!is_approval_caller("agntcy/ns/channel-manager/42", cm));
        assert!(!is_approval_caller("agntcy/ns/someone-approval/42", cm));
    }

    fn config(endpoint: &str, name: &str) -> ChannelManagerConfig {
        ChannelManagerConfig {
            endpoint: endpoint.to_string(),
            name: name.to_string(),
            ca_file: None,
            approval_did: Some(AgentIdentity::generate().unwrap().did()),
            audience: None,
            api_token_file: None,
        }
    }

    #[test]
    fn a_config_needs_an_http_endpoint_a_slim_name_and_an_approval_did() {
        assert!(config("http://127.0.0.1:10356", "agntcy/ns/cm")
            .validate()
            .is_ok());
        assert!(config("127.0.0.1:10356", "agntcy/ns/cm")
            .validate()
            .is_err());
        assert!(config("https://cm.example", "agntcy/cm")
            .validate()
            .is_err());
        let mut no_did = config("http://127.0.0.1:10356", "agntcy/ns/cm");
        no_did.approval_did = None;
        assert!(no_did.validate().is_err());
        no_did.approval_did = Some("agntcy/ns/cm-approval".to_string());
        assert!(no_did.validate().is_err());
    }

    #[test]
    fn only_the_approval_did_may_ask_the_owner() {
        let config = config("http://127.0.0.1:10356", "agntcy/ns/cm");
        let did = config.approval_did.clone().unwrap();
        let caller = "agntcy/ns/cm-approval/42";
        assert!(check_approval_caller(&config, caller, Some(&did)).is_ok());
        let other = AgentIdentity::generate().unwrap().did();
        assert!(check_approval_caller(&config, caller, Some(&other)).is_err());
        assert!(check_approval_caller(&config, caller, None).is_err());
        assert!(check_approval_caller(&config, "agntcy/ns/cm/42", Some(&did)).is_err());
        let unset = ChannelManagerConfig {
            approval_did: None,
            ..config
        };
        assert!(check_approval_caller(&unset, caller, Some(&did)).is_err());
    }

    #[test]
    fn create_and_delete_are_signed_for_the_channel_managers_audience() {
        let owner = AgentIdentity::generate().unwrap();
        let mut config = config("http://127.0.0.1:10356", "agntcy/ns/cm");
        let proof = |request: Option<Vec<u8>>| -> serde_json::Value {
            serde_json::from_slice(&request.unwrap()).unwrap()
        };
        let create = create_request(&config, &owner, ROOM, Some(60), "agntcy/ns/owner").unwrap();
        let signed = proof(create.owner_proof);
        assert_eq!(signed["audience"], "agntcy/ns/cm");
        assert_eq!(signed["owner"], owner.did().as_str());
        assert_eq!(
            (&signed["channel"], &signed["ttl_seconds"]),
            (&serde_json::json!(ROOM), &serde_json::json!(60))
        );
        assert_eq!(signed["owner_callback_name"], "agntcy/ns/owner");

        config.audience = Some("cm.example".to_string());
        let delete = delete_request(&config, &owner, ROOM).unwrap();
        let signed = proof(delete.owner_proof);
        assert_eq!(
            (&signed["audience"], &signed["channel"]),
            (&serde_json::json!("cm.example"), &serde_json::json!(ROOM))
        );
    }

    #[test]
    fn the_owners_own_changes_carry_its_grant() {
        let owner = AgentIdentity::generate().unwrap();
        let Call::Remove(remove) = participant_call(&owner, ROOM, PEER, false).unwrap() else {
            panic!("expected a removal");
        };
        let grant =
            shadi_identity::verify_grant(&remove.grant.unwrap(), &owner.did(), now()).unwrap();
        assert_eq!(
            (grant.action, grant.channel.as_str(), grant.invitee.as_str()),
            (GrantAction::Delete, ROOM, PEER)
        );
    }

    #[tokio::test]
    async fn an_allow_rule_answers_with_a_grant_for_the_requested_action() {
        let (approvals, key) = approvals(
            r#"{"rules": [{"channel": "*", "action": "delete", "decision": "allow"}]}"#,
            55,
        );
        let request = owner_request(&approval(cm::ParticipantAction::Delete)).unwrap();
        let Answer::Grant(grant) = approvals.decide(request).await else {
            panic!("expected a grant");
        };
        let grant = shadi_identity::verify_grant(&grant, &key.did(), now()).unwrap();
        assert_eq!(
            (grant.action, grant.channel.as_str()),
            (GrantAction::Delete, ROOM)
        );
    }

    #[tokio::test]
    async fn an_ask_waits_for_the_owner_and_is_denied_when_nobody_answers() {
        let (approvals, _) = approvals("{}", 55);
        let approvals = Arc::new(approvals);
        let request = owner_request(&approval(cm::ParticipantAction::Add)).unwrap();
        let deciding = tokio::spawn({
            let approvals = approvals.clone();
            let request = request.clone();
            async move { approvals.decide(request).await }
        });
        let ask_id = loop {
            let pending = approvals
                .owner
                .lock()
                .unwrap()
                .pending()
                .next()
                .map(|a| a.id);
            if let Some(id) = pending.filter(|id| approvals.is_waiting(*id)) {
                break id;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        assert!(approvals.answer(ask_id, Answer::Denied("no".to_string())));
        assert_eq!(deciding.await.unwrap(), Answer::Denied("no".to_string()));

        let (approvals, _) = approvals_with_no_time();
        assert_eq!(
            approvals.decide(request).await,
            Answer::Denied("the owner didn't answer in time".to_string())
        );
        assert_eq!(approvals.owner.lock().unwrap().pending().count(), 0);
    }

    fn approvals_with_no_time() -> (Approvals, AgentIdentity) {
        approvals("{}", 0)
    }

    #[test]
    fn the_api_auth_snippet_verifies_the_owner_key() {
        let owner = AgentIdentity::generate().unwrap();
        let auth: serde_json::Value =
            serde_json::from_str(&api_auth_json(&owner).unwrap()).unwrap();
        let text = auth.to_string();
        assert!(text.contains("EdDSA") && text.contains("jwks"), "{text}");
    }

    /// Kills the channel manager when the test ends, however it ends.
    struct Running(std::process::Child);

    impl Drop for Running {
        fn drop(&mut self) {
            let _ = self.0.kill();
        }
    }

    /// The owner flow against a real channel manager, driven by
    /// docs/content/demos/desktop-channel-manager-e2e.sh: the owner creates a
    /// room with a signed request, codex asks to add claude-code without a
    /// grant, the channel manager asks the owner service from its approval
    /// identity, and the owner's rules grant it; a request the rules block is
    /// refused. The owner then removes claude-code with its own grant and
    /// deletes the room with a signed request.
    #[test]
    #[ignore = "needs a SLIM node and the channel-manager binary; run the e2e script"]
    fn live_channel_manager_asks_the_owner_and_adds_who_it_grants() {
        use agentbridge::owner_intake::OwnerExecutor;
        use slim_config::client::ClientConfig;
        use slim_config::server::ServerConfig;
        use slim_config::tls::server::TlsServerConfig;

        let env = |key: &str| std::env::var(key).unwrap_or_else(|_| panic!("{key} is unset"));
        let seed = env("SLIM_HUMAN_SEED");
        let derive = |name: &str| AgentIdentity::derive(seed.as_bytes(), name).unwrap();
        let (owner, codex, cm) = (derive("owner"), derive("codex"), derive("channel-manager"));
        let approval = derive("channel-manager-approval");
        let invitee = "agntcy/shadi/claude-code";
        let cm_name = "agntcy/shadi/channel-manager";
        let room = env("SHADI_E2E_ROOM");
        let api_addr = env("SHADI_E2E_CM_API");
        let dir = tempfile::tempdir().unwrap();
        let file = |name: &str| dir.path().join(name).display().to_string();

        // The channel manager's own key, and whom it trusts on SLIM and on its API.
        std::fs::write(file("cm.pem"), cm.to_pkcs8_pem().unwrap()).unwrap();
        std::fs::write(file("approval.pem"), approval.to_pkcs8_pem().unwrap()).unwrap();
        let dids =
            |names: &[&str]| -> Vec<String> { names.iter().map(|n| derive(n).did()).collect() };
        let jwks = |dids: Vec<String>| {
            shadi_identity::jwks_from_dids(dids.iter().map(String::as_str)).unwrap()
        };
        // Its own key too: MLS checks the group creator's own credential.
        std::fs::write(
            file("members.jwks.json"),
            jwks(dids(&[
                "channel-manager",
                "channel-manager-approval",
                "avatar",
                "owner",
                "claude-code",
                "codex",
            ])),
        )
        .unwrap();
        let slim_connection =
            ClientConfig::with_endpoint(&format!("https://{}", env("SLIM_ENDPOINT")))
                .with_tls_setting(
                    TlsClientConfig::new()
                        .with_ca_file(&env("SLIM_TLS_CA"))
                        .with_cert_and_key_file(
                            &env("SHADI_E2E_CM_CERT"),
                            &env("SHADI_E2E_CM_KEY"),
                        ),
                );
        let api_server = ServerConfig::with_endpoint(&api_addr)
            .with_tls_settings(TlsServerConfig::new().with_insecure(true))
            .with_auth(slim_config::server::AuthenticationConfig::Jwt(
                JwtConfig::new(
                    Claims::default(),
                    TOKEN_TTL,
                    JwtKey::Decoding(Key {
                        algorithm: Algorithm::EdDSA,
                        format: KeyFormat::Jwks,
                        key: KeyData::Data(jwks(dids(&["owner", "codex"]))),
                    }),
                ),
            ));
        let config = serde_json::json!({ "channel-manager": {
            "slim-connection": slim_connection,
            "api-server": api_server,
            "local-name": cm_name,
            "auth": {
                "type": "jwt",
                "private_key": { "file": file("cm.pem") },
                "trusted_keys": { "file": file("members.jwks.json") },
            },
            "approval-auth": {
                "type": "jwt",
                "private_key": { "file": file("approval.pem") },
                "trusted_keys": { "file": file("members.jwks.json") },
            },
        }});
        std::fs::write(file("config.yaml"), config.to_string()).unwrap();

        let log = std::fs::File::create(env("SHADI_E2E_CM_LOG")).unwrap();
        let _cm = Running(
            std::process::Command::new(env("SHADI_E2E_CHANNEL_MANAGER"))
                .env(
                    "RUST_LOG",
                    std::env::var("SHADI_E2E_CM_RUST_LOG").unwrap_or_else(|_| "info".to_string()),
                )
                .arg("--config-file")
                .arg(file("config.yaml"))
                .stdout(log.try_clone().unwrap())
                .stderr(log)
                .spawn()
                .expect("start the channel manager"),
        );
        let up = (0..60).any(|_| {
            std::thread::sleep(Duration::from_millis(500));
            std::net::TcpStream::connect(&api_addr).is_ok()
        });
        assert!(up, "the channel manager API never came up");

        // The owner service, answering for rooms the channel manager lists
        // with this owner. Codex may add anyone but the stranger.
        let policy = format!(
            r#"{{"default": "block", "rules": [
                {{"channel": "*", "invitee": "agntcy/shadi/stranger", "decision": "block"}},
                {{"channel": "*", "requested_by": "{}", "decision": "allow"}}
            ]}}"#,
            codex.did()
        );
        std::env::set_var(
            "SHADI_CHANNEL_MANAGER_ENDPOINT",
            format!("http://{api_addr}"),
        );
        std::env::set_var("SHADI_CHANNEL_MANAGER_NAME", cm_name);
        std::env::set_var("SHADI_CHANNEL_MANAGER_APPROVAL_DID", approval.did());
        let channel_manager = Arc::new(ChannelManagerState::default());
        channel_manager.init(dir.path().to_path_buf()).unwrap();
        let cm_config = channel_manager.require().unwrap();
        let state = SlimState::default();
        let core = Owner::new(
            state.owner_identity().unwrap(),
            OwnerPolicy::from_json(&policy).unwrap(),
            None,
        );
        let core = Arc::new(Mutex::new(core));
        let executor = OwnerExecutor::new(core.clone(), Arc::new(state.room_inviter(owner.did())));
        let service = state
            .serve_owner(executor, Arc::new(Approvals::new(core)), channel_manager)
            .expect("serve the owner service");
        println!("owner service ready at {service}");

        let create = create_request(&cm_config, &owner, &room, None, &service).unwrap();
        api(&cm_config, &owner, Call::Create(create)).expect("create the room as its owner");

        let add = |participant: &str| {
            api(
                &cm_config,
                &codex,
                Call::Add(cm::AddParticipantRequest {
                    channel_name: room.clone(),
                    participant_name: participant.to_string(),
                    grant: None,
                }),
            )
        };
        add(invitee).expect("the owner grants codex's request");
        let participants = || {
            let Reply::Participants(participants) =
                api(&cm_config, &owner, Call::ListParticipants(room.clone())).unwrap()
            else {
                panic!("expected participants");
            };
            participants
        };
        let joined = participants();
        assert!(
            joined.iter().any(|p| p.starts_with(invitee)),
            "{invitee} isn't in {joined:?}"
        );
        let refused = add("agntcy/shadi/stranger");
        assert!(
            refused.is_err(),
            "the owner's rules block the stranger: {:?}",
            refused.err()
        );
        println!(
            "granted {invitee}; refused the stranger: {}",
            refused.err().unwrap_or_default()
        );

        let remove = participant_call(&owner, &room, invitee, false).unwrap();
        api(&cm_config, &owner, remove).expect("the owner removes with its own grant");
        let left = participants();
        assert!(
            !left.iter().any(|p| p.starts_with(invitee)),
            "{invitee} is still in {left:?}"
        );
        let unsigned = cm::DeleteChannelRequest {
            channel_name: room.clone(),
            owner_proof: None,
        };
        assert!(
            api(&cm_config, &owner, Call::Delete(unsigned)).is_err(),
            "an unsigned delete of an owned room is refused"
        );
        let delete = delete_request(&cm_config, &owner, &room).unwrap();
        api(&cm_config, &owner, Call::Delete(delete)).expect("the owner deletes the room");
        println!("removed {invitee} and deleted {room}");
    }
}
