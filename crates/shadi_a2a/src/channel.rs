// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use a2a::event::StreamResponse;
use a2a::*;
use a2a_client::jsonrpc::JsonRpcTransport;
use a2a_client::rest::RestTransport;
use a2a_client::transport::{ServiceParams, Transport};
use a2a_grpc::GrpcTransport;
use a2a_slimrpc::SlimRpcTransport;
use agent_secrets::{AgentVerifier, SecretError, SessionContext};
use async_trait::async_trait;
use futures::stream::BoxStream;
use slim_bindings::{App, Name};

use crate::locator::{A2ABinding, A2ALocator};

/// `Message.metadata` key the A2A group API sets to the proven sender DID.
/// SLIM still also sets [`a2a_slimrpc::SLIM_SRC_METADATA_KEY`] on the wire.
pub const A2A_SRC_DID_METADATA_KEY: &str = "a2a-src-did";

/// `Message.metadata` key naming the intended recipient DID.
///
/// The URL is only a locator. Two agents can share one gRPC URL (proxy,
/// multiplexer); this key says which DID the message is for. Listeners whose
/// DID does not match must not execute the task.
pub const A2A_DST_DID_METADATA_KEY: &str = "a2a-dst-did";

fn secret_err_to_a2a(err: SecretError) -> A2AError {
    A2AError::internal(format!("SHADI auth error: {err}"))
}

fn insert_metadata_did(mut message: Message, key: &str, did: &str) -> Message {
    message
        .metadata
        .get_or_insert_with(std::collections::HashMap::new)
        .insert(key.to_string(), serde_json::Value::String(did.to_string()));
    message
}

fn insert_sender_did(message: Message, did: &str) -> Message {
    insert_metadata_did(message, A2A_SRC_DID_METADATA_KEY, did)
}

/// Tag an outbound A2A message with the recipient DID (the portable name).
pub fn insert_dest_did(message: Message, did: &str) -> Message {
    insert_metadata_did(message, A2A_DST_DID_METADATA_KEY, did)
}

/// Recipient DID from `Message.metadata`, if the caller set one.
pub fn dest_did_from_message(message: &Message) -> Option<&str> {
    message
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get(A2A_DST_DID_METADATA_KEY))
        .and_then(|value| value.as_str())
        .filter(|did| !did.is_empty())
}

fn response_to_message(response: SendMessageResponse) -> Message {
    match response {
        SendMessageResponse::Message(message) => message,
        SendMessageResponse::Task(task) => task.status.message.unwrap_or_else(|| {
            Message::new(
                Role::Agent,
                vec![Part::text(format!("task {} {:?}", task.id, task.status.state))],
            )
        }),
    }
}

/// An A2A channel between two agentic apps, guarded by SHADI identity
/// verification. The bytes may travel over SLIMRPC or gRPC; the verifier is
/// the same on every binding.
///
/// Every outbound A2A call first passes through the configured
/// [`AgentVerifier`], ensuring the remote peer's identity is acceptable before
/// any protocol bytes leave the process.
pub struct A2AChannel {
    transport: Box<dyn Transport>,
    verifier: Arc<dyn AgentVerifier>,
    ctx: SessionContext,
}

impl A2AChannel {
    fn check_auth(&self) -> Result<(), A2AError> {
        self.verifier.verify(&self.ctx).map_err(secret_err_to_a2a)
    }

    /// Wrap an already-connected A2A [`Transport`] (SLIMRPC, gRPC, or a test stub).
    pub fn from_transport(
        transport: Box<dyn Transport>,
        verifier: Arc<dyn AgentVerifier>,
        ctx: SessionContext,
    ) -> Self {
        Self {
            transport,
            verifier,
            ctx,
        }
    }

    /// Connect to a standard A2A gRPC listener at `url` (`http://host:port` or
    /// `host:port`). Application auth is still [`AgentVerifier`] — the URL is
    /// only the address.
    pub async fn grpc(
        url: impl Into<String>,
        verifier: Arc<dyn AgentVerifier>,
        ctx: SessionContext,
    ) -> Result<Self, A2AError> {
        Self::connect(A2ALocator::new(A2ABinding::Grpc, url.into()), verifier, ctx).await
    }

    /// Connect using an official A2A unicast locator (`GRPC`, `JSONRPC`, or
    /// `HTTP+JSON`). The DID stays the name; this is only the current address.
    pub async fn connect(
        locator: A2ALocator,
        verifier: Arc<dyn AgentVerifier>,
        ctx: SessionContext,
    ) -> Result<Self, A2AError> {
        let transport: Box<dyn Transport> = match locator.binding {
            A2ABinding::Slim => {
                return Err(A2AError::invalid_params(
                    "SLIM locators use A2AChannelBuilder (local node + SLIM name), not A2AChannel::connect",
                ));
            }
            A2ABinding::Grpc => {
                if locator.url.starts_with("https://") {
                    return Err(A2AError::internal(
                        "https:// A2A gRPC needs origin TLS in a2a-grpc (see a2aproject/a2a-rs#162 / SHADI A2A_TLS_CA). Use http://127.0.0.1 for loopback experiments.",
                    ));
                }
                Box::new(GrpcTransport::connect(locator.url).await?)
            }
            A2ABinding::Jsonrpc => {
                let client = a2a_client::default_reqwest_client(None)?;
                Box::new(JsonRpcTransport::new(client, locator.url))
            }
            A2ABinding::HttpJson => {
                let client = a2a_client::default_reqwest_client(None)?;
                Box::new(RestTransport::new(client, locator.url))
            }
        };
        Ok(Self::from_transport(transport, verifier, ctx))
    }
}

/// Builder for [`A2AChannel`] backed by SLIMRPC.
pub struct A2AChannelBuilder {
    app: Arc<App>,
    remote: Arc<Name>,
    connection_id: Option<u64>,
    verifier: Arc<dyn AgentVerifier>,
    ctx: SessionContext,
}

impl A2AChannelBuilder {
    pub fn new(
        app: Arc<App>,
        remote: Arc<Name>,
        verifier: Arc<dyn AgentVerifier>,
        ctx: SessionContext,
    ) -> Self {
        Self {
            app,
            remote,
            connection_id: None,
            verifier,
            ctx,
        }
    }

    pub fn connection_id(mut self, id: u64) -> Self {
        self.connection_id = Some(id);
        self
    }

    pub fn build(self) -> A2AChannel {
        let transport = SlimRpcTransport::new_with_connection(
            self.app.inner(),
            Arc::new(self.remote.as_slim_name()),
            self.connection_id,
        );
        A2AChannel::from_transport(Box::new(transport), self.verifier, self.ctx)
    }
}

/// One member of an A2A group. The DID is who they are; `url` + `binding` is
/// how to reach them on an official unicast binding. SLIM members keep using
/// SLIM names via [`A2AGroupChannelBuilder`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupMember {
    pub agent_id: String,
    pub did: String,
    pub url: String,
    pub binding: A2ABinding,
}

enum GroupBinding {
    Slim(SlimRpcTransport),
    Grpc { members: Vec<GroupMember> },
}

/// Many-to-many A2A Collaborate, guarded by the same SHADI identity
/// verification as [`A2AChannel`].
///
/// The group is an A2A extension (roster + Collaborate). SLIM may carry it as
/// a native multicast session; gRPC fans out unicast `SendMessage`. MLS,
/// moderator invite, and SLIM names are SLIM-binding-only.
pub struct A2AGroupChannel {
    binding: GroupBinding,
    verifier: Arc<dyn AgentVerifier>,
    ctx: SessionContext,
}

impl A2AGroupChannel {
    fn check_auth(&self) -> Result<(), A2AError> {
        self.verifier.verify(&self.ctx).map_err(secret_err_to_a2a)
    }

    /// gRPC fan-out Collaborate: each outbound `Message` is `SendMessage` to
    /// every roster URL. Replies are attributed with [`A2A_SRC_DID_METADATA_KEY`].
    /// Incoming unsolicited Collaborate still arrives on each member's
    /// `--a2a-listen` handler. Mesh invite/MLS are not on this path.
    pub fn grpc(
        members: Vec<GroupMember>,
        verifier: Arc<dyn AgentVerifier>,
        ctx: SessionContext,
    ) -> Result<Self, A2AError> {
        if members.is_empty() {
            return Err(A2AError::invalid_params("A2A group roster is empty"));
        }
        for member in &members {
            if member.did.is_empty() || member.url.is_empty() {
                return Err(A2AError::invalid_params(
                    "each unicast group member needs a DID and URL",
                ));
            }
        }
        Ok(Self {
            binding: GroupBinding::Grpc { members },
            verifier,
            ctx,
        })
    }

    /// Open a `Collaborate` session on the group: broadcast every `Message`
    /// produced by `outbound` to the group, and yield every `Message`
    /// broadcast by other members (attributed via [`A2A_SRC_DID_METADATA_KEY`];
    /// SLIM also sets `slim-src`). Runs the same identity check as
    /// [`A2AChannel`]'s calls, once, before delegating.
    pub fn collaborate(
        &self,
        outbound: impl futures::Stream<Item = Message> + Send + 'static,
        timeout: Option<std::time::Duration>,
    ) -> Result<BoxStream<'static, Result<Message, A2AError>>, A2AError> {
        self.check_auth()?;
        match &self.binding {
            GroupBinding::Slim(transport) => {
                let transport = transport.clone();
                Ok(Box::pin(async_stream::stream! {
                    let inner = transport.collaborate(outbound, timeout);
                    futures::pin_mut!(inner);
                    while let Some(item) = futures::StreamExt::next(&mut inner).await {
                        yield item;
                    }
                }))
            }
            GroupBinding::Grpc { members } => {
                let members = members.clone();
                Ok(Box::pin(async_stream::stream! {
                    futures::pin_mut!(outbound);
                    while let Some(message) = futures::StreamExt::next(&mut outbound).await {
                        for member in &members {
                            let locator = A2ALocator::new(member.binding, member.url.clone());
                            let channel = match A2AChannel::connect(
                                locator,
                                Arc::new(AllowAllForFanout),
                                SessionContext::new(&member.agent_id, "a2a-group-fanout")
                                    .with_proven_did(&member.did),
                            )
                            .await
                            {
                                Ok(channel) => channel,
                                Err(err) => {
                                    yield Err(err);
                                    continue;
                                }
                            };
                            let request = SendMessageRequest {
                                message: insert_dest_did(message.clone(), &member.did),
                                configuration: None,
                                metadata: None,
                                tenant: None,
                            };
                            let params = ServiceParams::new();
                            let send = channel.send_message(&params, &request);
                            let result = if let Some(timeout) = timeout {
                                match tokio::time::timeout(timeout, send).await {
                                    Ok(inner) => inner,
                                    Err(_) => {
                                        yield Err(A2AError::internal(format!(
                                            "gRPC Collaborate timed out sending to {}",
                                            member.agent_id
                                        )));
                                        continue;
                                    }
                                }
                            } else {
                                send.await
                            };
                            match result {
                                Ok(response) => {
                                    yield Ok(insert_sender_did(
                                        response_to_message(response),
                                        &member.did,
                                    ));
                                }
                                Err(err) => yield Err(err),
                            }
                        }
                    }
                }))
            }
        }
    }
}

/// Fan-out already ran [`A2AGroupChannel::check_auth`]. Per-peer gRPC channels
/// still require a verifier; identity of each hop is the roster DID on the reply.
struct AllowAllForFanout;

impl AgentVerifier for AllowAllForFanout {
    fn verify(&self, _session: &SessionContext) -> agent_secrets::SecretResult<()> {
        Ok(())
    }
}

/// Builder for [`A2AGroupChannel`] backed by a SLIM group session spanning
/// `members`. Separate from [`A2AChannelBuilder`] because a group has no single
/// "remote" peer.
pub struct A2AGroupChannelBuilder {
    app: Arc<App>,
    members: Vec<Arc<Name>>,
    connection_id: Option<u64>,
    verifier: Arc<dyn AgentVerifier>,
    ctx: SessionContext,
}

impl A2AGroupChannelBuilder {
    pub fn new(
        app: Arc<App>,
        members: Vec<Arc<Name>>,
        verifier: Arc<dyn AgentVerifier>,
        ctx: SessionContext,
    ) -> Self {
        Self {
            app,
            members,
            connection_id: None,
            verifier,
            ctx,
        }
    }

    pub fn connection_id(mut self, id: u64) -> Self {
        self.connection_id = Some(id);
        self
    }

    pub fn build(self) -> Result<A2AGroupChannel, A2AError> {
        let members = self
            .members
            .iter()
            .map(|name| Arc::new(name.as_slim_name()))
            .collect();
        let transport =
            SlimRpcTransport::new_group_with_connection(self.app.inner(), members, self.connection_id)
                .map_err(|error| a2a_slimrpc::errors::rpc_error_to_a2a_error(&error))?;
        Ok(A2AGroupChannel {
            binding: GroupBinding::Slim(transport),
            verifier: self.verifier,
            ctx: self.ctx,
        })
    }
}

#[async_trait]
impl Transport for A2AChannel {
    async fn send_message(
        &self,
        params: &ServiceParams,
        req: &SendMessageRequest,
    ) -> Result<SendMessageResponse, A2AError> {
        self.check_auth()?;
        self.transport.send_message(params, req).await
    }

    async fn send_streaming_message(
        &self,
        params: &ServiceParams,
        req: &SendMessageRequest,
    ) -> Result<BoxStream<'static, Result<StreamResponse, A2AError>>, A2AError> {
        self.check_auth()?;
        self.transport.send_streaming_message(params, req).await
    }

    async fn get_task(
        &self,
        params: &ServiceParams,
        req: &GetTaskRequest,
    ) -> Result<Task, A2AError> {
        self.check_auth()?;
        self.transport.get_task(params, req).await
    }

    async fn list_tasks(
        &self,
        params: &ServiceParams,
        req: &ListTasksRequest,
    ) -> Result<ListTasksResponse, A2AError> {
        self.check_auth()?;
        self.transport.list_tasks(params, req).await
    }

    async fn cancel_task(
        &self,
        params: &ServiceParams,
        req: &CancelTaskRequest,
    ) -> Result<Task, A2AError> {
        self.check_auth()?;
        self.transport.cancel_task(params, req).await
    }

    async fn subscribe_to_task(
        &self,
        params: &ServiceParams,
        req: &SubscribeToTaskRequest,
    ) -> Result<BoxStream<'static, Result<StreamResponse, A2AError>>, A2AError> {
        self.check_auth()?;
        self.transport.subscribe_to_task(params, req).await
    }

    async fn create_push_config(
        &self,
        params: &ServiceParams,
        req: &TaskPushNotificationConfig,
    ) -> Result<TaskPushNotificationConfig, A2AError> {
        self.check_auth()?;
        self.transport.create_push_config(params, req).await
    }

    async fn get_push_config(
        &self,
        params: &ServiceParams,
        req: &GetTaskPushNotificationConfigRequest,
    ) -> Result<TaskPushNotificationConfig, A2AError> {
        self.check_auth()?;
        self.transport.get_push_config(params, req).await
    }

    async fn list_push_configs(
        &self,
        params: &ServiceParams,
        req: &ListTaskPushNotificationConfigsRequest,
    ) -> Result<ListTaskPushNotificationConfigsResponse, A2AError> {
        self.check_auth()?;
        self.transport.list_push_configs(params, req).await
    }

    async fn delete_push_config(
        &self,
        params: &ServiceParams,
        req: &DeleteTaskPushNotificationConfigRequest,
    ) -> Result<(), A2AError> {
        self.check_auth()?;
        self.transport.delete_push_config(params, req).await
    }

    async fn get_extended_agent_card(
        &self,
        params: &ServiceParams,
        req: &GetExtendedAgentCardRequest,
    ) -> Result<AgentCard, A2AError> {
        self.check_auth()?;
        self.transport.get_extended_agent_card(params, req).await
    }

    async fn destroy(&self) -> Result<(), A2AError> {
        self.check_auth()?;
        self.transport.destroy().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_secrets::{SecretError, SecretResult};
    use futures::{stream, StreamExt};

    struct AllowVerifier;

    impl AgentVerifier for AllowVerifier {
        fn verify(&self, _session: &SessionContext) -> SecretResult<()> {
            Ok(())
        }
    }

    struct DenyVerifier;

    impl AgentVerifier for DenyVerifier {
        fn verify(&self, _session: &SessionContext) -> SecretResult<()> {
            Err(SecretError::NotAuthorized)
        }
    }

    struct StubTransport;

    #[async_trait]
    impl Transport for StubTransport {
        async fn send_message(
            &self,
            _params: &ServiceParams,
            _req: &SendMessageRequest,
        ) -> Result<SendMessageResponse, A2AError> {
            Err(A2AError::internal("stub"))
        }

        async fn send_streaming_message(
            &self,
            _params: &ServiceParams,
            _req: &SendMessageRequest,
        ) -> Result<BoxStream<'static, Result<StreamResponse, A2AError>>, A2AError> {
            Ok(Box::pin(stream::empty()))
        }

        async fn get_task(
            &self,
            _params: &ServiceParams,
            _req: &GetTaskRequest,
        ) -> Result<Task, A2AError> {
            Err(A2AError::internal("stub"))
        }

        async fn list_tasks(
            &self,
            _params: &ServiceParams,
            _req: &ListTasksRequest,
        ) -> Result<ListTasksResponse, A2AError> {
            Err(A2AError::internal("stub"))
        }

        async fn cancel_task(
            &self,
            _params: &ServiceParams,
            _req: &CancelTaskRequest,
        ) -> Result<Task, A2AError> {
            Err(A2AError::internal("stub"))
        }

        async fn subscribe_to_task(
            &self,
            _params: &ServiceParams,
            _req: &SubscribeToTaskRequest,
        ) -> Result<BoxStream<'static, Result<StreamResponse, A2AError>>, A2AError> {
            Ok(Box::pin(stream::empty()))
        }

        async fn create_push_config(
            &self,
            _params: &ServiceParams,
            _req: &TaskPushNotificationConfig,
        ) -> Result<TaskPushNotificationConfig, A2AError> {
            Err(A2AError::internal("stub"))
        }

        async fn get_push_config(
            &self,
            _params: &ServiceParams,
            _req: &GetTaskPushNotificationConfigRequest,
        ) -> Result<TaskPushNotificationConfig, A2AError> {
            Err(A2AError::internal("stub"))
        }

        async fn list_push_configs(
            &self,
            _params: &ServiceParams,
            _req: &ListTaskPushNotificationConfigsRequest,
        ) -> Result<ListTaskPushNotificationConfigsResponse, A2AError> {
            Err(A2AError::internal("stub"))
        }

        async fn delete_push_config(
            &self,
            _params: &ServiceParams,
            _req: &DeleteTaskPushNotificationConfigRequest,
        ) -> Result<(), A2AError> {
            Err(A2AError::internal("stub"))
        }

        async fn get_extended_agent_card(
            &self,
            _params: &ServiceParams,
            _req: &GetExtendedAgentCardRequest,
        ) -> Result<AgentCard, A2AError> {
            Err(A2AError::internal("stub"))
        }

        async fn destroy(&self) -> Result<(), A2AError> {
            Ok(())
        }
    }

    fn make_channel(verifier: Arc<dyn AgentVerifier>) -> A2AChannel {
        A2AChannel {
            transport: Box::new(StubTransport),
            verifier,
            ctx: SessionContext::new("test-agent", "test-session"),
        }
    }

    #[test]
    fn allow_verifier_passes_check_auth() {
        let channel = make_channel(Arc::new(AllowVerifier));
        assert!(channel.check_auth().is_ok());
    }

    #[test]
    fn deny_verifier_fails_check_auth() {
        let channel = make_channel(Arc::new(DenyVerifier));
        let err = channel.check_auth().unwrap_err();
        assert_eq!(err.code, a2a::error_code::INTERNAL_ERROR);
    }

    #[tokio::test]
    async fn deny_verifier_blocks_send_message() {
        let channel = make_channel(Arc::new(DenyVerifier));
        let params = ServiceParams::new();
        let req = SendMessageRequest {
            message: Message::new(Role::User, vec![Part::text("hello")]),
            configuration: None,
            metadata: None,
            tenant: None,
        };
        let err = channel.send_message(&params, &req).await.unwrap_err();
        assert_eq!(err.code, a2a::error_code::INTERNAL_ERROR);
    }

    #[tokio::test]
    async fn allow_verifier_reaches_transport() {
        let channel = make_channel(Arc::new(AllowVerifier));
        let params = ServiceParams::new();
        let req = SendMessageRequest {
            message: Message::new(Role::User, vec![Part::text("hello")]),
            configuration: None,
            metadata: None,
            tenant: None,
        };
        // StubTransport always returns an internal "stub" error, confirming
        // the auth gate was passed and the call reached the transport layer.
        let err = channel.send_message(&params, &req).await.unwrap_err();
        assert_eq!(err.message, "stub");
    }

    #[tokio::test]
    async fn allow_verifier_reaches_remaining_transport_methods() {
        let channel = make_channel(Arc::new(AllowVerifier));
        let params = ServiceParams::new();
        let req = SendMessageRequest {
            message: Message::new(Role::User, vec![Part::text("hello")]),
            configuration: None,
            metadata: None,
            tenant: None,
        };

        let mut stream = channel
            .send_streaming_message(&params, &req)
            .await
            .expect("streaming transport");
        assert!(stream.next().await.is_none());

        let task_err = channel
            .get_task(
                &params,
                &GetTaskRequest {
                    id: "task-1".to_string(),
                    history_length: Some(1),
                    tenant: None,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(task_err.message, "stub");

        let list_err = channel
            .list_tasks(
                &params,
                &ListTasksRequest {
                    context_id: Some("context-1".to_string()),
                    status: Some(TaskState::Working),
                    page_size: Some(1),
                    page_token: None,
                    history_length: Some(1),
                    status_timestamp_after: None,
                    include_artifacts: Some(false),
                    tenant: None,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(list_err.message, "stub");

        let cancel_err = channel
            .cancel_task(
                &params,
                &CancelTaskRequest {
                    id: "task-1".to_string(),
                    metadata: None,
                    tenant: None,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(cancel_err.message, "stub");

        let mut subscription = channel
            .subscribe_to_task(
                &params,
                &SubscribeToTaskRequest {
                    id: "task-1".to_string(),
                    tenant: None,
                },
            )
            .await
            .expect("subscription transport");
        assert!(subscription.next().await.is_none());

        let create_err = channel
            .create_push_config(
                &params,
                &TaskPushNotificationConfig {
                    task_id: "task-1".to_string(),
                    tenant: None,
                    url: "https://example.invalid/hook".to_string(),
                    id: Some("cfg-1".to_string()),
                    token: None,
                    authentication: None,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(create_err.message, "stub");

        let get_push_err = channel
            .get_push_config(
                &params,
                &GetTaskPushNotificationConfigRequest {
                    task_id: "task-1".to_string(),
                    id: "cfg-1".to_string(),
                    tenant: None,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(get_push_err.message, "stub");

        let list_push_err = channel
            .list_push_configs(
                &params,
                &ListTaskPushNotificationConfigsRequest {
                    task_id: "task-1".to_string(),
                    page_size: Some(10),
                    page_token: None,
                    tenant: None,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(list_push_err.message, "stub");

        let delete_push_err = channel
            .delete_push_config(
                &params,
                &DeleteTaskPushNotificationConfigRequest {
                    task_id: "task-1".to_string(),
                    id: "cfg-1".to_string(),
                    tenant: None,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(delete_push_err.message, "stub");

        let card_err = channel
            .get_extended_agent_card(
                &params,
                &GetExtendedAgentCardRequest { tenant: None },
            )
            .await
            .unwrap_err();
        assert_eq!(card_err.message, "stub");

        channel.destroy().await.expect("destroy transport");
    }

    #[tokio::test]
    async fn connect_rejects_slim_locator_and_https_grpc() {
        let slim = match A2AChannel::connect(
            A2ALocator::slim("127.0.0.1:47357"),
            Arc::new(AllowVerifier),
            SessionContext::new("client", "reject"),
        )
        .await
        {
            Ok(_) => panic!("SLIM locator must not use A2AChannel::connect"),
            Err(err) => err,
        };
        assert!(
            slim.message.contains("A2AChannelBuilder"),
            "{}",
            slim.message
        );

        let https = match A2AChannel::connect(
            A2ALocator::parse("https://example.test:443").unwrap(),
            Arc::new(AllowVerifier),
            SessionContext::new("client", "reject"),
        )
        .await
        {
            Ok(_) => panic!("https gRPC must be rejected until a2a-rs#162"),
            Err(err) => err,
        };
        assert!(
            https.message.contains("a2a-rs#162"),
            "{}",
            https.message
        );
    }

    #[test]
    fn response_to_message_synthesizes_task_status_when_empty() {
        let task = Task {
            id: "task-9".to_string(),
            context_id: "ctx".to_string(),
            status: TaskStatus {
                state: TaskState::Completed,
                message: None,
                timestamp: None,
            },
            artifacts: None,
            history: None,
            metadata: None,
        };
        let message = response_to_message(SendMessageResponse::Task(task));
        let text = message
            .parts
            .iter()
            .filter_map(Part::as_text)
            .collect::<Vec<_>>()
            .join(" ");
        assert!(text.contains("task-9"), "{text}");
        assert!(text.contains("Completed"), "{text}");
    }

    #[test]
    fn dest_did_is_a_routing_key_not_a_locator() {
        let message = insert_dest_did(
            Message::new(Role::User, vec![Part::text("hi".to_string())]),
            "did:key:zPeer",
        );
        assert_eq!(dest_did_from_message(&message), Some("did:key:zPeer"));
        assert_eq!(
            message
                .metadata
                .as_ref()
                .and_then(|m| m.get(A2A_DST_DID_METADATA_KEY))
                .and_then(|v| v.as_str()),
            Some("did:key:zPeer")
        );
        let unlabeled = Message::new(Role::User, vec![Part::text("hi".to_string())]);
        assert_eq!(dest_did_from_message(&unlabeled), None);
        let empty = insert_dest_did(unlabeled, "");
        assert_eq!(dest_did_from_message(&empty), None);
    }

    #[test]
    fn grpc_group_rejects_empty_or_incomplete_roster() {
        let ctx = SessionContext::new("moderator", "group");
        let empty = A2AGroupChannel::grpc(Vec::new(), Arc::new(AllowVerifier), ctx.clone());
        assert!(empty.is_err());
        let incomplete = A2AGroupChannel::grpc(
            vec![GroupMember {
                agent_id: "peer".to_string(),
                did: String::new(),
                url: "http://127.0.0.1:9".to_string(),
                binding: A2ABinding::Grpc,
            }],
            Arc::new(AllowVerifier),
            ctx,
        );
        assert!(incomplete.is_err());
    }

    struct EchoExecutor;

    impl a2a_server::AgentExecutor for EchoExecutor {
        fn execute(
            &self,
            ctx: a2a_server::ExecutorContext,
        ) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
            let text = ctx
                .message
                .as_ref()
                .map(|message| {
                    message
                        .parts
                        .iter()
                        .filter_map(Part::as_text)
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_default();
            let reply = Message::new(
                Role::Agent,
                vec![Part::text(format!("echo:{text}"))],
            );
            Box::pin(futures::stream::once(async move { Ok(StreamResponse::Message(reply)) }))
        }

        fn cancel(
            &self,
            ctx: a2a_server::ExecutorContext,
        ) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
            let task = Task {
                id: ctx.task_id,
                context_id: ctx.context_id,
                status: TaskStatus {
                    state: TaskState::Canceled,
                    message: None,
                    timestamp: None,
                },
                artifacts: None,
                history: None,
                metadata: None,
            };
            Box::pin(futures::stream::once(async move { Ok(StreamResponse::Task(task)) }))
        }
    }

    async fn serve_loopback_grpc() -> (String, tokio::task::JoinHandle<()>) {
        let incoming = tonic::transport::server::TcpIncoming::bind("127.0.0.1:0".parse().unwrap())
            .expect("bind loopback");
        let addr = incoming.local_addr().expect("local addr");
        let handler = Arc::new(a2a_server::DefaultRequestHandler::new(
            EchoExecutor,
            a2a_server::InMemoryTaskStore::new(),
        ));
        let handle = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(a2a_pb::a2a_service_server::A2aServiceServer::new(
                    a2a_grpc::GrpcHandler::new(handler),
                ))
                .serve_with_incoming(incoming)
                .await
                .expect("serve gRPC");
        });
        (format!("http://{addr}"), handle)
    }

    #[tokio::test]
    async fn grpc_loopback_send_message_without_slim() {
        let (url, server) = serve_loopback_grpc().await;
        let channel = A2AChannel::grpc(
            url,
            Arc::new(AllowVerifier),
            SessionContext::new("client", "loopback"),
        )
        .await
        .expect("connect gRPC");
        let params = ServiceParams::new();
        let req = SendMessageRequest {
            message: Message::new(Role::User, vec![Part::text("ping".to_string())]),
            configuration: None,
            metadata: None,
            tenant: None,
        };
        let response = channel
            .send_message(&params, &req)
            .await
            .expect("send_message over loopback gRPC");
        let message = response_to_message(response);
        let text = message
            .parts
            .iter()
            .filter_map(Part::as_text)
            .collect::<Vec<_>>()
            .join(" ");
        assert!(text.contains("echo:ping"), "{text}");
        server.abort();
    }

    #[tokio::test]
    async fn grpc_group_fanout_tags_roster_did() {
        let (url, server) = serve_loopback_grpc().await;
        let group = A2AGroupChannel::grpc(
            vec![
                GroupMember {
                    agent_id: "alpha".to_string(),
                    did: "did:key:zAlpha".to_string(),
                    url: url.clone(),
                    binding: A2ABinding::Grpc,
                },
                GroupMember {
                    agent_id: "beta".to_string(),
                    did: "did:key:zBeta".to_string(),
                    url,
                    binding: A2ABinding::Grpc,
                },
            ],
            Arc::new(AllowVerifier),
            SessionContext::new("moderator", "fanout"),
        )
        .expect("group");
        let outbound = futures::stream::iter([Message::new(
            Role::User,
            vec![Part::text("hello-group".to_string())],
        )]);
        let mut replies = group
            .collaborate(outbound, Some(std::time::Duration::from_secs(5)))
            .expect("collaborate");
        let first = replies.next().await.expect("alpha reply").expect("ok");
        let second = replies.next().await.expect("beta reply").expect("ok");
        let dids = [
            first
                .metadata
                .as_ref()
                .and_then(|m| m.get(A2A_SRC_DID_METADATA_KEY))
                .and_then(|v| v.as_str()),
            second
                .metadata
                .as_ref()
                .and_then(|m| m.get(A2A_SRC_DID_METADATA_KEY))
                .and_then(|v| v.as_str()),
        ];
        assert!(dids.contains(&Some("did:key:zAlpha")));
        assert!(dids.contains(&Some("did:key:zBeta")));
        server.abort();
    }

    async fn serve_loopback_http(
        binding: A2ABinding,
    ) -> (A2ALocator, tokio::task::JoinHandle<()>) {
        let handler = Arc::new(a2a_server::DefaultRequestHandler::new(
            EchoExecutor,
            a2a_server::InMemoryTaskStore::new(),
        ));
        let router = match binding {
            A2ABinding::Jsonrpc => a2a_server::jsonrpc::jsonrpc_router(handler),
            A2ABinding::HttpJson => a2a_server::rest::rest_router(handler),
            A2ABinding::Grpc | A2ABinding::Slim => panic!("use serve_loopback_grpc"),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback HTTP");
        let addr = listener.local_addr().expect("local addr");
        let handle = tokio::spawn(async move {
            axum::serve(listener, router).await.expect("serve HTTP");
        });
        (
            A2ALocator::new(binding, format!("http://{addr}")),
            handle,
        )
    }

    async fn assert_loopback_echo(locator: A2ALocator) {
        let channel = A2AChannel::connect(
            locator,
            Arc::new(AllowVerifier),
            SessionContext::new("client", "loopback"),
        )
        .await
        .expect("connect");
        let params = ServiceParams::new();
        let req = SendMessageRequest {
            message: Message::new(Role::User, vec![Part::text("ping".to_string())]),
            configuration: None,
            metadata: None,
            tenant: None,
        };
        let response = channel
            .send_message(&params, &req)
            .await
            .expect("send_message");
        let message = response_to_message(response);
        let text = message
            .parts
            .iter()
            .filter_map(Part::as_text)
            .collect::<Vec<_>>()
            .join(" ");
        assert!(text.contains("echo:ping"), "{text}");
    }

    #[tokio::test]
    async fn echo_executor_cancel_emits_canceled_task() {
        let ctx = a2a_server::ExecutorContext {
            message: None,
            task_id: "task-cancel".to_string(),
            stored_task: None,
            context_id: "ctx-cancel".to_string(),
            metadata: None,
            user: None,
            service_params: Default::default(),
            tenant: None,
        };
        let mut stream = a2a_server::AgentExecutor::cancel(&EchoExecutor, ctx);
        let event = stream.next().await.expect("event").expect("ok");
        match event {
            StreamResponse::Task(task) => {
                assert_eq!(task.id, "task-cancel");
                assert_eq!(task.status.state, TaskState::Canceled);
            }
            other => panic!("expected canceled task, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn jsonrpc_loopback_send_message_without_slim() {
        let (locator, server) = serve_loopback_http(A2ABinding::Jsonrpc).await;
        assert_loopback_echo(locator).await;
        server.abort();
    }

    #[tokio::test]
    async fn http_json_loopback_send_message_without_slim() {
        let (locator, server) = serve_loopback_http(A2ABinding::HttpJson).await;
        assert_loopback_echo(locator).await;
        server.abort();
    }
}
