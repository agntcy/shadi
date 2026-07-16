// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use a2a::event::StreamResponse;
use a2a::*;
use a2a_client::transport::{ServiceParams, Transport};
use a2a_slimrpc::SlimRpcTransport;
use agent_secrets::{AgentVerifier, SecretError, SessionContext};
use async_trait::async_trait;
use futures::stream::BoxStream;
use slim_bindings::{App, Name};

fn secret_err_to_a2a(err: SecretError) -> A2AError {
    A2AError::internal(format!("SHADI auth error: {err}"))
}

/// An A2A channel between two agentic apps over SLIMRPC, guarded by SHADI
/// identity verification.
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
        A2AChannel {
            transport: Box::new(transport),
            verifier: self.verifier,
            ctx: self.ctx,
        }
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
}
