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
            self.app,
            self.remote,
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
        req: &CreateTaskPushNotificationConfigRequest,
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
    use futures::stream;

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
            _req: &CreateTaskPushNotificationConfigRequest,
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
}
