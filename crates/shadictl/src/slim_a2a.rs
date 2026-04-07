use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use a2a::event::StreamResponse;
use a2a::*;
use a2a_client::A2AClient;
use a2a_server::{
    AgentExecutor, DefaultRequestHandler, InMemoryTaskStore, RequestHandler,
    ServiceParams as A2AServiceParams,
};
use agent_secrets::{AgentSecretAccess, AgentVerifier, SecretResult, SessionContext};
use async_trait::async_trait;
use futures::stream::BoxStream;
use shadi_a2a::{A2AChannelBuilder, SlimRpcHandler};
use slim_bindings::{Server, Service};
use tokio::runtime::Builder as TokioRuntimeBuilder;
use tokio::sync::Notify;

use crate::cli_types::{SlimA2AEchoPeerArgs, SlimA2ASendArgs};
use crate::slim_shell::{
    build_client_config_for_endpoint, build_server_config_for_endpoint, format_slim_error,
    parse_name, resolve_client_tls_material_for_agent, resolve_default_shared_secret,
    resolve_server_tls_material,
};

const DEFAULT_SLIM_ENDPOINT: &str = "127.0.0.1:47357";
pub(crate) const SHELL_A2A_ECHO_PEER_USAGE: &str =
    "usage: /slim a2a-echo-peer [--endpoint HOST:PORT] [--agent-id ID] [--listen-timeout SECONDS] [--ready-file PATH] [--start-local-node]";
pub(crate) const SHELL_A2A_SEND_USAGE: &str =
    "usage: /slim a2a-send [--endpoint HOST:PORT] [--agent-id ID] [--peer-agent-id ID] [--destination NAME] [--message TEXT...] [--stream] [--timeout SECONDS] [--session-id ID]";

struct VerifiedSessionVerifier;

impl AgentVerifier for VerifiedSessionVerifier {
    fn verify(&self, session: &SessionContext) -> SecretResult<()> {
        AgentSecretAccess::require_verified(session)
    }
}

struct SlimA2AExecutor {
    agent_name: String,
}

#[async_trait]
impl AgentExecutor for SlimA2AExecutor {
    fn execute(
        &self,
        ctx: a2a_server::ExecutorContext,
    ) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
        let input = ctx
            .message
            .as_ref()
            .map(readable_message_text)
            .unwrap_or_else(|| "(no request message)".to_string());
        let response = Message {
            message_id: new_message_id(),
            context_id: Some(ctx.context_id.clone()),
            task_id: Some(ctx.task_id.clone()),
            role: Role::Agent,
            parts: vec![Part::text(format!("echo:{}:{}", self.agent_name, input))],
            metadata: None,
            extensions: None,
            reference_task_ids: None,
        };
        let history = ctx.message.clone().map(|message| vec![message]);

        Box::pin(futures::stream::iter(vec![
            Ok(StreamResponse::StatusUpdate(TaskStatusUpdateEvent {
                task_id: ctx.task_id.clone(),
                context_id: ctx.context_id.clone(),
                status: TaskStatus {
                    state: TaskState::Working,
                    message: None,
                    timestamp: None,
                },
                metadata: None,
            })),
            Ok(StreamResponse::Task(Task {
                id: ctx.task_id,
                context_id: ctx.context_id,
                status: TaskStatus {
                    state: TaskState::Completed,
                    message: Some(response),
                    timestamp: None,
                },
                artifacts: None,
                history,
                metadata: None,
            })),
        ]))
    }

    fn cancel(
        &self,
        ctx: a2a_server::ExecutorContext,
    ) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
        Box::pin(futures::stream::once(async move {
            Ok(StreamResponse::Task(Task {
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
            }))
        }))
    }
}

struct SlimA2AHandler {
    inner: DefaultRequestHandler,
    card: AgentCard,
    request_seen: Arc<Notify>,
}

impl SlimA2AHandler {
    fn new(agent_name: String, target: String, request_seen: Arc<Notify>) -> Self {
        Self {
            inner: DefaultRequestHandler::new(
                SlimA2AExecutor {
                    agent_name: agent_name.clone(),
                },
                InMemoryTaskStore::new(),
            ),
            card: a2a_agent_card(&agent_name, &target),
            request_seen,
        }
    }
}

#[async_trait]
impl RequestHandler for SlimA2AHandler {
    async fn send_message(
        &self,
        params: &A2AServiceParams,
        req: SendMessageRequest,
    ) -> Result<SendMessageResponse, A2AError> {
        let result = self.inner.send_message(params, req).await;
        if result.is_ok() {
            self.request_seen.notify_waiters();
        }
        result
    }

    async fn send_streaming_message(
        &self,
        params: &A2AServiceParams,
        req: SendMessageRequest,
    ) -> Result<BoxStream<'static, Result<StreamResponse, A2AError>>, A2AError> {
        let result = self.inner.send_streaming_message(params, req).await;
        if result.is_ok() {
            self.request_seen.notify_waiters();
        }
        result
    }

    async fn get_task(
        &self,
        params: &A2AServiceParams,
        req: GetTaskRequest,
    ) -> Result<Task, A2AError> {
        self.inner.get_task(params, req).await
    }

    async fn list_tasks(
        &self,
        params: &A2AServiceParams,
        req: ListTasksRequest,
    ) -> Result<ListTasksResponse, A2AError> {
        self.inner.list_tasks(params, req).await
    }

    async fn cancel_task(
        &self,
        params: &A2AServiceParams,
        req: CancelTaskRequest,
    ) -> Result<Task, A2AError> {
        self.inner.cancel_task(params, req).await
    }

    async fn subscribe_to_task(
        &self,
        params: &A2AServiceParams,
        req: SubscribeToTaskRequest,
    ) -> Result<BoxStream<'static, Result<StreamResponse, A2AError>>, A2AError> {
        self.inner.subscribe_to_task(params, req).await
    }

    async fn create_push_config(
        &self,
        params: &A2AServiceParams,
        req: CreateTaskPushNotificationConfigRequest,
    ) -> Result<TaskPushNotificationConfig, A2AError> {
        self.inner.create_push_config(params, req).await
    }

    async fn get_push_config(
        &self,
        params: &A2AServiceParams,
        req: GetTaskPushNotificationConfigRequest,
    ) -> Result<TaskPushNotificationConfig, A2AError> {
        self.inner.get_push_config(params, req).await
    }

    async fn list_push_configs(
        &self,
        params: &A2AServiceParams,
        req: ListTaskPushNotificationConfigsRequest,
    ) -> Result<ListTaskPushNotificationConfigsResponse, A2AError> {
        self.inner.list_push_configs(params, req).await
    }

    async fn delete_push_config(
        &self,
        params: &A2AServiceParams,
        req: DeleteTaskPushNotificationConfigRequest,
    ) -> Result<(), A2AError> {
        self.inner.delete_push_config(params, req).await
    }

    async fn get_extended_agent_card(
        &self,
        _params: &A2AServiceParams,
        _req: GetExtendedAgentCardRequest,
    ) -> Result<AgentCard, A2AError> {
        Ok(self.card.clone())
    }
}

pub(crate) fn run_a2a_echo_peer(args: SlimA2AEchoPeerArgs) -> Result<(), String> {
    let endpoint = resolve_endpoint(args.endpoint.as_deref());
    let shared_secret = resolve_default_shared_secret()?;
    let peer_name = slim_name(&args.agent_id);
    let client_tls = resolve_client_tls_material_for_agent(Some(&args.agent_id))?;
    let server_tls = resolve_server_tls_material()?;

    let node_service = if args.start_local_node {
        let service = Service::new(format!("shadictl-a2a-node-{}", std::process::id()));
        service
            .run_server(build_server_config_for_endpoint(&endpoint, &server_tls))
            .map_err(format_slim_error)?;
        thread::sleep(Duration::from_millis(300));
        Some(service)
    } else {
        None
    };

    let service = Service::new(format!("shadictl-a2a-peer-{}", std::process::id()));
    let connection_id = service
        .connect(build_client_config_for_endpoint(&endpoint, &client_tls))
        .map_err(format_slim_error)?;
    let peer_name_ref = Arc::new(parse_name(&peer_name)?);
    let app = service
        .create_app_with_secret(peer_name_ref.clone(), shared_secret)
        .map_err(format_slim_error)?;
    app.subscribe(peer_name_ref.clone(), Some(connection_id))
        .map_err(format_slim_error)?;

    let server = Arc::new(Server::new(&app, app.name().clone()));
    let request_seen = Arc::new(Notify::new());
    let handler = Arc::new(SlimA2AHandler::new(
        peer_name.clone(),
        format!("slimrpc://{}", peer_name),
        request_seen.clone(),
    ));
    SlimRpcHandler::new(handler).register(&server);

    let ready_file = args.ready_file.clone();
    let wait_seconds = args.listen_timeout_seconds;
    let endpoint_label = endpoint.clone();
    let peer_label = peer_name.clone();
    let runtime = TokioRuntimeBuilder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| format!("failed to create tokio runtime: {}", err))?;

    let serve_result = runtime.block_on(async move {
        let server_task = {
            let server = server.clone();
            tokio::spawn(async move {
                server
                    .serve_async()
                    .await
                    .map_err(|err| format!("A2A SLIMRPC server failed: {}", err))
            })
        };

        tokio::time::sleep(Duration::from_millis(300)).await;
        if let Some(ready_file) = &ready_file {
            fs::write(ready_file, b"ready")
                .map_err(|err| format!("failed to write {}: {}", ready_file.display(), err))?;
        }

        println!("[shadictl a2a-peer] ready as {} on {}", peer_label, endpoint_label);

        let request_result = tokio::time::timeout(
            Duration::from_secs(wait_seconds),
            request_seen.notified(),
        )
        .await;

        if request_result.is_ok() {
            tokio::time::sleep(Duration::from_millis(300)).await;
        }

        server.shutdown_async().await;
        let server_status = server_task
            .await
            .map_err(|err| format!("failed to join A2A SLIMRPC server task: {}", err))?;
        server_status?;

        request_result.map_err(|_| {
            format!(
                "timed out waiting for A2A request after {}s",
                wait_seconds
            )
        })?;

        Ok::<(), String>(())
    });

    let _ = app.unsubscribe(peer_name_ref, Some(connection_id));
    let _ = service.disconnect(connection_id);
    let _ = service.shutdown();

    if let Some(service) = node_service {
        let _ = service.stop_server(endpoint.clone());
        let _ = service.shutdown();
    }

    serve_result
}

pub(crate) fn run_a2a_send(args: SlimA2ASendArgs) -> Result<(), String> {
    let detail = run_a2a_send_once(&args)?;
    println!("{}", detail);
    Ok(())
}

pub(crate) fn parse_shell_a2a_echo_peer_args(
    args: &[&str],
) -> Result<SlimA2AEchoPeerArgs, String> {
    let mut parsed = SlimA2AEchoPeerArgs {
        endpoint: None,
        agent_id: "secops-a".to_string(),
        listen_timeout_seconds: 20,
        ready_file: None,
        start_local_node: false,
    };

    let mut index = 0;
    while index < args.len() {
        match args[index] {
            "--endpoint" => {
                parsed.endpoint = Some(next_value(args, &mut index, SHELL_A2A_ECHO_PEER_USAGE)?.to_string());
            }
            "--agent-id" => {
                parsed.agent_id = next_value(args, &mut index, SHELL_A2A_ECHO_PEER_USAGE)?.to_string();
            }
            "--listen-timeout" | "--listen-timeout-seconds" => {
                let value = next_value(args, &mut index, SHELL_A2A_ECHO_PEER_USAGE)?;
                parsed.listen_timeout_seconds = value
                    .parse::<u64>()
                    .map_err(|_| format!("invalid timeout value: {value}"))?;
            }
            "--ready-file" => {
                parsed.ready_file = Some(PathBuf::from(next_value(
                    args,
                    &mut index,
                    SHELL_A2A_ECHO_PEER_USAGE,
                )?));
            }
            "--start-local-node" => {
                parsed.start_local_node = true;
            }
            _ => return Err(SHELL_A2A_ECHO_PEER_USAGE.to_string()),
        }
        index += 1;
    }

    Ok(parsed)
}

pub(crate) fn parse_shell_a2a_send_args(args: &[&str]) -> Result<SlimA2ASendArgs, String> {
    let mut parsed = SlimA2ASendArgs {
        endpoint: None,
        agent_id: "avatar".to_string(),
        peer_agent_id: "secops-a".to_string(),
        destination: None,
        message: "hello from SHADI A2A".to_string(),
        stream: false,
        timeout_seconds: 20,
        session_id: "shadictl-a2a-session".to_string(),
    };

    let mut index = 0;
    while index < args.len() {
        match args[index] {
            "--endpoint" => {
                parsed.endpoint = Some(next_value(args, &mut index, SHELL_A2A_SEND_USAGE)?.to_string());
            }
            "--agent-id" => {
                parsed.agent_id = next_value(args, &mut index, SHELL_A2A_SEND_USAGE)?.to_string();
            }
            "--peer-agent-id" => {
                parsed.peer_agent_id = next_value(args, &mut index, SHELL_A2A_SEND_USAGE)?.to_string();
            }
            "--destination" => {
                parsed.destination = Some(next_value(args, &mut index, SHELL_A2A_SEND_USAGE)?.to_string());
            }
            "--message" => {
                let (message, next_index) = collect_message_value(args, index + 1)?;
                parsed.message = message;
                index = next_index;
                continue;
            }
            "--stream" => {
                parsed.stream = true;
            }
            "--timeout" | "--timeout-seconds" => {
                let value = next_value(args, &mut index, SHELL_A2A_SEND_USAGE)?;
                parsed.timeout_seconds = value
                    .parse::<u64>()
                    .map_err(|_| format!("invalid timeout value: {value}"))?;
            }
            "--session-id" => {
                parsed.session_id = next_value(args, &mut index, SHELL_A2A_SEND_USAGE)?.to_string();
            }
            _ => return Err(SHELL_A2A_SEND_USAGE.to_string()),
        }
        index += 1;
    }

    Ok(parsed)
}

fn run_a2a_send_once(args: &SlimA2ASendArgs) -> Result<String, String> {
    let endpoint = resolve_endpoint(args.endpoint.as_deref());
    let shared_secret = resolve_default_shared_secret()?;
    let client_tls = resolve_client_tls_material_for_agent(Some(&args.agent_id))?;
    let local_name = slim_name(&args.agent_id);
    let destination = args
        .destination
        .clone()
        .unwrap_or_else(|| slim_name(&args.peer_agent_id));

    let service = Service::new(format!("shadictl-a2a-client-{}", std::process::id()));
    let connection_id = service
        .connect(build_client_config_for_endpoint(&endpoint, &client_tls))
        .map_err(format_slim_error)?;
    let local_name_ref = Arc::new(parse_name(&local_name)?);
    let remote_name_ref = Arc::new(parse_name(&destination)?);
    let app = service
        .create_app_with_secret(local_name_ref.clone(), shared_secret)
        .map_err(format_slim_error)?;
    app.subscribe(local_name_ref.clone(), Some(connection_id))
        .map_err(format_slim_error)?;

    let mut session = SessionContext::new(&args.agent_id, &args.session_id);
    session.verified = true;
    let verifier: Arc<dyn AgentVerifier> = Arc::new(VerifiedSessionVerifier);
    let channel = A2AChannelBuilder::new(app.clone(), remote_name_ref, verifier, session)
        .connection_id(connection_id)
        .build();
    let client = A2AClient::new(Box::new(channel));
    let request = SendMessageRequest {
        message: Message::new(Role::User, vec![Part::text(args.message.clone())]),
        configuration: None,
        metadata: None,
        tenant: None,
    };

    let runtime = TokioRuntimeBuilder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| format!("failed to create tokio runtime: {}", err))?;
    let response_detail = runtime
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(args.timeout_seconds), async {
                if args.stream {
                    use futures::StreamExt;

                    let stream = client.send_streaming_message(&request).await?;
                    let events = stream.collect::<Vec<_>>().await;
                    client.destroy().await?;
                    Ok::<String, A2AError>(describe_a2a_stream(&events))
                } else {
                    let response = client.send_message(&request).await?;
                    client.destroy().await?;
                    Ok::<String, A2AError>(describe_a2a_response(&response))
                }
            })
            .await
            .map_err(|_| {
                A2AError::internal(format!(
                    "timed out waiting for A2A response after {}s",
                    args.timeout_seconds
                ))
            })?
        })
        .map_err(|err| format!("failed to send A2A message: {}", err))?;

    let _ = app.unsubscribe(local_name_ref, Some(connection_id));
    let _ = service.disconnect(connection_id);
    let _ = service.shutdown();

    Ok(format!(
        "sent {:?} to {} via {} and received {}",
        args.message,
        destination,
        local_name,
        response_detail
    ))
}

fn resolve_endpoint(override_value: Option<&str>) -> String {
    override_value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            std::env::var("SLIM_ENDPOINT")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .unwrap_or_else(|| DEFAULT_SLIM_ENDPOINT.to_string())
}

fn next_value<'a>(args: &'a [&'a str], index: &mut usize, usage: &str) -> Result<&'a str, String> {
    if *index + 1 >= args.len() {
        return Err(usage.to_string());
    }
    *index += 1;
    Ok(args[*index])
}

fn collect_message_value(args: &[&str], start: usize) -> Result<(String, usize), String> {
    if start >= args.len() {
        return Err(SHELL_A2A_SEND_USAGE.to_string());
    }

    let mut end = start;
    while end < args.len() && !is_send_flag(args[end]) {
        end += 1;
    }

    if end == start {
        return Err(SHELL_A2A_SEND_USAGE.to_string());
    }

    Ok((args[start..end].join(" "), end))
}

fn is_send_flag(token: &str) -> bool {
    matches!(
        token,
        "--endpoint"
            | "--agent-id"
            | "--peer-agent-id"
            | "--destination"
            | "--message"
            | "--stream"
            | "--timeout"
            | "--timeout-seconds"
            | "--session-id"
    )
}

fn slim_name(agent_id: &str) -> String {
    if agent_id.contains('/') {
        agent_id.to_string()
    } else {
        format!("agntcy/shadi/{}", agent_id)
    }
}

fn readable_message_text(message: &Message) -> String {
    let text = message
        .parts
        .iter()
        .filter_map(Part::as_text)
        .collect::<Vec<_>>()
        .join(" ");
    if text.is_empty() {
        "(no text parts)".to_string()
    } else {
        text
    }
}

fn describe_a2a_response(response: &SendMessageResponse) -> String {
    match response {
        SendMessageResponse::Message(message) => {
            format!("message {:?}", readable_message_text(message))
        }
        SendMessageResponse::Task(task) => {
            let detail = task
                .status
                .message
                .as_ref()
                .map(readable_message_text)
                .unwrap_or_else(|| format!("state {:?}", task.status.state));
            format!("task {} ({})", task.id, detail)
        }
    }
}

fn describe_a2a_stream(events: &[Result<StreamResponse, A2AError>]) -> String {
    let mut descriptions = Vec::new();
    for event in events {
        match event {
            Ok(StreamResponse::StatusUpdate(update)) => {
                descriptions.push(format!("status {:?}", update.status.state));
            }
            Ok(StreamResponse::Task(task)) => descriptions.push(format!(
                "task {} ({})",
                task.id,
                task.status
                    .message
                    .as_ref()
                    .map(readable_message_text)
                    .unwrap_or_else(|| format!("state {:?}", task.status.state))
            )),
            Ok(StreamResponse::Message(message)) => {
                descriptions.push(format!("message {:?}", readable_message_text(message)));
            }
            Ok(StreamResponse::ArtifactUpdate(update)) => {
                descriptions.push(format!("artifact {}", update.task_id));
            }
            Err(error) => descriptions.push(format!("error {}", error)),
        }
    }
    format!("stream [{}]", descriptions.join(", "))
}

fn a2a_agent_card(agent_name: &str, target: &str) -> AgentCard {
    AgentCard {
        name: format!("SHADI CLI A2A Peer ({})", agent_name),
        description: "shadictl A2A peer exposed over SLIMRPC".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        supported_interfaces: vec![AgentInterface::new(
            target.to_string(),
            TRANSPORT_PROTOCOL_SLIMRPC,
        )],
        capabilities: AgentCapabilities {
            streaming: Some(true),
            push_notifications: Some(false),
            extensions: None,
            extended_agent_card: Some(true),
        },
        default_input_modes: vec!["text/plain".to_string()],
        default_output_modes: vec!["text/plain".to_string()],
        skills: Vec::new(),
        provider: None,
        documentation_url: None,
        icon_url: None,
        security_schemes: None,
        security_requirements: None,
        signatures: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_secrets::SecretError;

    #[test]
    fn slim_name_canonicalizes_bare_agent_ids() {
        assert_eq!(slim_name("avatar"), "agntcy/shadi/avatar");
        assert_eq!(slim_name("agntcy/other/agent"), "agntcy/other/agent");
    }

    #[test]
    fn describe_a2a_response_formats_message_and_task_variants() {
        let message = SendMessageResponse::Message(Message::new(
            Role::Agent,
            vec![Part::text("hello from shadictl")],
        ));
        assert_eq!(
            describe_a2a_response(&message),
            "message \"hello from shadictl\""
        );

        let task = SendMessageResponse::Task(Task {
            id: "task-1".to_string(),
            context_id: "context-1".to_string(),
            status: TaskStatus {
                state: TaskState::Completed,
                message: Some(Message::new(Role::Agent, vec![Part::text("done")])),
                timestamp: None,
            },
            artifacts: None,
            history: None,
            metadata: None,
        });
        assert_eq!(describe_a2a_response(&task), "task task-1 (done)");
    }

    #[test]
    fn describe_a2a_stream_formats_status_and_task_events() {
        let events = vec![
            Ok(StreamResponse::StatusUpdate(TaskStatusUpdateEvent {
                task_id: "task-1".to_string(),
                context_id: "context-1".to_string(),
                status: TaskStatus {
                    state: TaskState::Working,
                    message: None,
                    timestamp: None,
                },
                metadata: None,
            })),
            Ok(StreamResponse::Task(Task {
                id: "task-1".to_string(),
                context_id: "context-1".to_string(),
                status: TaskStatus {
                    state: TaskState::Completed,
                    message: Some(Message::new(Role::Agent, vec![Part::text("stream done")])),
                    timestamp: None,
                },
                artifacts: None,
                history: None,
                metadata: None,
            })),
        ];

        assert_eq!(
            describe_a2a_stream(&events),
            "stream [status Working, task task-1 (stream done)]"
        );
    }

    #[test]
    fn verified_session_verifier_requires_verified_session() {
        let verifier = VerifiedSessionVerifier;
        let unverified = SessionContext::new("avatar", "session-1");
        let err = verifier.verify(&unverified).unwrap_err();
        assert!(matches!(err, SecretError::NotAuthorized));

        let mut verified = SessionContext::new("avatar", "session-2");
        verified.verified = true;
        verifier.verify(&verified).expect("verified session should pass");
    }

    #[test]
    fn parse_shell_a2a_send_args_supports_multiword_message_and_flags() {
        let parsed = parse_shell_a2a_send_args(&[
            "--agent-id",
            "avatar",
            "--peer-agent-id",
            "secops-a",
            "--message",
            "hello",
            "from",
            "shell",
            "--stream",
            "--timeout",
            "7",
            "--session-id",
            "shell-session",
        ])
        .expect("parse shell args");

        assert_eq!(parsed.agent_id, "avatar");
        assert_eq!(parsed.peer_agent_id, "secops-a");
        assert_eq!(parsed.message, "hello from shell");
        assert!(parsed.stream);
        assert_eq!(parsed.timeout_seconds, 7);
        assert_eq!(parsed.session_id, "shell-session");
    }

    #[test]
    fn parse_shell_a2a_echo_peer_args_supports_overrides() {
        let parsed = parse_shell_a2a_echo_peer_args(&[
            "--endpoint",
            "127.0.0.1:48555",
            "--agent-id",
            "secops-a",
            "--listen-timeout",
            "12",
            "--ready-file",
            "/tmp/ready.flag",
            "--start-local-node",
        ])
        .expect("parse shell peer args");

        assert_eq!(parsed.endpoint.as_deref(), Some("127.0.0.1:48555"));
        assert_eq!(parsed.agent_id, "secops-a");
        assert_eq!(parsed.listen_timeout_seconds, 12);
        assert_eq!(parsed.ready_file, Some(PathBuf::from("/tmp/ready.flag")));
        assert!(parsed.start_local_node);
    }

    #[test]
    fn parse_shell_a2a_send_args_rejects_missing_message_value() {
        let err = parse_shell_a2a_send_args(&["--message"]).unwrap_err();
        assert_eq!(err, SHELL_A2A_SEND_USAGE);
    }
}