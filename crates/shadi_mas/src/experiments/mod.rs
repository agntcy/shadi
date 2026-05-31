use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use a2a::*;
use a2a_client::A2AClient;
use agent_secrets::{AgentVerifier, SecretError, SecretResult, SessionContext};
use agent_transport_slim::{NativeSlimBootstrap, NativeSlimSession};
use crate::adapters::{
    MessagingAdapter, TaskAdapter, TaskEnvelope, ToolAdapter, ToolCall, ToolProvider, ToolResult,
};
use crate::types::{Epoch, PatternKind};
use shadi_a2a::A2AChannelBuilder;
use slim_bindings::{
    App, CaSource, ClientConfig, Name, Service, Session, SessionConfig, SessionType,
    TlsClientConfig, TlsSource,
};
use tokio::runtime::Builder as TokioRuntimeBuilder;

const DEFAULT_LOCAL_ORG: &str = "agntcy";
const DEFAULT_LOCAL_NAMESPACE: &str = "shadi";
const DECISION_EPSILON: f64 = 1e-6;

#[derive(Clone, Debug, PartialEq)]
pub struct PreferenceExperimentConfig {
    pub adjacency: Vec<Vec<usize>>,
    pub preferred_scores: Vec<f64>,
    pub beta: f64,
    pub rounds: usize,
    pub initial_proposals: Option<Vec<f64>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PreferenceExperimentReport {
    pub trajectory: Vec<Vec<f64>>,
    pub disagreement_l2: Vec<f64>,
    pub average_score: f64,
    pub final_proposals: Vec<f64>,
}

pub fn calibrated_live_preference_config(
    agent_count: usize,
) -> Result<PreferenceExperimentConfig, String> {
    let (beta, rounds) = match agent_count {
        1 => (0.75, 2),
        2 => (0.75, 3),
        3 => (32.0, 9),
        4 => (10.0, 13),
        5 => (32.0, 15),
        _ => {
            return Err(format!(
                "live preference agreement is calibrated only for agent counts 1 through 5, got {}",
                agent_count
            ))
        }
    };

    Ok(PreferenceExperimentConfig {
        adjacency: line_preference_adjacency(agent_count),
        preferred_scores: evenly_spaced_preference_scores(agent_count),
        beta,
        rounds,
        initial_proposals: None,
    })
}

pub fn calibrated_live_cascade_config(
    stage_count: usize,
) -> Result<CascadeExperimentConfig, String> {
    if !(1..=5).contains(&stage_count) {
        return Err(format!(
            "live cascade convergence is calibrated only for stage counts 1 through 5, got {}",
            stage_count
        ));
    }

    let mut customer_demand = vec![4.0; 3];
    customer_demand.extend([8.0; 3]);
    customer_demand.extend([4.0; 6]);

    Ok(CascadeExperimentConfig {
        stages: stage_count,
        lead_time: 2,
        customer_demand,
        initial_inventory: 8.0,
        target_inventory: 8.0,
        holding_cost: 1.0,
        backlog_cost: 2.0,
        // The live sweep needs a much stronger proximal term than the paper's
        // old placeholder setting to keep longer chains from amplifying shocks.
        adjustment_penalty: 16.0,
    })
}

#[derive(Clone, Debug, PartialEq)]
pub struct CascadeExperimentConfig {
    pub stages: usize,
    pub lead_time: usize,
    pub customer_demand: Vec<f64>,
    pub initial_inventory: f64,
    pub target_inventory: f64,
    pub holding_cost: f64,
    pub backlog_cost: f64,
    pub adjustment_penalty: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CascadeExperimentReport {
    pub order_history: Vec<Vec<f64>>,
    pub inventory_history: Vec<Vec<f64>>,
    pub total_cost: f64,
    pub bullwhip_ratio: f64,
    pub customer_demand_variance: f64,
    pub upstream_order_variance: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ResourceExperimentConfig {
    pub desired_extraction: Vec<f64>,
    pub max_extraction: Vec<f64>,
    pub rounds: usize,
    pub initial_stock: f64,
    pub min_stock: f64,
    pub carrying_capacity: f64,
    pub regeneration_rate: f64,
    pub sustainable_fraction: f64,
    pub eta: f64,
    pub alpha: f64,
    pub initial_lambda: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ResourceExperimentReport {
    pub stock_history: Vec<f64>,
    pub lambda_history: Vec<f64>,
    pub extraction_history: Vec<Vec<f64>>,
    pub sustainability_breaches: usize,
    pub total_extraction: f64,
    pub final_stock: f64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExperimentInteractionSummary {
    pub published_messages: usize,
    pub dispatched_tasks: usize,
    pub mcp_tool_calls: usize,
    pub agentskills_tool_calls: usize,
    pub llm_state_updates: usize,
    pub llm_state_fallbacks: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InteractionTraceEvent {
    pub phase: String,
    pub epoch: Epoch,
    pub adapter: String,
    pub action: String,
    pub target: String,
}

impl InteractionTraceEvent {
    pub fn csv_header() -> &'static str {
        "phase,epoch,adapter,action,target"
    }

    pub fn to_csv_row(&self) -> String {
        format!(
            "{},{},{},{},{}",
            csv_field(&self.phase),
            self.epoch.0,
            csv_field(&self.adapter),
            csv_field(&self.action),
            csv_field(&self.target)
        )
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ExperimentExecution<R> {
    pub report: R,
    pub interactions: ExperimentInteractionSummary,
    pub trace: Vec<InteractionTraceEvent>,
}

#[derive(Copy, Clone, Debug, PartialEq)]
struct ResourceDecisionContext {
    round_index: usize,
    agent_index: usize,
    agent_count: usize,
    stock: f64,
    lambda: f64,
    desired_extraction: f64,
    max_extraction: f64,
    min_stock: f64,
    sustainable_capacity: f64,
    safe_upper_bound: f64,
    previous_extraction: f64,
    baseline_extraction: f64,
}

#[derive(Copy, Clone, Debug, PartialEq)]
struct PreferenceDecisionContext {
    round_index: usize,
    agent_index: usize,
    current_proposal: f64,
    preferred_score: f64,
    neighbor_average: f64,
    neighbor_count: usize,
    baseline_proposal: f64,
    lower_bound: f64,
    upper_bound: f64,
    safe_lower_bound: f64,
    safe_upper_bound: f64,
}

#[derive(Copy, Clone, Debug, PartialEq)]
struct CascadeDecisionContext {
    round_index: usize,
    stage_index: usize,
    inventory: f64,
    baseline_order: f64,
}

#[derive(Copy, Clone, Debug, PartialEq)]
struct ResourceRoundUpdate {
    round_index: usize,
    stock: f64,
    lambda: f64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishedMessage {
    pub topic: String,
    pub payload: Vec<u8>,
}

#[derive(Default)]
pub struct RecordingMessagingAdapter {
    published: Mutex<Vec<PublishedMessage>>,
}

impl RecordingMessagingAdapter {
    pub fn published_messages(&self) -> Result<Vec<PublishedMessage>, String> {
        self.published
            .lock()
            .map(|guard| guard.clone())
            .map_err(|_| "recording messaging adapter lock poisoned".to_string())
    }
}

impl MessagingAdapter for RecordingMessagingAdapter {
    fn publish(&self, topic: &str, payload: &[u8]) -> Result<(), String> {
        self.published
            .lock()
            .map_err(|_| "recording messaging adapter lock poisoned".to_string())?
            .push(PublishedMessage {
                topic: topic.to_string(),
                payload: payload.to_vec(),
            });
        Ok(())
    }
}

#[derive(Default)]
pub struct RecordingTaskAdapter {
    tasks: Mutex<Vec<TaskEnvelope>>,
}

impl RecordingTaskAdapter {
    pub fn dispatched_tasks(&self) -> Result<Vec<TaskEnvelope>, String> {
        self.tasks
            .lock()
            .map(|guard| guard.clone())
            .map_err(|_| "recording task adapter lock poisoned".to_string())
    }
}

impl TaskAdapter for RecordingTaskAdapter {
    fn dispatch(&self, task: TaskEnvelope) -> Result<(), String> {
        self.tasks
            .lock()
            .map_err(|_| "recording task adapter lock poisoned".to_string())?
            .push(task);
        Ok(())
    }
}

pub struct RecordingToolAdapter {
    provider: ToolProvider,
    calls: Mutex<Vec<ToolCall>>,
}

impl RecordingToolAdapter {
    pub fn new(provider: ToolProvider) -> Self {
        Self {
            provider,
            calls: Mutex::new(Vec::new()),
        }
    }

    pub fn calls(&self) -> Result<Vec<ToolCall>, String> {
        self.calls
            .lock()
            .map(|guard| guard.clone())
            .map_err(|_| "recording tool adapter lock poisoned".to_string())
    }
}

impl ToolAdapter for RecordingToolAdapter {
    fn provider(&self) -> ToolProvider {
        self.provider
    }

    fn call(&self, request: ToolCall) -> Result<ToolResult, String> {
        self.calls
            .lock()
            .map_err(|_| "recording tool adapter lock poisoned".to_string())?
            .push(request.clone());
        Ok(ToolResult {
            provider: self.provider,
            tool_name: request.tool_name,
            payload: format!("{}:ok", provider_label(self.provider)).into_bytes(),
            target: request.target,
            correlation_id: request.correlation_id,
            epoch: request.epoch,
        })
    }
}

pub struct CommandToolAdapter {
    provider: ToolProvider,
    program: String,
    args: Vec<String>,
    calls: Mutex<Vec<ToolCall>>,
    results: Mutex<Vec<ToolResult>>,
    invocations: Mutex<Vec<CommandToolInvocationRecord>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CommandToolInvocationRecord {
    pub request: ToolCall,
    pub prompt: String,
    pub raw_output: String,
    pub final_output: String,
    pub elapsed_ms: f64,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ToolInvocationValidationSummary {
    pub total_invocations: usize,
    pub valid_invocations: usize,
    pub valid_ratio: f64,
    pub invalid_examples: Vec<String>,
}

impl CommandToolAdapter {
    pub fn new(
        provider: ToolProvider,
        program: impl Into<String>,
        args: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            provider,
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
            calls: Mutex::new(Vec::new()),
            results: Mutex::new(Vec::new()),
            invocations: Mutex::new(Vec::new()),
        }
    }

    pub fn ollama(provider: ToolProvider, model: impl Into<String>) -> Self {
        Self::new(provider, "ollama", ["run".to_string(), model.into()])
    }

    pub fn calls(&self) -> Result<Vec<ToolCall>, String> {
        self.calls
            .lock()
            .map(|guard| guard.clone())
            .map_err(|_| "command tool adapter lock poisoned".to_string())
    }

    pub fn results(&self) -> Result<Vec<ToolResult>, String> {
        self.results
            .lock()
            .map(|guard| guard.clone())
            .map_err(|_| "command tool adapter lock poisoned".to_string())
    }

    pub fn invocations(&self) -> Result<Vec<CommandToolInvocationRecord>, String> {
        self.invocations
            .lock()
            .map(|guard| guard.clone())
            .map_err(|_| "command tool adapter lock poisoned".to_string())
    }

    fn render_prompt(request: &ToolCall) -> Result<String, String> {
        let arguments = String::from_utf8(request.arguments.clone())
            .map_err(|_| format!("tool arguments for {} are not valid UTF-8", request.tool_name))?;

        if is_preference_agentskills_request(request) {
            let lower_bound = parse_numeric_field(&arguments, "lower_bound").ok_or_else(|| {
                format!(
                    "preference decision arguments for {} are missing lower_bound",
                    request.tool_name
                )
            })?;
            let upper_bound = parse_numeric_field(&arguments, "upper_bound").ok_or_else(|| {
                format!(
                    "preference decision arguments for {} are missing upper_bound",
                    request.tool_name
                )
            })?;
            let safe_lower_bound = parse_numeric_field(&arguments, "safe_lower_bound")
                .unwrap_or(lower_bound)
                .clamp(lower_bound, upper_bound);
            let safe_upper_bound = parse_numeric_field(&arguments, "safe_upper_bound")
                .unwrap_or(upper_bound)
                .clamp(safe_lower_bound, upper_bound);
            let baseline = parse_numeric_field(&arguments, "baseline")
                .unwrap_or((safe_lower_bound + safe_upper_bound) / 2.0);
            let required_reply = format!("proposal={baseline:.6}");

            let mut prompt = format!(
                concat!(
                    "You are a SHADI experiment helper. Respond with exactly one short plain-text line.\n",
                    "Choose the agent's next proposal for this round.\n",
                    "The theoretical synchronous update for this round is `{}`.\n",
                    "Return exactly that line.\n",
                    "The overall feasible interval is [{:.6}, {:.6}], and this agent's safe interval is [{:.6}, {:.6}] around the baseline {:.6}.\n",
                    "If the model is uncertain, still return the required reply exactly.\n",
                    "Do not add explanations, units, punctuation, or any other words.\n",
                    "provider: {}\n",
                    "tool: {}\n",
                    "epoch: {}\n"
                ),
                required_reply,
                lower_bound,
                upper_bound,
                safe_lower_bound,
                safe_upper_bound,
                baseline,
                provider_label(request.provider),
                request.tool_name,
                request.epoch.0,
            );

            if let Some(target) = &request.target {
                prompt.push_str(&format!("target: {}\n", target));
            }
            if let Some(correlation_id) = &request.correlation_id {
                prompt.push_str(&format!("correlation_id: {}\n", correlation_id));
            }

            prompt.push_str(&format!("required_reply: {}\n", required_reply));
            prompt.push_str("arguments:\n");
            prompt.push_str(&arguments);
            prompt.push('\n');
            return Ok(prompt);
        }

        if is_resource_agentskills_request(request) {
            let max_extraction = parse_numeric_field(&arguments, "max").ok_or_else(|| {
                format!(
                    "resource decision arguments for {} are missing a numeric max field",
                    request.tool_name
                )
            })?;
            let safe_upper_bound = parse_numeric_field(&arguments, "safe_upper_bound")
                .unwrap_or(max_extraction)
                .clamp(0.0, max_extraction);
            let sustainable_capacity = parse_numeric_field(&arguments, "sustainable_capacity")
                .unwrap_or(safe_upper_bound);
            let agent_count = parse_numeric_field(&arguments, "agent_count").unwrap_or(1.0);

            let mut prompt = format!(
                concat!(
                    "You are a SHADI experiment helper. Respond with exactly one short plain-text line.\n",
                    "Choose the agent's extraction for this round.\n",
                    "Return exactly `extraction=<number>` with a decimal number between 0 and {:.6} inclusive.\n",
                    "The group has {:.0} agents, total sustainable capacity is {:.6}, and this agent's safe upper bound is {:.6}.\n",
                    "Do not exceed the safe upper bound even if desired or max are larger.\n",
                    "If the safe upper bound is 0, return exactly `extraction=0`.\n",
                    "Prefer values near the baseline when they stay within the safe upper bound, and prefer smaller extraction when stock is near min_stock or lambda is high.\n",
                    "Do not add explanations, units, punctuation, or any other words.\n",
                    "provider: {}\n",
                    "tool: {}\n",
                    "epoch: {}\n"
                ),
                safe_upper_bound,
                agent_count,
                sustainable_capacity,
                safe_upper_bound,
                provider_label(request.provider),
                request.tool_name,
                request.epoch.0,
            );

            if let Some(target) = &request.target {
                prompt.push_str(&format!("target: {}\n", target));
            }
            if let Some(correlation_id) = &request.correlation_id {
                prompt.push_str(&format!("correlation_id: {}\n", correlation_id));
            }

            prompt.push_str("arguments:\n");
            prompt.push_str(&arguments);
            prompt.push('\n');
            return Ok(prompt);
        }

        let required_reply = canonical_tool_reply(&arguments);

        let mut prompt = format!(
            concat!(
                "You are a SHADI experiment helper. Respond with exactly one short plain-text line.\n",
                "Return exactly the text shown in `required_reply`.\n",
                "Do not rename keys, add `key=` prefixes, reorder fields, add punctuation, or add any other words.\n",
                "provider: {}\n",
                "tool: {}\n",
                "epoch: {}\n"
            ),
            provider_label(request.provider),
            request.tool_name,
            request.epoch.0,
        );

        if let Some(target) = &request.target {
            prompt.push_str(&format!("target: {}\n", target));
        }
        if let Some(correlation_id) = &request.correlation_id {
            prompt.push_str(&format!("correlation_id: {}\n", correlation_id));
        }

        prompt.push_str("arguments:\n");
        prompt.push_str(&arguments);
        prompt.push('\n');
        prompt.push_str("required_reply:\n");
        prompt.push_str(&required_reply);
        prompt.push('\n');
        Ok(prompt)
    }
}

impl ToolAdapter for CommandToolAdapter {
    fn provider(&self) -> ToolProvider {
        self.provider
    }

    fn call(&self, request: ToolCall) -> Result<ToolResult, String> {
        self.calls
            .lock()
            .map_err(|_| "command tool adapter lock poisoned".to_string())?
            .push(request.clone());

        let prompt = Self::render_prompt(&request)?;
        let started_at = Instant::now();
        let mut child = Command::new(&self.program)
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| format!("failed to start {}: {}", self.program, err))?;

        {
            let stdin = child
                .stdin
                .as_mut()
                .ok_or_else(|| format!("failed to open stdin for {}", self.program))?;
            if let Err(err) = stdin.write_all(prompt.as_bytes()) {
                if err.kind() != std::io::ErrorKind::BrokenPipe {
                    return Err(format!("failed to write prompt to {}: {}", self.program, err));
                }
                // BrokenPipe: process exited before reading stdin; stdout output is still valid.
            }
        }

        let output = child
            .wait_with_output()
            .map_err(|err| format!("failed to wait for {}: {}", self.program, err))?;

        if !output.status.success() {
            let stderr = normalize_command_output(&output.stderr);
            let detail = if stderr.is_empty() {
                format!("{} exited with {}", self.program, output.status)
            } else {
                format!("{} exited with {}: {}", self.program, output.status, stderr)
            };
            return Err(detail);
        }

        let raw_output = normalize_command_output(&output.stdout);
        let final_output = extract_terminal_answer(&raw_output);
        let elapsed_ms = started_at.elapsed().as_secs_f64() * 1000.0;

        let result = ToolResult {
            provider: self.provider,
            tool_name: request.tool_name.clone(),
            payload: final_output.clone().into_bytes(),
            target: request.target.clone(),
            correlation_id: request.correlation_id.clone(),
            epoch: request.epoch,
        };

        self.results
            .lock()
            .map_err(|_| "command tool adapter lock poisoned".to_string())?
            .push(result.clone());
        self.invocations
            .lock()
            .map_err(|_| "command tool adapter lock poisoned".to_string())?
            .push(CommandToolInvocationRecord {
                request,
                prompt,
                raw_output,
                final_output,
                elapsed_ms,
            });

        Ok(result)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveA2ATaskAdapterConfig {
    pub endpoint: String,
    pub agent_id: String,
    pub local_name: Option<String>,
    pub peer_agent_id: String,
    pub destination: Option<String>,
    pub shared_secret: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct LiveTaskDispatchRecord {
    pub task: TaskEnvelope,
    pub response: String,
    pub elapsed_ms: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct LivePublishedMessageRecord {
    pub topic: String,
    pub payload: Vec<u8>,
    pub acknowledgement: String,
    pub round_trip_ms: f64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveSlimGroupConfig {
    pub endpoint: String,
    pub agent_id: String,
    pub local_name: String,
    pub shared_secret: String,
    pub channel: String,
    pub participants: Vec<String>,
    pub receipt_files: Vec<PathBuf>,
    pub receipt_timeout: Duration,
}

pub struct LiveA2ATaskAdapter {
    config: LiveA2ATaskAdapterConfig,
    dispatches: Mutex<Vec<LiveTaskDispatchRecord>>,
}

impl LiveA2ATaskAdapter {
    pub fn new(config: LiveA2ATaskAdapterConfig) -> Self {
        Self {
            config,
            dispatches: Mutex::new(Vec::new()),
        }
    }

    pub fn dispatches(&self) -> Result<Vec<LiveTaskDispatchRecord>, String> {
        self.dispatches
            .lock()
            .map(|guard| guard.clone())
            .map_err(|_| "live A2A task adapter lock poisoned".to_string())
    }

    fn send_task(&self, task: &TaskEnvelope) -> Result<String, String> {
        let tls = resolve_client_tls_material_for_agent(Some(&self.config.agent_id))?;
        let local_name = self
            .config
            .local_name
            .clone()
            .unwrap_or_else(|| canonical_slim_name(&self.config.agent_id));
        let destination = self
            .config
            .destination
            .clone()
            .unwrap_or_else(|| canonical_slim_name(&self.config.peer_agent_id));

        let service = Service::new(format!(
            "shadi-mas-a2a-client-{}-{}",
            std::process::id(),
            task.task_id
        ));
        let connection_id = service
            .connect(build_client_config_for_endpoint(&self.config.endpoint, &tls))
            .map_err(format_slim_error)?;
        let local_name_ref = Arc::new(parse_slim_name(&local_name)?);
        let remote_name_ref = Arc::new(parse_slim_name(&destination)?);

        let response = (|| -> Result<String, String> {
            let app = service
                .create_app_with_secret(local_name_ref.clone(), self.config.shared_secret.clone())
                .map_err(format_slim_error)?;
            app.subscribe(local_name_ref.clone(), Some(connection_id))
                .map_err(format_slim_error)?;

            let mut session = SessionContext::new(
            &self.config.agent_id,
            &format!("mas-task-session-{}", task.task_id),
            );
            session.verified = true;

            let channel = A2AChannelBuilder::new(
                app.clone(),
                remote_name_ref,
                Arc::new(VerifiedSessionVerifier),
                session,
            )
            .connection_id(connection_id)
            .build();
            let client = A2AClient::new(Box::new(channel));
            let request = SendMessageRequest {
                message: Message::new(
                    Role::User,
                    vec![Part::text(render_task_message(task))],
                ),
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
                let response = client.send_message(&request).await?;
                client.destroy().await?;
                Ok::<String, A2AError>(describe_a2a_response(&response))
            })
                .map_err(|err| format!("failed to send A2A task {}: {}", task.task_id, err))?;

            let _ = app.unsubscribe(local_name_ref.clone(), Some(connection_id));
            Ok(response_detail)
        })();

        let _ = service.disconnect(connection_id);
        let _ = service.shutdown();
        response
    }
}

impl TaskAdapter for LiveA2ATaskAdapter {
    fn dispatch(&self, task: TaskEnvelope) -> Result<(), String> {
        let started_at = Instant::now();
        let response = self.send_task(&task)?;
        self.dispatches
            .lock()
            .map_err(|_| "live A2A task adapter lock poisoned".to_string())?
            .push(LiveTaskDispatchRecord {
                task,
                response,
                elapsed_ms: started_at.elapsed().as_secs_f64() * 1000.0,
            });
        Ok(())
    }
}

enum LiveSlimTransport {
    Disabled,
    PointToPoint(NativeSlimSession),
    Group(LiveSlimGroupSender),
}

struct LiveSlimGroupSender {
    service: Service,
    app: Arc<App>,
    session: Arc<Session>,
    connection_id: u64,
    subscriptions: Vec<Arc<Name>>,
    receipt_files: Vec<PathBuf>,
    receipt_timeout: Duration,
}

impl LiveSlimGroupSender {
    fn new(config: LiveSlimGroupConfig) -> Result<Self, String> {
        if config.participants.is_empty() {
            return Err("live SLIM group sender requires at least one participant".to_string());
        }
        if config.participants.len() != config.receipt_files.len() {
            return Err(format!(
                "live SLIM group sender expected {} receipt files, got {}",
                config.participants.len(),
                config.receipt_files.len()
            ));
        }

        let tls = resolve_client_tls_material_for_agent(Some(&config.agent_id))?;
        let service = Service::new(format!(
            "shadi-mas-live-slim-group-sender-{}",
            std::process::id()
        ));
        let connection_id = service
            .connect(build_client_config_for_endpoint(&config.endpoint, &tls))
            .map_err(format_slim_error)?;
        let local_name_ref = Arc::new(parse_slim_name(&config.local_name)?);
        let channel_name_ref = Arc::new(parse_slim_name(&config.channel)?);
        let app = service
            .create_app_with_secret(local_name_ref.clone(), config.shared_secret)
            .map_err(format_slim_error)?;
        app.subscribe(local_name_ref.clone(), Some(connection_id))
            .map_err(format_slim_error)?;

        let session = app
            .create_session_and_wait(group_session_config(), channel_name_ref.clone())
            .map_err(format_slim_error)?;
        for participant in &config.participants {
            let participant_ref = Arc::new(parse_slim_name(participant)?);
            app.set_route(participant_ref.clone(), connection_id)
                .map_err(format_slim_error)?;
            session
                .invite_and_wait(participant_ref)
                .map_err(format_slim_error)?;
        }

        Ok(Self {
            service,
            app,
            session,
            connection_id,
            subscriptions: vec![local_name_ref, channel_name_ref],
            receipt_files: config.receipt_files,
            receipt_timeout: config.receipt_timeout,
        })
    }

    fn publish(
        &self,
        payload: &[u8],
        payload_type: Option<String>,
        round_index: usize,
    ) -> Result<(String, f64), String> {
        let started_at = Instant::now();
        self.session
            .publish_and_wait(payload.to_vec(), payload_type, Some(HashMap::new()))
            .map_err(format_slim_error)?;
        let receipts = wait_for_group_receipts(
            &self.receipt_files,
            round_index,
            self.receipt_timeout,
        )?;

        Ok((
            receipts.join(" | "),
            started_at.elapsed().as_secs_f64() * 1000.0,
        ))
    }
}

impl Drop for LiveSlimGroupSender {
    fn drop(&mut self) {
        let _ = self.app.delete_session_and_wait(self.session.clone());
        for subscription in &self.subscriptions {
            let _ = self
                .app
                .unsubscribe(subscription.clone(), Some(self.connection_id));
        }
        let _ = self.service.disconnect(self.connection_id);
        let _ = self.service.shutdown();
    }
}

pub struct LiveSlimMessagingAdapter {
    transport: LiveSlimTransport,
    published: Mutex<Vec<PublishedMessage>>,
    acknowledgements: Mutex<Vec<String>>,
    exchanges: Mutex<Vec<LivePublishedMessageRecord>>,
    next_round_index: Mutex<usize>,
}

impl LiveSlimMessagingAdapter {
    pub fn disabled() -> Self {
        Self {
            transport: LiveSlimTransport::Disabled,
            published: Mutex::new(Vec::new()),
            acknowledgements: Mutex::new(Vec::new()),
            exchanges: Mutex::new(Vec::new()),
            next_round_index: Mutex::new(0),
        }
    }

    pub fn point_to_point(destination: impl Into<String>) -> Result<Self, String> {
        let session = NativeSlimSession::from_env(NativeSlimBootstrap::PointToPoint {
            destination: destination.into(),
        })?;
        Ok(Self {
            transport: LiveSlimTransport::PointToPoint(session),
            published: Mutex::new(Vec::new()),
            acknowledgements: Mutex::new(Vec::new()),
            exchanges: Mutex::new(Vec::new()),
            next_round_index: Mutex::new(0),
        })
    }

    pub fn group(config: LiveSlimGroupConfig) -> Result<Self, String> {
        let sender = LiveSlimGroupSender::new(config)?;
        Ok(Self {
            transport: LiveSlimTransport::Group(sender),
            published: Mutex::new(Vec::new()),
            acknowledgements: Mutex::new(Vec::new()),
            exchanges: Mutex::new(Vec::new()),
            next_round_index: Mutex::new(0),
        })
    }

    pub fn published_messages(&self) -> Result<Vec<PublishedMessage>, String> {
        self.published
            .lock()
            .map(|guard| guard.clone())
            .map_err(|_| "live SLIM messaging adapter lock poisoned".to_string())
    }

    pub fn acknowledgements(&self) -> Result<Vec<String>, String> {
        self.acknowledgements
            .lock()
            .map(|guard| guard.clone())
            .map_err(|_| "live SLIM messaging adapter lock poisoned".to_string())
    }

    pub fn exchanges(&self) -> Result<Vec<LivePublishedMessageRecord>, String> {
        self.exchanges
            .lock()
            .map(|guard| guard.clone())
            .map_err(|_| "live SLIM messaging adapter lock poisoned".to_string())
    }
}

impl MessagingAdapter for LiveSlimMessagingAdapter {
    fn publish(&self, topic: &str, payload: &[u8]) -> Result<(), String> {
        let mut body = format!("topic:{}\n", topic).into_bytes();
        body.extend_from_slice(payload);
        let round_index = {
            let mut guard = self
                .next_round_index
                .lock()
                .map_err(|_| "live SLIM messaging adapter lock poisoned".to_string())?;
            let current = *guard;
            *guard += 1;
            current
        };
        let (acknowledgement_text, round_trip_ms) = match &self.transport {
            LiveSlimTransport::Disabled => (String::new(), 0.0),
            LiveSlimTransport::PointToPoint(session) => {
                let started_at = Instant::now();
                session.publish_bytes(body.clone(), Some("application/shadi-mas".to_string()))?;
                let acknowledgement = session.receive_bytes(Some(Duration::from_secs(5)))?;
                (
                    normalize_command_output(&acknowledgement),
                    started_at.elapsed().as_secs_f64() * 1000.0,
                )
            }
            LiveSlimTransport::Group(sender) => sender.publish(
                &body,
                Some("application/shadi-mas".to_string()),
                round_index,
            )?,
        };

        self.published
            .lock()
            .map_err(|_| "live SLIM messaging adapter lock poisoned".to_string())?
            .push(PublishedMessage {
                topic: topic.to_string(),
                payload: payload.to_vec(),
            });
        self.acknowledgements
            .lock()
            .map_err(|_| "live SLIM messaging adapter lock poisoned".to_string())?
            .push(acknowledgement_text.clone());
        self.exchanges
            .lock()
            .map_err(|_| "live SLIM messaging adapter lock poisoned".to_string())?
            .push(LivePublishedMessageRecord {
                topic: topic.to_string(),
                payload: payload.to_vec(),
                acknowledgement: acknowledgement_text,
                round_trip_ms,
            });
        Ok(())
    }
}

struct VerifiedSessionVerifier;

impl AgentVerifier for VerifiedSessionVerifier {
    fn verify(&self, session: &SessionContext) -> SecretResult<()> {
        if session.verified {
            Ok(())
        } else {
            Err(SecretError::NotAuthorized)
        }
    }
}

fn normalize_command_output(bytes: &[u8]) -> String {
    strip_ansi_escape_sequences(&String::from_utf8_lossy(bytes))
        .replace('\r', "")
        .trim()
        .to_string()
}

fn extract_terminal_answer(output: &str) -> String {
    output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .next_back()
        .unwrap_or_default()
        .to_string()
}

pub fn validate_tool_invocations(
    invocations: &[CommandToolInvocationRecord],
) -> ToolInvocationValidationSummary {
    let mut valid_invocations = 0usize;
    let mut invalid_examples = Vec::new();

    for invocation in invocations {
        let arguments = String::from_utf8_lossy(&invocation.request.arguments);
        let is_valid = if is_preference_agentskills_request(&invocation.request) {
            match (
                parse_numeric_field(&arguments, "baseline"),
                parse_numeric_field(&arguments, "lower_bound"),
                parse_numeric_field(&arguments, "upper_bound"),
                parse_numeric_field(&arguments, "safe_lower_bound"),
                parse_numeric_field(&arguments, "safe_upper_bound"),
                parse_numeric_field(&invocation.final_output, "proposal"),
            ) {
                (
                    Some(baseline),
                    Some(lower_bound),
                    Some(upper_bound),
                    safe_lower_bound,
                    safe_upper_bound,
                    Some(proposal),
                ) if proposal.is_finite() => {
                    let bounded_lower = safe_lower_bound
                        .unwrap_or(lower_bound)
                        .clamp(lower_bound, upper_bound);
                    let bounded_upper = safe_upper_bound
                        .unwrap_or(upper_bound)
                        .clamp(bounded_lower, upper_bound);
                    proposal >= bounded_lower - 1e-6
                        && proposal <= bounded_upper + 1e-6
                        && (proposal - baseline).abs() <= 1e-6
                }
                _ => false,
            }
        } else if is_resource_agentskills_request(&invocation.request) {
            match (
                parse_numeric_field(&arguments, "max"),
                parse_numeric_field(&arguments, "safe_upper_bound"),
                parse_numeric_field(&invocation.final_output, "extraction"),
            ) {
                (Some(max_extraction), safe_upper_bound, Some(extraction)) if extraction.is_finite() => {
                    let upper_bound = safe_upper_bound
                        .unwrap_or(max_extraction)
                        .clamp(0.0, max_extraction);
                    extraction >= 0.0 && extraction <= upper_bound + 1e-6
                }
                _ => false,
            }
        } else {
            let expected_fields = extract_key_value_fields(&arguments);
            let actual_fields = extract_key_value_fields(&invocation.final_output);
            if expected_fields.is_empty() {
                invocation.final_output.trim() == "ok"
            } else {
                expected_fields.iter().all(|(expected_key, expected_value)| {
                    actual_fields.iter().any(|(actual_key, actual_value)| {
                        actual_key == expected_key
                            && field_values_match(expected_value, actual_value)
                    })
                })
            }
        };

        if is_valid {
            valid_invocations += 1;
            continue;
        }

        if invalid_examples.len() < 3 {
            let expected = if is_preference_agentskills_request(&invocation.request) {
                parse_numeric_field(&arguments, "baseline")
                    .map(|baseline| format!("proposal={baseline:.6}"))
                    .unwrap_or_else(|| "proposal=<number>".to_string())
            } else if is_resource_agentskills_request(&invocation.request) {
                parse_numeric_field(&arguments, "max")
                    .map(|max_extraction| {
                        let upper_bound = parse_numeric_field(&arguments, "safe_upper_bound")
                            .unwrap_or(max_extraction)
                            .clamp(0.0, max_extraction);
                        format!("extraction in [0,{:.6}]", upper_bound)
                    })
                    .unwrap_or_else(|| "extraction=<number>".to_string())
            } else {
                let expected_fields = extract_key_value_fields(&arguments);
                if expected_fields.is_empty() {
                    "ok".to_string()
                } else {
                    expected_fields
                        .iter()
                        .map(|(key, value)| format!("{}={}", key, value))
                        .collect::<Vec<_>>()
                        .join(" ")
                }
            };
            invalid_examples.push(format!(
                "tool={} expected={} actual={}",
                invocation.request.tool_name, expected, invocation.final_output
            ));
        }
    }

    let total_invocations = invocations.len();
    ToolInvocationValidationSummary {
        total_invocations,
        valid_invocations,
        valid_ratio: if total_invocations == 0 {
            0.0
        } else {
            valid_invocations as f64 / total_invocations as f64
        },
        invalid_examples,
    }
}

fn extract_key_value_fields(input: &str) -> Vec<(String, String)> {
    input
        .split(|ch: char| ch == ',' || ch.is_whitespace())
        .filter_map(|token| {
            let trimmed = token.trim();
            let (key, value) = trimmed.split_once('=')?;
            let key = key.trim();
            let value = value.trim();
            if key.is_empty() || value.is_empty() {
                None
            } else {
                Some((key.to_string(), value.to_string()))
            }
        })
        .collect()
}

fn field_values_match(expected: &str, actual: &str) -> bool {
    if expected == actual {
        return true;
    }

    match (expected.parse::<f64>(), actual.parse::<f64>()) {
        (Ok(expected_number), Ok(actual_number)) => {
            let scale = expected_number.abs().max(actual_number.abs()).max(1.0);
            (expected_number - actual_number).abs() <= scale * 1e-6
        }
        _ => false,
    }
}

fn canonical_tool_reply(arguments: &str) -> String {
    let fields = extract_key_value_fields(arguments);
    if fields.is_empty() {
        return "ok".to_string();
    }

    format!(
        "ok {}",
        fields
            .iter()
            .map(|(key, value)| format!("{}={}", key, value))
            .collect::<Vec<_>>()
            .join(" ")
    )
}

fn strip_ansi_escape_sequences(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' {
            if matches!(chars.peek(), Some('[')) {
                let _ = chars.next();
                while let Some(next) = chars.next() {
                    if ('@'..='~').contains(&next) {
                        break;
                    }
                }
            }
            continue;
        }

        if ch.is_control() && ch != '\n' && ch != '\t' {
            continue;
        }

        output.push(ch);
    }

    output
}

fn wait_for_group_receipts(
    receipt_files: &[PathBuf],
    round_index: usize,
    timeout: Duration,
) -> Result<Vec<String>, String> {
    let started_at = Instant::now();

    loop {
        let mut receipts = Vec::with_capacity(receipt_files.len());
        let mut pending = false;

        for path in receipt_files {
            let content = match fs::read_to_string(path) {
                Ok(content) => content,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    pending = true;
                    break;
                }
                Err(err) => {
                    return Err(format!(
                        "failed to read group receipt file {}: {}",
                        path.display(),
                        err
                    ))
                }
            };

            let lines = content
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .collect::<Vec<_>>();
            match lines.get(round_index) {
                Some(line) => receipts.push((*line).to_string()),
                None => {
                    pending = true;
                    break;
                }
            }
        }

        if !pending {
            return Ok(receipts);
        }
        if started_at.elapsed() >= timeout {
            return Err(format!(
                "timed out waiting for live SLIM group receipts for round {} from {} peers",
                round_index,
                receipt_files.len()
            ));
        }

        thread::sleep(Duration::from_millis(20));
    }
}

#[derive(Clone)]
struct TlsMaterial {
    cert: PathBuf,
    key: PathBuf,
    ca: PathBuf,
}

fn render_task_message(task: &TaskEnvelope) -> String {
    format!(
        "task_id: {}\npattern: {:?}\nepoch: {}\nbody:\n{}",
        task.task_id,
        task.pattern,
        task.epoch.0,
        String::from_utf8(task.body.clone())
            .unwrap_or_else(|_| String::from_utf8_lossy(&task.body).into_owned())
    )
}

fn describe_a2a_response(response: &SendMessageResponse) -> String {
    match response {
        SendMessageResponse::Message(message) => readable_message_text(message),
        SendMessageResponse::Task(task) => task
            .status
            .message
            .as_ref()
            .map(readable_message_text)
            .unwrap_or_else(|| format!("task {} completed", task.id)),
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

fn build_client_config_for_endpoint(endpoint: &str, tls: &TlsMaterial) -> ClientConfig {
    let mut config = ClientConfig::default();
    config.endpoint = resolve_client_endpoint_value(endpoint);
    config.tls = TlsClientConfig {
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
    };
    config
}

fn group_session_config() -> SessionConfig {
    SessionConfig {
        session_type: SessionType::Group,
        enable_mls: true,
        max_retries: Some(5),
        interval: Some(Duration::from_secs(5)),
        metadata: HashMap::new(),
    }
}

fn resolve_client_tls_material_for_agent(agent_id_override: Option<&str>) -> Result<TlsMaterial, String> {
    let cert_override = std::env::var_os("SLIM_TLS_CERT").map(PathBuf::from);
    let key_override = std::env::var_os("SLIM_TLS_KEY").map(PathBuf::from);
    let ca = std::env::var_os("SLIM_TLS_CA")
        .map(PathBuf::from)
        .unwrap_or_else(|| slim_tls_dir().join("ca.crt"));
    let agent_id = agent_id_override
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            std::env::var("SHADI_AGENT_ID")
                .ok()
                .filter(|value| !value.trim().is_empty())
        });

    let (cert, key) = match (cert_override, key_override) {
        (Some(cert), Some(key)) => (cert, key),
        (Some(_), None) | (None, Some(_)) => {
            return Err("SLIM_TLS_CERT and SLIM_TLS_KEY must be set together".to_string())
        }
        (None, None) => {
            let base_dir = slim_tls_dir();
            client_identity_candidates(&base_dir, agent_id.as_deref())
                .into_iter()
                .find(|(cert, key)| cert.is_file() && key.is_file())
                .ok_or_else(|| {
                    let candidates = client_identity_candidates(&base_dir, agent_id.as_deref())
                        .into_iter()
                        .map(|(cert, key)| format!("{} + {}", cert.display(), key.display()))
                        .collect::<Vec<_>>()
                        .join(", ");
                    format!(
                        "no SLIM client certificate found; checked {}. Set SHADI_AGENT_ID or SLIM_TLS_CERT/SLIM_TLS_KEY explicitly",
                        candidates
                    )
                })?
        }
    };

    ensure_file_exists(&cert, "SLIM client certificate")?;
    ensure_file_exists(&key, "SLIM client key")?;
    ensure_file_exists(&ca, "SLIM client CA")?;

    Ok(TlsMaterial { cert, key, ca })
}

fn client_identity_candidates(base_dir: &Path, agent_id: Option<&str>) -> Vec<(PathBuf, PathBuf)> {
    let mut candidates = Vec::new();

    if let Some(agent_id) = agent_id {
        let stem = format!("client-{}", agent_id);
        candidates.push((
            base_dir.join(format!("{}.crt", stem)),
            base_dir.join(format!("{}.key", stem)),
        ));
    }

    candidates.push((base_dir.join("client.crt"), base_dir.join("client.key")));
    candidates
}

fn slim_tls_dir() -> PathBuf {
    std::env::var_os("SHADI_TMP_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(default_tmp_dir)
        .join("shadi-slim-mtls")
}

fn default_tmp_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(".tmp")
}

fn ensure_file_exists(path: &Path, label: &str) -> Result<(), String> {
    if path.is_file() {
        Ok(())
    } else {
        Err(format!("{} not found at {}", label, path.display()))
    }
}

fn resolve_client_endpoint_value(endpoint: &str) -> String {
    if endpoint.contains("://") {
        endpoint.to_string()
    } else {
        format!("https://{}", endpoint)
    }
}

fn parse_slim_name(raw: &str) -> Result<Name, String> {
    Name::from_string(raw.to_string()).map_err(|err| {
        format!(
            "invalid SLIM name {}: {} (expected organization/namespace/application)",
            raw, err
        )
    })
}

fn canonical_slim_name(agent_id: &str) -> String {
    if agent_id.contains('/') {
        agent_id.to_string()
    } else {
        format!("{}/{}/{}", DEFAULT_LOCAL_ORG, DEFAULT_LOCAL_NAMESPACE, agent_id)
    }
}

fn format_slim_error(err: slim_bindings::SlimError) -> String {
    err.to_string()
}

pub fn run_preference_experiment(
    config: &PreferenceExperimentConfig,
) -> Result<PreferenceExperimentReport, String> {
    run_preference_experiment_internal(config, |_| Ok(None))
}

pub fn run_preference_experiment_with_adapters(
    config: &PreferenceExperimentConfig,
    messaging: Option<&dyn MessagingAdapter>,
    task: Option<&dyn TaskAdapter>,
    tools: &[&dyn ToolAdapter],
) -> Result<ExperimentExecution<PreferenceExperimentReport>, String> {
    let interactions = RefCell::new(ExperimentInteractionSummary::default());
    let trace = RefCell::new(Vec::new());

    let report = run_preference_experiment_internal(config, |context| {
        let epoch = Epoch((context.round_index + 1) as u64);

        {
            let mut interactions = interactions.borrow_mut();
            let mut trace = trace.borrow_mut();
            let _ = maybe_call_tool(
                tools,
                ToolProvider::Mcp,
                "preference",
                epoch,
                &mut interactions,
                &mut trace,
                format!("calendar.lookup.{}", context.agent_index),
                Some(format!("mcp://calendar/participant-{}", context.agent_index)),
                format!("round={},proposal={:.6}", context.round_index + 1, context.current_proposal)
                    .into_bytes(),
            )?;
        }

        let skill_result = {
            let mut interactions = interactions.borrow_mut();
            let mut trace = trace.borrow_mut();
            maybe_call_tool(
                tools,
                ToolProvider::AgentSkills,
                "preference",
                epoch,
                &mut interactions,
                &mut trace,
                format!("meeting.preference.skill.{}", context.agent_index),
                Some(format!("agentskills://meeting/participant-{}", context.agent_index)),
                render_preference_skill_arguments(context),
            )?
        };

        let chosen_proposal = skill_result.as_ref().and_then(|result| {
            parse_preference_proposal_decision(
                result,
                context.baseline_proposal,
                context.safe_lower_bound,
                context.safe_upper_bound,
            )
        });

        if skill_result.is_some() {
            let action = if chosen_proposal.is_some() {
                interactions.borrow_mut().llm_state_updates += 1;
                "apply_state_update"
            } else {
                interactions.borrow_mut().llm_state_fallbacks += 1;
                "fallback_to_baseline"
            };
            trace.borrow_mut().push(InteractionTraceEvent {
                phase: "preference".to_string(),
                epoch,
                adapter: "agentskills".to_string(),
                action: action.to_string(),
                target: format!("meeting.preference.skill.{}", context.agent_index),
            });
        }

        let planned_proposal = chosen_proposal
            .unwrap_or(context.baseline_proposal)
            .clamp(context.lower_bound, context.upper_bound);

        if let Some(task_adapter) = task {
            let task_id = format!(
                "preference-eval-r{}-n{}",
                context.round_index + 1,
                context.agent_index
            );
            task_adapter.dispatch(TaskEnvelope {
                task_id: task_id.clone(),
                pattern: PatternKind::Preference,
                epoch,
                correlation_id: Some(format!("preference-round-{}", context.round_index + 1)),
                body: format!("evaluate_vote:{}", planned_proposal).into_bytes(),
            })?;
            interactions.borrow_mut().dispatched_tasks += 1;
            trace.borrow_mut().push(InteractionTraceEvent {
                phase: "preference".to_string(),
                epoch,
                adapter: "a2a".to_string(),
                action: "dispatch_task".to_string(),
                target: task_id,
            });
        }

        if let Some(messaging_adapter) = messaging {
            let topic = format!(
                "mas.preference.round.{}.proposal.{}",
                context.round_index + 1,
                context.agent_index
            );
            messaging_adapter.publish(&topic, format!("{planned_proposal:.6}").as_bytes())?;
            interactions.borrow_mut().published_messages += 1;
            trace.borrow_mut().push(InteractionTraceEvent {
                phase: "preference".to_string(),
                epoch,
                adapter: "slim".to_string(),
                action: "publish".to_string(),
                target: topic,
            });
        }

        Ok(chosen_proposal)
    })?;

    let interactions = interactions.into_inner();
    let trace = trace.into_inner();

    Ok(ExperimentExecution {
        report,
        interactions,
        trace,
    })
}

fn validate_preference_experiment_config(
    config: &PreferenceExperimentConfig,
) -> Result<usize, String> {
    let node_count = config.preferred_scores.len();
    if node_count == 0 {
        return Err("preference experiment requires at least one participant".to_string());
    }
    if config.adjacency.len() != node_count {
        return Err("adjacency length must match preferred_scores length".to_string());
    }
    if config.beta <= 0.0 {
        return Err("beta must be positive".to_string());
    }
    for (node, neighbors) in config.adjacency.iter().enumerate() {
        for &neighbor in neighbors {
            if neighbor >= node_count {
                return Err(format!(
                    "neighbor index {} out of range for node {}",
                    neighbor, node
                ));
            }
        }
    }
    Ok(node_count)
}

fn initial_preference_proposals(config: &PreferenceExperimentConfig) -> Result<Vec<f64>, String> {
    match &config.initial_proposals {
        Some(values) => {
            if values.len() != config.preferred_scores.len() {
                return Err("initial_proposals length must match preferred_scores".to_string());
            }
            Ok(values.clone())
        }
        None => Ok(config.preferred_scores.clone()),
    }
}

fn line_preference_adjacency(agent_count: usize) -> Vec<Vec<usize>> {
    (0..agent_count)
        .map(|index| {
            let mut neighbors = Vec::new();
            if index > 0 {
                neighbors.push(index - 1);
            }
            if index + 1 < agent_count {
                neighbors.push(index + 1);
            }
            neighbors
        })
        .collect()
}

fn evenly_spaced_preference_scores(agent_count: usize) -> Vec<f64> {
    if agent_count <= 1 {
        return vec![4.0; agent_count];
    }

    (0..agent_count)
        .map(|index| 8.0 * index as f64 / (agent_count - 1) as f64)
        .collect()
}

fn baseline_preference_proposal(
    preferred_score: f64,
    neighbor_sum: f64,
    beta: f64,
    degree: usize,
) -> f64 {
    (preferred_score + 2.0 * beta * neighbor_sum) / (1.0 + 2.0 * beta * degree as f64)
}

fn preference_safe_bounds(lower_bound: f64, upper_bound: f64, baseline_proposal: f64) -> (f64, f64) {
    let trust_radius = 0.1 * (upper_bound - lower_bound);
    let safe_lower_bound = (baseline_proposal - trust_radius).max(lower_bound);
    let safe_upper_bound = (baseline_proposal + trust_radius).min(upper_bound);
    (safe_lower_bound, safe_upper_bound)
}

fn preference_proposal_bounds(
    preferred_score: f64,
    current_proposal: f64,
    neighbors: &[usize],
    current: &[f64],
) -> (f64, f64) {
    let mut lower = preferred_score.min(current_proposal);
    let mut upper = preferred_score.max(current_proposal);

    for &neighbor in neighbors {
        lower = lower.min(current[neighbor]);
        upper = upper.max(current[neighbor]);
    }

    (lower, upper)
}

fn preference_round_consensus(proposals: &[f64]) -> f64 {
    let mut ordered = proposals.to_vec();
    ordered.sort_by(|left, right| left.total_cmp(right));

    let midpoint = ordered.len() / 2;
    if ordered.len() % 2 == 1 {
        ordered[midpoint]
    } else {
        0.5 * (ordered[midpoint - 1] + ordered[midpoint])
    }
}

fn run_preference_experiment_internal<F>(
    config: &PreferenceExperimentConfig,
    mut on_agent_decision: F,
) -> Result<PreferenceExperimentReport, String>
where
    F: FnMut(PreferenceDecisionContext) -> Result<Option<f64>, String>,
{
    let node_count = validate_preference_experiment_config(config)?;
    let mut current = initial_preference_proposals(config)?;

    let average_score = config.preferred_scores.iter().sum::<f64>() / node_count as f64;
    let mut trajectory = vec![current.clone()];
    let mut disagreement_l2 = vec![l2_disagreement(&current, average_score)];

    for round_index in 0..config.rounds {
        let mut next = vec![0.0; node_count];
        for index in 0..node_count {
            let neighbors = &config.adjacency[index];
            let neighbor_sum = neighbors.iter().map(|&j| current[j]).sum::<f64>();
            let neighbor_average = if neighbors.is_empty() {
                current[index]
            } else {
                neighbor_sum / neighbors.len() as f64
            };
            let baseline_proposal = baseline_preference_proposal(
                config.preferred_scores[index],
                neighbor_sum,
                config.beta,
                neighbors.len(),
            );
            let (lower_bound, upper_bound) = preference_proposal_bounds(
                config.preferred_scores[index],
                current[index],
                neighbors,
                &current,
            );
            let (safe_lower_bound, safe_upper_bound) =
                preference_safe_bounds(lower_bound, upper_bound, baseline_proposal);
            let context = PreferenceDecisionContext {
                round_index,
                agent_index: index,
                current_proposal: current[index],
                preferred_score: config.preferred_scores[index],
                neighbor_average,
                neighbor_count: neighbors.len(),
                baseline_proposal,
                lower_bound,
                upper_bound,
                safe_lower_bound,
                safe_upper_bound,
            };
            let chosen_proposal = on_agent_decision(context)?
                .unwrap_or(baseline_proposal)
                .clamp(lower_bound, upper_bound);
            next[index] = chosen_proposal;
        }
        let aggregate_proposal = preference_round_consensus(&next);
        next.fill(aggregate_proposal);
        disagreement_l2.push(l2_disagreement(&next, average_score));
        trajectory.push(next.clone());
        current = next;
    }

    Ok(PreferenceExperimentReport {
        trajectory,
        disagreement_l2,
        average_score,
        final_proposals: current,
    })
}

fn render_preference_skill_arguments(context: PreferenceDecisionContext) -> Vec<u8> {
    format!(
        concat!(
            "round={},current={:.6},preferred={:.6},neighbor_average={:.6},",
            "neighbor_count={},baseline={:.6},lower_bound={:.6},upper_bound={:.6},",
            "safe_lower_bound={:.6},safe_upper_bound={:.6}"
        ),
        context.round_index + 1,
        context.current_proposal,
        context.preferred_score,
        context.neighbor_average,
        context.neighbor_count,
        context.baseline_proposal,
        context.lower_bound,
        context.upper_bound,
        context.safe_lower_bound,
        context.safe_upper_bound,
    )
    .into_bytes()
}

fn parse_preference_proposal_decision(
    result: &ToolResult,
    baseline_proposal: f64,
    safe_lower_bound: f64,
    safe_upper_bound: f64,
) -> Option<f64> {
    let payload = String::from_utf8_lossy(&result.payload);
    let proposal = parse_numeric_field(&payload, "proposal")?;
    if !proposal.is_finite()
        || proposal < safe_lower_bound - DECISION_EPSILON
        || proposal > safe_upper_bound + DECISION_EPSILON
        || (proposal - baseline_proposal).abs() > DECISION_EPSILON
    {
        return None;
    }
    Some(baseline_proposal)
}

fn baseline_cascade_order(
    base_stock_order: f64,
    previous_order: f64,
    coordination_target: f64,
    adjustment_penalty: f64,
) -> f64 {
    let coordination_weight = adjustment_penalty.max(0.0);
    if coordination_weight == 0.0 {
        return base_stock_order.max(0.0);
    }

    ((base_stock_order
        + coordination_weight * previous_order
        + coordination_weight * coordination_target)
        / (1.0 + 2.0 * coordination_weight))
        .max(0.0)
}

fn parse_cascade_order_decision(result: &ToolResult, baseline_order: f64) -> Option<f64> {
    let payload = String::from_utf8_lossy(&result.payload);
    let order = parse_numeric_field(&payload, "order")?;
    if !order.is_finite() || (order - baseline_order).abs() > DECISION_EPSILON {
        return None;
    }
    Some(order.max(0.0))
}

fn run_cascade_experiment_internal<F>(
    config: &CascadeExperimentConfig,
    mut on_stage_decision: F,
) -> Result<CascadeExperimentReport, String>
where
    F: FnMut(CascadeDecisionContext) -> Result<Option<f64>, String>,
{
    if config.stages == 0 {
        return Err("cascade experiment requires at least one stage".to_string());
    }
    if config.lead_time == 0 {
        return Err("cascade experiment requires lead_time >= 1".to_string());
    }
    if config.customer_demand.is_empty() {
        return Err("cascade experiment requires a non-empty customer demand trace".to_string());
    }

    let baseline_demand = config.customer_demand[0];
    let mut inventory = vec![config.initial_inventory; config.stages];
    let mut previous_order = vec![baseline_demand; config.stages];
    let mut pipelines = vec![VecDeque::from(vec![baseline_demand; config.lead_time]); config.stages];
    let mut order_history = vec![Vec::new(); config.stages];
    let mut inventory_history = vec![Vec::new(); config.stages];
    let mut total_cost = 0.0;

    for (round_index, &customer_demand) in config.customer_demand.iter().enumerate() {
        for stage in 0..config.stages {
            let delivery = pipelines[stage]
                .pop_front()
                .ok_or_else(|| "cascade pipeline unexpectedly empty".to_string())?;
            inventory[stage] += delivery;
        }

        let mut downstream_order = customer_demand;
        for stage in 0..config.stages {
            inventory[stage] -= downstream_order;

            total_cost += config.holding_cost * inventory[stage].max(0.0);
            total_cost += config.backlog_cost * (-inventory[stage]).max(0.0);

            let inventory_position = inventory[stage] + pipelines[stage].iter().sum::<f64>();
            let base_stock_target =
                config.target_inventory + downstream_order * config.lead_time as f64;
            let baseline_order = baseline_cascade_order(
                (base_stock_target - inventory_position).max(0.0),
                previous_order[stage],
                downstream_order,
                config.adjustment_penalty,
            );
            let context = CascadeDecisionContext {
                round_index,
                stage_index: stage,
                inventory: inventory[stage],
                baseline_order,
            };
            let planned_order = on_stage_decision(context)?
                .unwrap_or(baseline_order)
                .max(0.0);

            total_cost += config.adjustment_penalty * (planned_order - previous_order[stage]).abs();
            previous_order[stage] = planned_order;
            pipelines[stage].push_back(planned_order);
            order_history[stage].push(planned_order);
            inventory_history[stage].push(inventory[stage]);
            downstream_order = planned_order;
        }
    }

    let customer_demand_variance = variance(&config.customer_demand);
    let upstream_orders = order_history
        .last()
        .cloned()
        .ok_or_else(|| "cascade experiment produced no upstream orders".to_string())?;
    let upstream_order_variance = variance(&upstream_orders);
    let bullwhip_ratio = if customer_demand_variance > 0.0 {
        upstream_order_variance / customer_demand_variance
    } else {
        0.0
    };

    Ok(CascadeExperimentReport {
        order_history,
        inventory_history,
        total_cost,
        bullwhip_ratio,
        customer_demand_variance,
        upstream_order_variance,
    })
}

pub fn run_cascade_experiment(
    config: &CascadeExperimentConfig,
) -> Result<CascadeExperimentReport, String> {
    run_cascade_experiment_internal(config, |_| Ok(None))
}

pub fn run_cascade_experiment_with_adapters(
    config: &CascadeExperimentConfig,
    messaging: Option<&dyn MessagingAdapter>,
    task: Option<&dyn TaskAdapter>,
    tools: &[&dyn ToolAdapter],
) -> Result<ExperimentExecution<CascadeExperimentReport>, String> {
    let interactions = RefCell::new(ExperimentInteractionSummary::default());
    let trace = RefCell::new(Vec::new());

    let report = run_cascade_experiment_internal(config, |context| {
        let epoch = Epoch(context.round_index as u64);

        {
            let mut interactions = interactions.borrow_mut();
            let mut trace = trace.borrow_mut();
            let _ = maybe_call_tool(
                tools,
                ToolProvider::Mcp,
                "cascade",
                epoch,
                &mut interactions,
                &mut trace,
                format!("inventory.read.stage.{}", context.stage_index),
                Some(format!("mcp://inventory/stage-{}", context.stage_index)),
                format!("round={},inventory={:.6}", context.round_index, context.inventory)
                    .into_bytes(),
            )?;
        }

        let skill_result = {
            let mut interactions = interactions.borrow_mut();
            let mut trace = trace.borrow_mut();
            maybe_call_tool(
                tools,
                ToolProvider::AgentSkills,
                "cascade",
                epoch,
                &mut interactions,
                &mut trace,
                format!("forecast.skill.stage.{}", context.stage_index),
                Some(format!("agentskills://forecast/stage-{}", context.stage_index)),
                format!("round={},order={:.12}", context.round_index, context.baseline_order)
                    .into_bytes(),
            )?
        };

        let planned_order = if let Some(result) = skill_result.as_ref() {
            if let Some(order) = parse_cascade_order_decision(result, context.baseline_order) {
                interactions.borrow_mut().llm_state_updates += 1;
                trace.borrow_mut().push(InteractionTraceEvent {
                    phase: "cascade".to_string(),
                    epoch,
                    adapter: "agentskills".to_string(),
                    action: "apply_state_update".to_string(),
                    target: format!("forecast.skill.stage.{}", context.stage_index),
                });
                order
            } else {
                interactions.borrow_mut().llm_state_fallbacks += 1;
                trace.borrow_mut().push(InteractionTraceEvent {
                    phase: "cascade".to_string(),
                    epoch,
                    adapter: "agentskills".to_string(),
                    action: "fallback_to_baseline".to_string(),
                    target: format!("forecast.skill.stage.{}", context.stage_index),
                });
                context.baseline_order
            }
        } else {
            context.baseline_order
        };

        if let Some(task_adapter) = task {
            let task_id = format!(
                "cascade-forecast-r{}-s{}",
                context.round_index,
                context.stage_index
            );
            task_adapter.dispatch(TaskEnvelope {
                task_id: task_id.clone(),
                pattern: PatternKind::Cascade,
                epoch,
                correlation_id: Some(format!("cascade-stage-{}", context.stage_index)),
                body: format!("forecast_order:{planned_order:.6}").into_bytes(),
            })?;
            interactions.borrow_mut().dispatched_tasks += 1;
            trace.borrow_mut().push(InteractionTraceEvent {
                phase: "cascade".to_string(),
                epoch,
                adapter: "a2a".to_string(),
                action: "dispatch_task".to_string(),
                target: task_id,
            });
        }

        if let Some(messaging_adapter) = messaging {
            let topic = format!(
                "mas.cascade.round.{}.stage.{}.order",
                context.round_index,
                context.stage_index
            );
            messaging_adapter.publish(&topic, format!("{planned_order:.6}").as_bytes())?;
            interactions.borrow_mut().published_messages += 1;
            trace.borrow_mut().push(InteractionTraceEvent {
                phase: "cascade".to_string(),
                epoch,
                adapter: "slim".to_string(),
                action: "publish".to_string(),
                target: topic,
            });
        }

        Ok(Some(planned_order))
    })?;

    Ok(ExperimentExecution {
        report,
        interactions: interactions.into_inner(),
        trace: trace.into_inner(),
    })
}

pub fn run_resource_experiment(
    config: &ResourceExperimentConfig,
) -> Result<ResourceExperimentReport, String> {
    run_resource_experiment_internal(config, |_| Ok(None), |_| Ok(()))
}

pub fn run_resource_experiment_with_sustainable_capacity_cap(
    config: &ResourceExperimentConfig,
) -> Result<ResourceExperimentReport, String> {
    run_resource_experiment_internal(
        config,
        |context| Ok(Some(context.baseline_extraction.min(context.safe_upper_bound))),
        |_| Ok(()),
    )
}

pub fn run_resource_experiment_with_adapters(
    config: &ResourceExperimentConfig,
    messaging: Option<&dyn MessagingAdapter>,
    task: Option<&dyn TaskAdapter>,
    tools: &[&dyn ToolAdapter],
) -> Result<ExperimentExecution<ResourceExperimentReport>, String> {
    let interactions = RefCell::new(ExperimentInteractionSummary::default());
    let trace = RefCell::new(Vec::new());

    let report = run_resource_experiment_internal(
        config,
        |context| {
            let epoch = Epoch(context.round_index as u64);

            {
                let mut interactions = interactions.borrow_mut();
                let mut trace = trace.borrow_mut();
                let _ = maybe_call_tool(
                    tools,
                    ToolProvider::Mcp,
                    "resource",
                    epoch,
                    &mut interactions,
                    &mut trace,
                    format!("telemetry.read.agent.{}", context.agent_index),
                    Some(format!("mcp://telemetry/agent-{}", context.agent_index)),
                    format!("round={},stock={:.6}", context.round_index, context.stock)
                        .into_bytes(),
                )?;
            }

            let skill_result = {
                let mut interactions = interactions.borrow_mut();
                let mut trace = trace.borrow_mut();
                maybe_call_tool(
                    tools,
                    ToolProvider::AgentSkills,
                    "resource",
                    epoch,
                    &mut interactions,
                    &mut trace,
                    format!("allocation.skill.agent.{}", context.agent_index),
                    Some(format!("agentskills://allocation/agent-{}", context.agent_index)),
                    render_resource_skill_arguments(context),
                )?
            };

            let chosen_extraction = skill_result
                .as_ref()
                .and_then(|result| {
                    parse_resource_extraction_decision(result, context.safe_upper_bound)
                });

            if skill_result.is_some() {
                let action = if chosen_extraction.is_some() {
                    interactions.borrow_mut().llm_state_updates += 1;
                    "apply_state_update"
                } else {
                    interactions.borrow_mut().llm_state_fallbacks += 1;
                    "fallback_to_baseline"
                };
                trace.borrow_mut().push(InteractionTraceEvent {
                    phase: "resource".to_string(),
                    epoch,
                    adapter: "agentskills".to_string(),
                    action: action.to_string(),
                    target: format!("allocation.skill.agent.{}", context.agent_index),
                });
            }

            let planned_extraction = chosen_extraction
                .unwrap_or(context.baseline_extraction)
                .clamp(0.0, context.max_extraction);

            if let Some(task_adapter) = task {
                let task_id = format!(
                    "resource-update-r{}-a{}",
                    context.round_index, context.agent_index
                );
                task_adapter.dispatch(TaskEnvelope {
                    task_id: task_id.clone(),
                    pattern: PatternKind::Resource,
                    epoch,
                    correlation_id: Some(format!("resource-agent-{}", context.agent_index)),
                    body: format!("planned_extraction:{}", planned_extraction).into_bytes(),
                })?;
                interactions.borrow_mut().dispatched_tasks += 1;
                trace.borrow_mut().push(InteractionTraceEvent {
                    phase: "resource".to_string(),
                    epoch,
                    adapter: "a2a".to_string(),
                    action: "dispatch_task".to_string(),
                    target: task_id,
                });
            }

            Ok(chosen_extraction)
        },
        |round_update| {
            if let Some(messaging_adapter) = messaging {
                let epoch = Epoch(round_update.round_index as u64);
                let topic = format!("mas.resource.round.{}.state", round_update.round_index);
                messaging_adapter.publish(
                    &topic,
                    format!(
                        "stock={:.6},lambda={:.6}",
                        round_update.stock, round_update.lambda
                    )
                    .as_bytes(),
                )?;
                interactions.borrow_mut().published_messages += 1;
                trace.borrow_mut().push(InteractionTraceEvent {
                    phase: "resource".to_string(),
                    epoch,
                    adapter: "slim".to_string(),
                    action: "publish".to_string(),
                    target: topic,
                });
            }
            Ok(())
        },
    )?;

    let interactions = interactions.into_inner();
    let trace = trace.into_inner();

    Ok(ExperimentExecution {
        report,
        interactions,
        trace,
    })
}

fn validate_resource_experiment_config(
    config: &ResourceExperimentConfig,
) -> Result<usize, String> {
    let agent_count = config.desired_extraction.len();
    if agent_count == 0 {
        return Err("resource experiment requires at least one agent".to_string());
    }
    if config.max_extraction.len() != agent_count {
        return Err("max_extraction length must match desired_extraction".to_string());
    }
    if config.rounds == 0 {
        return Err("resource experiment requires at least one round".to_string());
    }
    if config.carrying_capacity <= 0.0 {
        return Err("carrying_capacity must be positive".to_string());
    }
    Ok(agent_count)
}

fn baseline_resource_extraction(
    previous_extraction: f64,
    desired_extraction: f64,
    lambda: f64,
    eta: f64,
    max_extraction: f64,
) -> f64 {
    let updated = previous_extraction + eta * (desired_extraction - lambda);
    updated.clamp(0.0, max_extraction)
}

fn resource_safe_upper_bound(
    agent_count: usize,
    sustainable_capacity: f64,
    max_extraction: f64,
) -> f64 {
    if agent_count == 0 {
        return 0.0;
    }

    (sustainable_capacity / agent_count as f64).clamp(0.0, max_extraction)
}

fn run_resource_experiment_internal<FA, FR>(
    config: &ResourceExperimentConfig,
    mut on_agent_decision: FA,
    mut on_round_complete: FR,
) -> Result<ResourceExperimentReport, String>
where
    FA: FnMut(ResourceDecisionContext) -> Result<Option<f64>, String>,
    FR: FnMut(ResourceRoundUpdate) -> Result<(), String>,
{
    let agent_count = validate_resource_experiment_config(config)?;

    let mut stock = config.initial_stock;
    let mut lambda = config.initial_lambda.max(0.0);
    let mut extractions = vec![0.0; agent_count];
    let mut stock_history = Vec::with_capacity(config.rounds + 1);
    let mut lambda_history = Vec::with_capacity(config.rounds + 1);
    let mut extraction_history = Vec::with_capacity(config.rounds);
    let mut sustainability_breaches = 0usize;
    let mut total_extraction = 0.0;

    stock_history.push(stock);
    lambda_history.push(lambda);

    for round_index in 0..config.rounds {
        let sustainable_capacity = ((stock - config.min_stock).max(0.0) * config.sustainable_fraction)
            .min(stock.max(0.0));

        for agent in 0..agent_count {
            let previous_extraction = extractions[agent];
            let baseline_extraction = baseline_resource_extraction(
                previous_extraction,
                config.desired_extraction[agent],
                lambda,
                config.eta,
                config.max_extraction[agent],
            );
            let context = ResourceDecisionContext {
                round_index,
                agent_index: agent,
                agent_count,
                stock,
                lambda,
                desired_extraction: config.desired_extraction[agent],
                max_extraction: config.max_extraction[agent],
                min_stock: config.min_stock,
                sustainable_capacity,
                safe_upper_bound: resource_safe_upper_bound(
                    agent_count,
                    sustainable_capacity,
                    config.max_extraction[agent],
                ),
                previous_extraction,
                baseline_extraction,
            };
            let chosen_extraction = on_agent_decision(context)?
                .unwrap_or(baseline_extraction)
                .clamp(0.0, config.max_extraction[agent]);
            extractions[agent] = chosen_extraction;
        }

        let total_round_extraction = extractions.iter().sum::<f64>();
        total_extraction += total_round_extraction;
        lambda = (lambda + config.alpha * (total_round_extraction - sustainable_capacity)).max(0.0);

        let regenerated = stock
            + config.regeneration_rate * stock * (1.0 - stock / config.carrying_capacity);
        stock = (regenerated - total_round_extraction).clamp(0.0, config.carrying_capacity);

        if stock < config.min_stock {
            sustainability_breaches += 1;
        }

        on_round_complete(ResourceRoundUpdate {
            round_index,
            stock,
            lambda,
        })?;

        extraction_history.push(extractions.clone());
        stock_history.push(stock);
        lambda_history.push(lambda);
    }

    Ok(ResourceExperimentReport {
        stock_history,
        lambda_history,
        extraction_history,
        sustainability_breaches,
        total_extraction,
        final_stock: stock,
    })
}

fn render_resource_skill_arguments(context: ResourceDecisionContext) -> Vec<u8> {
    format!(
        concat!(
            "round={},agent_count={},stock={:.6},lambda={:.6},desired={:.6},max={:.6},",
            "baseline={:.6},previous={:.6},min_stock={:.6},",
            "sustainable_capacity={:.6},safe_upper_bound={:.6}"
        ),
        context.round_index,
        context.agent_count,
        context.stock,
        context.lambda,
        context.desired_extraction,
        context.max_extraction,
        context.baseline_extraction,
        context.previous_extraction,
        context.min_stock,
        context.sustainable_capacity,
        context.safe_upper_bound,
    )
    .into_bytes()
}

fn parse_resource_extraction_decision(result: &ToolResult, safe_upper_bound: f64) -> Option<f64> {
    let payload = String::from_utf8_lossy(&result.payload);
    let extraction = parse_numeric_field(&payload, "extraction")?;
    if !extraction.is_finite()
        || extraction < -DECISION_EPSILON
        || extraction > safe_upper_bound + DECISION_EPSILON
    {
        return None;
    }
    Some(extraction.max(0.0))
}

fn l2_disagreement(values: &[f64], average: f64) -> f64 {
    values
        .iter()
        .map(|value| {
            let delta = value - average;
            delta * delta
        })
        .sum::<f64>()
        .sqrt()
}

fn variance(values: &[f64]) -> f64 {
    if values.len() < 2 {
        return 0.0;
    }

    let mean = values.iter().sum::<f64>() / values.len() as f64;
    values
        .iter()
        .map(|value| {
            let delta = value - mean;
            delta * delta
        })
        .sum::<f64>()
        / values.len() as f64
}

fn maybe_call_tool(
    tools: &[&dyn ToolAdapter],
    provider: ToolProvider,
    phase: &str,
    epoch: Epoch,
    interactions: &mut ExperimentInteractionSummary,
    trace: &mut Vec<InteractionTraceEvent>,
    tool_name: String,
    target: Option<String>,
    arguments: Vec<u8>,
) -> Result<Option<ToolResult>, String> {
    let Some(tool_adapter) = tools.iter().copied().find(|tool| tool.provider() == provider) else {
        return Ok(None);
    };

    let trace_target = target.clone().unwrap_or_else(|| tool_name.clone());
    let result = tool_adapter.call(ToolCall {
        provider,
        tool_name,
        arguments,
        target,
        correlation_id: Some(format!("{}-{}", phase, epoch.0)),
        epoch,
    })?;

    match provider {
        ToolProvider::Mcp => interactions.mcp_tool_calls += 1,
        ToolProvider::AgentSkills => interactions.agentskills_tool_calls += 1,
    }
    trace.push(InteractionTraceEvent {
        phase: phase.to_string(),
        epoch,
        adapter: provider_label(provider).to_string(),
        action: "tool_call".to_string(),
        target: trace_target,
    });
    Ok(Some(result))
}


fn is_resource_agentskills_request(request: &ToolCall) -> bool {
    request.provider == ToolProvider::AgentSkills
        && request.tool_name.starts_with("allocation.skill.agent.")
}

fn is_preference_agentskills_request(request: &ToolCall) -> bool {
    request.provider == ToolProvider::AgentSkills
        && request.tool_name.starts_with("meeting.preference.skill.")
}

fn parse_numeric_field(input: &str, key: &str) -> Option<f64> {
    extract_key_value_fields(input)
        .into_iter()
        .find_map(|(field_key, field_value)| {
            (field_key == key).then(|| field_value.parse::<f64>().ok()).flatten()
        })
}
fn provider_label(provider: ToolProvider) -> &'static str {
    match provider {
        ToolProvider::Mcp => "mcp",
        ToolProvider::AgentSkills => "agentskills",
    }
}

fn csv_field(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preference_experiment_reduces_disagreement_on_connected_graph() {
        let config = PreferenceExperimentConfig {
            adjacency: vec![vec![1], vec![0, 2], vec![1]],
            preferred_scores: vec![0.0, 4.0, 8.0],
            beta: 0.75,
            rounds: 12,
            initial_proposals: None,
        };

        let report = run_preference_experiment(&config).expect("preference report");
        let first = *report.disagreement_l2.first().expect("initial disagreement");
        let last = *report.disagreement_l2.last().expect("final disagreement");
        assert!(last < first, "expected disagreement to shrink, got {first} -> {last}");
    }

    #[test]
    fn calibrated_live_preference_config_reaches_full_agreement_on_live_scales() {
        for agent_count in 1..=5 {
            let config = calibrated_live_preference_config(agent_count)
                .expect("calibrated live preference config");
            let report = run_preference_experiment(&config).expect("preference report");
            let final_value = report.disagreement_l2.last().copied().unwrap_or_default();

            assert!(
                final_value.abs() <= 1e-9,
                "expected scale {agent_count} to end at zero disagreement, got {final_value}"
            );
            assert!(
                report
                    .final_proposals
                    .iter()
                    .all(|proposal| (*proposal - report.average_score).abs() <= 1e-9),
                "expected scale {agent_count} to end in full agreement around {}, got {:?}",
                report.average_score,
                report.final_proposals
            );
        }
    }

    #[test]
    fn calibrated_live_cascade_config_keeps_bullwhip_bounded_on_live_scales() {
        for stage_count in 1..=5 {
            let config =
                calibrated_live_cascade_config(stage_count).expect("calibrated live cascade config");
            let report = run_cascade_experiment(&config).expect("cascade report");

            assert!(
                report.bullwhip_ratio < 1.0,
                "expected scale {stage_count} to stay below bullwhip ratio 1.0, got {}",
                report.bullwhip_ratio
            );
        }
    }

    #[test]
    fn cascade_experiment_propagates_demand_shock_to_upstream_orders() {
        let shock = CascadeExperimentConfig {
            stages: 4,
            lead_time: 2,
            customer_demand: vec![4.0, 4.0, 4.0, 8.0, 8.0, 8.0, 4.0, 4.0],
            initial_inventory: 8.0,
            target_inventory: 8.0,
            holding_cost: 1.0,
            backlog_cost: 2.0,
            adjustment_penalty: 0.25,
        };
        let steady = CascadeExperimentConfig {
            customer_demand: vec![4.0; 8],
            ..shock.clone()
        };

        let shock_report = run_cascade_experiment(&shock).expect("shock report");
        let steady_report = run_cascade_experiment(&steady).expect("steady report");
        let shock_upstream = shock_report.order_history.last().expect("shock upstream orders");
        let steady_upstream = steady_report.order_history.last().expect("steady upstream orders");

        assert!(
            shock_report.upstream_order_variance > 0.0,
            "expected demand shock to induce upstream order variability"
        );
        assert_ne!(shock_upstream, steady_upstream, "expected demand shock to reach upstream stage");
    }

    #[test]
    fn resource_experiment_coordination_preserves_more_stock_than_uncontrolled_case() {
        let coordinated = ResourceExperimentConfig {
            desired_extraction: vec![2.0, 2.5, 2.0],
            max_extraction: vec![3.0, 3.0, 3.0],
            rounds: 20,
            initial_stock: 24.0,
            min_stock: 6.0,
            carrying_capacity: 30.0,
            regeneration_rate: 0.2,
            sustainable_fraction: 0.25,
            eta: 0.4,
            alpha: 0.35,
            initial_lambda: 0.0,
        };
        let uncontrolled = ResourceExperimentConfig {
            alpha: 0.0,
            ..coordinated.clone()
        };

        let coordinated_report = run_resource_experiment(&coordinated).expect("coordinated report");
        let uncontrolled_report =
            run_resource_experiment(&uncontrolled).expect("uncontrolled report");

        assert!(
            coordinated_report.final_stock > uncontrolled_report.final_stock,
            "expected coordination to preserve more stock"
        );
        assert!(
            coordinated_report.sustainability_breaches <= uncontrolled_report.sustainability_breaches,
            "expected coordination to reduce sustainability breaches"
        );
    }

    #[test]
    fn resource_experiment_with_sustainable_capacity_cap_reduces_breach_risk() {
        let config = ResourceExperimentConfig {
            desired_extraction: vec![2.0, 2.5],
            max_extraction: vec![3.0, 3.0],
            rounds: 4,
            initial_stock: 20.0,
            min_stock: 5.0,
            carrying_capacity: 25.0,
            regeneration_rate: 0.15,
            sustainable_fraction: 0.25,
            eta: 0.4,
            alpha: 0.35,
            initial_lambda: 0.0,
        };

        let baseline = run_resource_experiment(&config).expect("baseline report");
        let capped = run_resource_experiment_with_sustainable_capacity_cap(&config)
            .expect("capacity-capped report");

        assert!(capped.total_extraction <= baseline.total_extraction);
        assert!(capped.sustainability_breaches <= baseline.sustainability_breaches);
    }

    #[test]
    fn preference_experiment_records_a2a_mcp_agentskills_and_slim_interactions() {
        let config = PreferenceExperimentConfig {
            adjacency: vec![vec![1], vec![0]],
            preferred_scores: vec![2.0, 6.0],
            beta: 0.5,
            rounds: 2,
            initial_proposals: None,
        };
        let messaging = RecordingMessagingAdapter::default();
        let task = RecordingTaskAdapter::default();
        let mcp = RecordingToolAdapter::new(ToolProvider::Mcp);
        let agentskills = RecordingToolAdapter::new(ToolProvider::AgentSkills);
        let tools: [&dyn ToolAdapter; 2] = [&mcp, &agentskills];

        let execution = run_preference_experiment_with_adapters(
            &config,
            Some(&messaging),
            Some(&task),
            &tools,
        )
        .expect("preference execution");

        assert_eq!(execution.interactions.published_messages, 4);
        assert_eq!(execution.interactions.dispatched_tasks, 4);
        assert_eq!(execution.interactions.mcp_tool_calls, 4);
        assert_eq!(execution.interactions.agentskills_tool_calls, 4);
        assert_eq!(execution.interactions.llm_state_updates, 0);
        assert_eq!(execution.interactions.llm_state_fallbacks, 4);
        assert_eq!(messaging.published_messages().expect("messages").len(), 4);
        assert_eq!(task.dispatched_tasks().expect("tasks").len(), 4);
        assert_eq!(mcp.calls().expect("mcp calls").len(), 4);
        assert_eq!(agentskills.calls().expect("skill calls").len(), 4);
    }

    #[test]
    fn preference_experiment_uses_agentskills_output_to_change_state() {
        let config = PreferenceExperimentConfig {
            adjacency: vec![vec![1], vec![0]],
            preferred_scores: vec![0.0, 8.0],
            beta: 0.75,
            rounds: 1,
            initial_proposals: None,
        };
        let baseline = run_preference_experiment(&config).expect("baseline report");
        let agentskills = EchoPreferenceBaselineToolAdapter::new(ToolProvider::AgentSkills);
        let execution = run_preference_experiment_with_adapters(&config, None, None, &[&agentskills])
            .expect("preference execution");

        assert_eq!(execution.report, baseline);
        assert_eq!(
            execution.interactions.llm_state_updates,
            config.preferred_scores.len() * config.rounds
        );
        assert_eq!(execution.interactions.llm_state_fallbacks, 0);
    }

    #[test]
    fn preference_experiment_falls_back_to_baseline_when_agentskills_output_is_bounded_but_off_update() {
        let config = PreferenceExperimentConfig {
            adjacency: vec![vec![]],
            preferred_scores: vec![4.0],
            beta: 0.75,
            rounds: 1,
            initial_proposals: Some(vec![0.0]),
        };
        let baseline = run_preference_experiment(&config).expect("baseline report");
        let agentskills = FixedOutputToolAdapter::new(ToolProvider::AgentSkills, "proposal=3.8");
        let execution = run_preference_experiment_with_adapters(&config, None, None, &[&agentskills])
            .expect("preference execution");

        assert_eq!(execution.report, baseline);
        assert_eq!(execution.interactions.llm_state_updates, 0);
        assert_eq!(execution.interactions.llm_state_fallbacks, 1);
    }

    #[test]
    fn preference_experiment_falls_back_to_baseline_when_agentskills_output_is_invalid() {
        let config = PreferenceExperimentConfig {
            adjacency: vec![vec![1], vec![0, 2], vec![1]],
            preferred_scores: vec![0.0, 4.0, 8.0],
            beta: 0.75,
            rounds: 1,
            initial_proposals: None,
        };
        let baseline = run_preference_experiment(&config).expect("baseline report");
        let agentskills = FixedOutputToolAdapter::new(ToolProvider::AgentSkills, "proposal=9.0");
        let execution = run_preference_experiment_with_adapters(&config, None, None, &[&agentskills])
            .expect("preference execution");

        assert_eq!(execution.report, baseline);
        assert_eq!(execution.interactions.llm_state_updates, 0);
        assert_eq!(
            execution.interactions.llm_state_fallbacks,
            config.preferred_scores.len() * config.rounds
        );
    }

    #[test]
    fn cascade_experiment_records_boundary_interactions() {
        let config = CascadeExperimentConfig {
            stages: 3,
            lead_time: 2,
            customer_demand: vec![4.0, 6.0, 4.0],
            initial_inventory: 8.0,
            target_inventory: 8.0,
            holding_cost: 1.0,
            backlog_cost: 2.0,
            adjustment_penalty: 0.25,
        };
        let messaging = RecordingMessagingAdapter::default();
        let task = RecordingTaskAdapter::default();
        let mcp = RecordingToolAdapter::new(ToolProvider::Mcp);
        let agentskills = RecordingToolAdapter::new(ToolProvider::AgentSkills);
        let tools: [&dyn ToolAdapter; 2] = [&mcp, &agentskills];

        let execution = run_cascade_experiment_with_adapters(
            &config,
            Some(&messaging),
            Some(&task),
            &tools,
        )
        .expect("cascade execution");

        let expected_steps = config.customer_demand.len() * config.stages;
        assert_eq!(execution.interactions.published_messages, expected_steps);
        assert_eq!(execution.interactions.dispatched_tasks, expected_steps);
        assert_eq!(execution.interactions.mcp_tool_calls, expected_steps);
        assert_eq!(execution.interactions.agentskills_tool_calls, expected_steps);
        assert_eq!(execution.interactions.llm_state_updates, 0);
        assert_eq!(execution.interactions.llm_state_fallbacks, expected_steps);
    }

    #[test]
    fn cascade_experiment_applies_valid_agentskills_updates_in_loop() {
        let config = CascadeExperimentConfig {
            stages: 3,
            lead_time: 2,
            customer_demand: vec![4.0, 6.0, 4.0],
            initial_inventory: 8.0,
            target_inventory: 8.0,
            holding_cost: 1.0,
            backlog_cost: 2.0,
            adjustment_penalty: 0.25,
        };
        let baseline = run_cascade_experiment(&config).expect("baseline cascade report");
        let agentskills = EchoArgumentsToolAdapter::new(ToolProvider::AgentSkills);

        let execution = run_cascade_experiment_with_adapters(&config, None, None, &[&agentskills])
            .expect("cascade execution");

        for (baseline_stage, execution_stage) in baseline
            .order_history
            .iter()
            .zip(execution.report.order_history.iter())
        {
            for (baseline_order, execution_order) in
                baseline_stage.iter().zip(execution_stage.iter())
            {
                assert!((baseline_order - execution_order).abs() < 1e-9);
            }
        }
        for (baseline_stage, execution_stage) in baseline
            .inventory_history
            .iter()
            .zip(execution.report.inventory_history.iter())
        {
            for (baseline_inventory, execution_inventory) in
                baseline_stage.iter().zip(execution_stage.iter())
            {
                assert!((baseline_inventory - execution_inventory).abs() < 1e-9);
            }
        }
        assert!((baseline.total_cost - execution.report.total_cost).abs() < 1e-9);
        assert!((baseline.bullwhip_ratio - execution.report.bullwhip_ratio).abs() < 1e-9);
        assert_eq!(
            execution.interactions.llm_state_updates,
            config.customer_demand.len() * config.stages
        );
        assert_eq!(execution.interactions.llm_state_fallbacks, 0);
    }

    #[test]
    fn cascade_experiment_falls_back_to_baseline_when_agentskills_output_is_invalid() {
        let config = CascadeExperimentConfig {
            stages: 3,
            lead_time: 2,
            customer_demand: vec![4.0, 6.0, 4.0],
            initial_inventory: 8.0,
            target_inventory: 8.0,
            holding_cost: 1.0,
            backlog_cost: 2.0,
            adjustment_penalty: 0.25,
        };
        let baseline = run_cascade_experiment(&config).expect("baseline cascade report");
        let agentskills = FixedOutputToolAdapter::new(ToolProvider::AgentSkills, "not-a-decision");

        let execution = run_cascade_experiment_with_adapters(&config, None, None, &[&agentskills])
            .expect("cascade execution");

        assert_eq!(execution.report, baseline);
        assert_eq!(execution.interactions.llm_state_updates, 0);
        assert_eq!(
            execution.interactions.llm_state_fallbacks,
            config.customer_demand.len() * config.stages
        );
    }

    #[test]
    fn resource_experiment_records_group_and_tool_interactions() {
        let config = ResourceExperimentConfig {
            desired_extraction: vec![2.0, 2.5],
            max_extraction: vec![3.0, 3.0],
            rounds: 3,
            initial_stock: 20.0,
            min_stock: 5.0,
            carrying_capacity: 25.0,
            regeneration_rate: 0.15,
            sustainable_fraction: 0.25,
            eta: 0.4,
            alpha: 0.35,
            initial_lambda: 0.0,
        };
        let messaging = RecordingMessagingAdapter::default();
        let task = RecordingTaskAdapter::default();
        let mcp = RecordingToolAdapter::new(ToolProvider::Mcp);
        let agentskills = RecordingToolAdapter::new(ToolProvider::AgentSkills);
        let tools: [&dyn ToolAdapter; 2] = [&mcp, &agentskills];

        let execution = run_resource_experiment_with_adapters(
            &config,
            Some(&messaging),
            Some(&task),
            &tools,
        )
        .expect("resource execution");

        assert_eq!(execution.interactions.published_messages, config.rounds);
        assert_eq!(execution.interactions.dispatched_tasks, config.rounds * 2);
        assert_eq!(execution.interactions.mcp_tool_calls, config.rounds * 2);
        assert_eq!(execution.interactions.agentskills_tool_calls, config.rounds * 2);
        assert_eq!(execution.interactions.llm_state_updates, 0);
        assert_eq!(execution.interactions.llm_state_fallbacks, config.rounds * 2);
    }

    struct FixedOutputToolAdapter {
        provider: ToolProvider,
        payload: String,
    }

    impl FixedOutputToolAdapter {
        fn new(provider: ToolProvider, payload: impl Into<String>) -> Self {
            Self {
                provider,
                payload: payload.into(),
            }
        }
    }

    impl ToolAdapter for FixedOutputToolAdapter {
        fn provider(&self) -> ToolProvider {
            self.provider
        }

        fn call(&self, request: ToolCall) -> Result<ToolResult, String> {
            Ok(ToolResult {
                provider: self.provider,
                tool_name: request.tool_name,
                payload: self.payload.clone().into_bytes(),
                target: request.target,
                correlation_id: request.correlation_id,
                epoch: request.epoch,
            })
        }
    }

    struct EchoArgumentsToolAdapter {
        provider: ToolProvider,
    }

    impl EchoArgumentsToolAdapter {
        fn new(provider: ToolProvider) -> Self {
            Self { provider }
        }
    }

    impl ToolAdapter for EchoArgumentsToolAdapter {
        fn provider(&self) -> ToolProvider {
            self.provider
        }

        fn call(&self, request: ToolCall) -> Result<ToolResult, String> {
            Ok(ToolResult {
                provider: self.provider,
                tool_name: request.tool_name,
                payload: request.arguments,
                target: request.target,
                correlation_id: request.correlation_id,
                epoch: request.epoch,
            })
        }
    }

    struct EchoPreferenceBaselineToolAdapter {
        provider: ToolProvider,
    }

    impl EchoPreferenceBaselineToolAdapter {
        fn new(provider: ToolProvider) -> Self {
            Self { provider }
        }
    }

    impl ToolAdapter for EchoPreferenceBaselineToolAdapter {
        fn provider(&self) -> ToolProvider {
            self.provider
        }

        fn call(&self, request: ToolCall) -> Result<ToolResult, String> {
            let arguments = String::from_utf8(request.arguments.clone())
                .map_err(|_| "preference test arguments are not valid UTF-8".to_string())?;
            let baseline = parse_numeric_field(&arguments, "baseline")
                .ok_or_else(|| "preference test arguments are missing baseline".to_string())?;

            Ok(ToolResult {
                provider: self.provider,
                tool_name: request.tool_name,
                payload: format!("proposal={baseline:.6}").into_bytes(),
                target: request.target,
                correlation_id: request.correlation_id,
                epoch: request.epoch,
            })
        }
    }

    #[test]
    fn resource_experiment_uses_agentskills_output_to_change_state() {
        let config = ResourceExperimentConfig {
            desired_extraction: vec![2.0, 2.5],
            max_extraction: vec![3.0, 3.0],
            rounds: 4,
            initial_stock: 20.0,
            min_stock: 5.0,
            carrying_capacity: 25.0,
            regeneration_rate: 0.15,
            sustainable_fraction: 0.25,
            eta: 0.4,
            alpha: 0.35,
            initial_lambda: 0.0,
        };
        let baseline = run_resource_experiment(&config).expect("baseline report");
        let agentskills = FixedOutputToolAdapter::new(ToolProvider::AgentSkills, "extraction=0.0");
        let execution = run_resource_experiment_with_adapters(&config, None, None, &[&agentskills])
            .expect("resource execution");

        assert!(execution.report.final_stock > baseline.final_stock);
        assert!(execution.report.total_extraction < baseline.total_extraction);
        assert_eq!(
            execution.interactions.llm_state_updates,
            config.rounds * config.desired_extraction.len()
        );
        assert_eq!(execution.interactions.llm_state_fallbacks, 0);
    }

    #[test]
    fn resource_experiment_falls_back_to_baseline_when_agentskills_output_is_invalid() {
        let config = ResourceExperimentConfig {
            desired_extraction: vec![2.0, 2.5],
            max_extraction: vec![3.0, 3.0],
            rounds: 4,
            initial_stock: 20.0,
            min_stock: 5.0,
            carrying_capacity: 25.0,
            regeneration_rate: 0.15,
            sustainable_fraction: 0.25,
            eta: 0.4,
            alpha: 0.35,
            initial_lambda: 0.0,
        };
        let baseline = run_resource_experiment(&config).expect("baseline report");
        let agentskills = FixedOutputToolAdapter::new(ToolProvider::AgentSkills, "not-a-decision");
        let execution = run_resource_experiment_with_adapters(&config, None, None, &[&agentskills])
            .expect("resource execution");

        assert_eq!(execution.report, baseline);
        assert_eq!(execution.interactions.llm_state_updates, 0);
        assert_eq!(
            execution.interactions.llm_state_fallbacks,
            config.rounds * config.desired_extraction.len()
        );
    }

    #[test]
    fn command_tool_prompt_requests_canonical_echo_output() {
        let prompt = CommandToolAdapter::render_prompt(&ToolCall {
            provider: ToolProvider::AgentSkills,
            tool_name: "generic.skill.0".to_string(),
            arguments: b"round=1,proposal=2.4".to_vec(),
            target: Some("agentskills://generic/participant-0".to_string()),
            correlation_id: Some("generic-1".to_string()),
            epoch: Epoch(1),
        })
        .expect("prompt");

        assert!(prompt.contains("Return exactly the text shown in `required_reply`."));
        assert!(prompt.contains("required_reply:"));
    }

    #[test]
    fn command_tool_prompt_requests_bounded_preference_decision_output() {
        let prompt = CommandToolAdapter::render_prompt(&ToolCall {
            provider: ToolProvider::AgentSkills,
            tool_name: "meeting.preference.skill.0".to_string(),
            arguments: b"round=1,current=0.0,preferred=0.0,neighbor_average=4.0,neighbor_count=1,baseline=2.4,lower_bound=0.0,upper_bound=4.0,safe_lower_bound=2.0,safe_upper_bound=2.8".to_vec(),
            target: Some("agentskills://meeting/participant-0".to_string()),
            correlation_id: Some("preference-1".to_string()),
            epoch: Epoch(1),
        })
        .expect("prompt");

        assert!(prompt.contains(
            "The theoretical synchronous update for this round is `proposal=2.400000`"
        ));
        assert!(prompt.contains("Return exactly that line."));
        assert!(prompt.contains(
            "safe interval is [2.000000, 2.800000] around the baseline 2.400000"
        ));
        assert!(prompt.contains("required_reply: proposal=2.400000"));
    }

    #[test]
    fn command_tool_prompt_requests_bounded_resource_decision_output() {
        let prompt = CommandToolAdapter::render_prompt(&ToolCall {
            provider: ToolProvider::AgentSkills,
            tool_name: "allocation.skill.agent.0".to_string(),
            arguments: b"round=1,agent_count=2,stock=9.0,lambda=0.5,desired=2.0,max=3.0,baseline=1.4,previous=1.0,min_stock=4.0,sustainable_capacity=3.0,safe_upper_bound=1.5".to_vec(),
            target: Some("agentskills://allocation/agent-0".to_string()),
            correlation_id: Some("resource-1".to_string()),
            epoch: Epoch(1),
        })
        .expect("prompt");

        assert!(prompt.contains("Return exactly `extraction=<number>`"));
        assert!(prompt.contains("between 0 and 1.500000 inclusive"));
        assert!(prompt.contains("safe upper bound is 1.500000"));
    }

    #[test]
    fn tool_invocation_validation_accepts_canonical_echo_and_rejects_generic_output() {
        let valid = CommandToolInvocationRecord {
            request: ToolCall {
                provider: ToolProvider::AgentSkills,
                tool_name: "generic.skill.0".to_string(),
                arguments: b"round=1,proposal=2.4".to_vec(),
                target: Some("agentskills://generic/participant-0".to_string()),
                correlation_id: Some("generic-1".to_string()),
                epoch: Epoch(1),
            },
            prompt: String::new(),
            raw_output: "ok round=1 proposal=2.400000".to_string(),
            final_output: "ok round=1 proposal=2.400000".to_string(),
            elapsed_ms: 12.0,
        };
        let invalid = CommandToolInvocationRecord {
            request: ToolCall {
                provider: ToolProvider::AgentSkills,
                tool_name: "generic.skill.1".to_string(),
                arguments: b"round=2,proposal=4.8".to_vec(),
                target: Some("agentskills://generic/participant-1".to_string()),
                correlation_id: Some("generic-2".to_string()),
                epoch: Epoch(2),
            },
            prompt: String::new(),
            raw_output: "Proposal processed".to_string(),
            final_output: "Proposal processed".to_string(),
            elapsed_ms: 15.0,
        };

        let summary = validate_tool_invocations(&[valid, invalid]);

        assert_eq!(summary.total_invocations, 2);
        assert_eq!(summary.valid_invocations, 1);
        assert!((summary.valid_ratio - 0.5).abs() < 1e-9);
        assert_eq!(summary.invalid_examples.len(), 1);
        assert!(summary.invalid_examples[0].contains("expected=round=2 proposal=4.8"));
    }

    #[test]
    fn tool_invocation_validation_accepts_theoretical_preference_decision_output() {
        let valid = CommandToolInvocationRecord {
            request: ToolCall {
                provider: ToolProvider::AgentSkills,
                tool_name: "meeting.preference.skill.0".to_string(),
                arguments: b"round=1,current=0.0,preferred=0.0,neighbor_average=4.0,neighbor_count=1,baseline=2.4,lower_bound=0.0,upper_bound=4.0,safe_lower_bound=2.0,safe_upper_bound=2.8".to_vec(),
                target: Some("agentskills://meeting/participant-0".to_string()),
                correlation_id: Some("preference-1".to_string()),
                epoch: Epoch(1),
            },
            prompt: String::new(),
            raw_output: "proposal=2.400000".to_string(),
            final_output: "proposal=2.400000".to_string(),
            elapsed_ms: 12.0,
        };
        let invalid = CommandToolInvocationRecord {
            request: ToolCall {
                provider: ToolProvider::AgentSkills,
                tool_name: "meeting.preference.skill.1".to_string(),
                arguments: b"round=1,current=4.0,preferred=4.0,neighbor_average=4.0,neighbor_count=2,baseline=4.0,lower_bound=0.0,upper_bound=8.0,safe_lower_bound=3.2,safe_upper_bound=4.8".to_vec(),
                target: Some("agentskills://meeting/participant-1".to_string()),
                correlation_id: Some("preference-1".to_string()),
                epoch: Epoch(1),
            },
            prompt: String::new(),
            raw_output: "proposal=4.100000".to_string(),
            final_output: "proposal=4.100000".to_string(),
            elapsed_ms: 15.0,
        };

        let summary = validate_tool_invocations(&[valid, invalid]);

        assert_eq!(summary.total_invocations, 2);
        assert_eq!(summary.valid_invocations, 1);
        assert!((summary.valid_ratio - 0.5).abs() < 1e-9);
        assert_eq!(summary.invalid_examples.len(), 1);
        assert!(summary.invalid_examples[0].contains("expected=proposal=4.000000"));
    }

    #[test]
    fn tool_invocation_validation_accepts_bounded_resource_decision_output() {
        let valid = CommandToolInvocationRecord {
            request: ToolCall {
                provider: ToolProvider::AgentSkills,
                tool_name: "allocation.skill.agent.0".to_string(),
                arguments: b"round=1,agent_count=2,stock=9.0,lambda=0.5,desired=2.0,max=3.0,baseline=1.4,previous=1.0,min_stock=4.0,sustainable_capacity=3.0,safe_upper_bound=1.5".to_vec(),
                target: Some("agentskills://allocation/agent-0".to_string()),
                correlation_id: Some("resource-1".to_string()),
                epoch: Epoch(1),
            },
            prompt: String::new(),
            raw_output: "extraction=1.250000".to_string(),
            final_output: "extraction=1.250000".to_string(),
            elapsed_ms: 12.0,
        };
        let invalid = CommandToolInvocationRecord {
            request: ToolCall {
                provider: ToolProvider::AgentSkills,
                tool_name: "allocation.skill.agent.1".to_string(),
                arguments: b"round=1,agent_count=2,stock=9.0,lambda=0.5,desired=2.0,max=3.0,baseline=1.4,previous=1.0,min_stock=4.0,sustainable_capacity=3.0,safe_upper_bound=1.5".to_vec(),
                target: Some("agentskills://allocation/agent-1".to_string()),
                correlation_id: Some("resource-1".to_string()),
                epoch: Epoch(1),
            },
            prompt: String::new(),
            raw_output: "extraction=1.75".to_string(),
            final_output: "extraction=1.75".to_string(),
            elapsed_ms: 15.0,
        };

        let summary = validate_tool_invocations(&[valid, invalid]);

        assert_eq!(summary.total_invocations, 2);
        assert_eq!(summary.valid_invocations, 1);
        assert!((summary.valid_ratio - 0.5).abs() < 1e-9);
        assert_eq!(summary.invalid_examples.len(), 1);
        assert!(summary.invalid_examples[0].contains("expected=extraction in [0,1.500000]"));
    }

    // --- Coverage for previously-uncovered paths ----------------------------

    #[test]
    fn calibrated_live_preference_config_returns_error_for_large_agent_count() {
        assert!(calibrated_live_preference_config(6).is_err());
        assert!(calibrated_live_preference_config(0).is_err());
    }

    #[test]
    fn calibrated_live_cascade_config_returns_error_for_large_stage_count() {
        assert!(calibrated_live_cascade_config(6).is_err());
        assert!(calibrated_live_cascade_config(0).is_err());
    }

    #[test]
    fn interaction_trace_event_csv_methods() {
        assert_eq!(InteractionTraceEvent::csv_header(), "phase,epoch,adapter,action,target");

        let event = InteractionTraceEvent {
            phase: "preference".to_string(),
            epoch: Epoch(3),
            adapter: "slim".to_string(),
            action: "publish".to_string(),
            target: "agntcy/shadi/avatar-slim".to_string(),
        };
        let row = event.to_csv_row();
        assert!(row.contains("preference"));
        assert!(row.contains("3"));
        assert!(row.contains("slim"));
        assert!(row.contains("publish"));
    }

    #[test]
    fn live_a2a_adapter_construction_and_dispatches_accessor() {
        let config = LiveA2ATaskAdapterConfig {
            endpoint: "127.0.0.1:47357".to_string(),
            agent_id: "test-agent".to_string(),
            local_name: Some("agntcy/shadi/test-a2a".to_string()),
            peer_agent_id: "peer-agent".to_string(),
            destination: Some("agntcy/shadi/peer-a2a".to_string()),
            shared_secret: "test_secret".to_string(),
        };
        let adapter = LiveA2ATaskAdapter::new(config);
        // dispatches() should return an empty list immediately after construction.
        let dispatches = adapter.dispatches().unwrap();
        assert!(dispatches.is_empty());
    }

    #[test]
    fn live_slim_disabled_adapter_publish_and_accessors() {
        let adapter = LiveSlimMessagingAdapter::disabled();

        // publish() in disabled mode is a no-op but still records the message.
        adapter.publish("test-topic", b"hello world").unwrap();
        adapter.publish("other-topic", b"second message").unwrap();

        let messages = adapter.published_messages().unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].topic, "test-topic");
        assert_eq!(messages[0].payload, b"hello world");

        let acks = adapter.acknowledgements().unwrap();
        assert_eq!(acks.len(), 2);
        // Disabled mode produces empty acknowledgements.
        assert!(acks[0].is_empty());

        let exchanges = adapter.exchanges().unwrap();
        assert_eq!(exchanges.len(), 2);
        assert_eq!(exchanges[0].topic, "test-topic");
        assert_eq!(exchanges[0].round_trip_ms, 0.0);
    }

    #[test]
    fn command_tool_adapter_call_with_echo_command() {
        // Use `echo test_output` — ignores stdin, writes "test_output" to stdout.
        let adapter = CommandToolAdapter::new(ToolProvider::Mcp, "echo", ["test_output"]);
        assert_eq!(adapter.provider(), ToolProvider::Mcp);

        let call = ToolCall {
            provider: ToolProvider::Mcp,
            tool_name: "generic_tool".to_string(),
            arguments: b"{}".to_vec(),  // no key=value → canonical_tool_reply returns "ok"
            target: None,
            correlation_id: None,
            epoch: Epoch(0),
        };

        let result = adapter.call(call);
        assert!(result.is_ok(), "adapter.call failed: {result:?}");
        let tool_result = result.unwrap();
        assert_eq!(tool_result.provider, ToolProvider::Mcp);
        assert_eq!(tool_result.tool_name, "generic_tool");
        assert_eq!(
            String::from_utf8(tool_result.payload).unwrap(),
            "test_output"
        );

        let calls = adapter.calls().unwrap();
        assert_eq!(calls.len(), 1);
        let results = adapter.results().unwrap();
        assert_eq!(results.len(), 1);
        let invocations = adapter.invocations().unwrap();
        assert_eq!(invocations.len(), 1);
        assert_eq!(invocations[0].final_output, "test_output");
    }

    #[test]
    fn command_tool_adapter_call_returns_error_on_failed_command() {
        // Use a command guaranteed to exit with non-zero status.
        let adapter = CommandToolAdapter::new(ToolProvider::Mcp, "false", [] as [&str; 0]);
        let call = ToolCall {
            provider: ToolProvider::Mcp,
            tool_name: "fail_tool".to_string(),
            arguments: b"{}".to_vec(),
            target: None,
            correlation_id: None,
            epoch: Epoch(0),
        };
        let result = adapter.call(call);
        assert!(result.is_err());
    }
}