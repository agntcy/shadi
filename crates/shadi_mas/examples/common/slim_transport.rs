use std::collections::{HashMap, VecDeque};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{mpsc, Arc, Once};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use shadi_mas::experiments::{
    run_cascade_experiment_with_adapters, run_preference_experiment_with_adapters,
    run_resource_experiment_with_adapters, CascadeExperimentConfig, CascadeExperimentReport,
    PreferenceExperimentConfig, PreferenceExperimentReport, RecordingMessagingAdapter,
    ResourceExperimentConfig, ResourceExperimentReport,
};
use shadi_mas::ToolAdapter;
use slim_bindings::{
    App, CaSource, ClientConfig, Name, ServerConfig, Service, Session, SessionConfig,
    SessionType, SlimError, TlsClientConfig, TlsServerConfig, TlsSource,
};

const BENCHMARK_SHARED_SECRET: &str = "shadi_mas_transport_benchmark_shared_secret";
const SESSION_TIMEOUT: Duration = Duration::from_secs(20);
const PARTICIPANT_CERT_NAMES: [&str; 2] = ["secops-a", "secops-b"];
const TRANSPORT_AGENT_COUNTS: &[usize] = &[1, 2, 3, 4, 5, 10, 17, 33, 65, 100];
const TRANSPORT_ROUND_DURATIONS_MS: &[f64] = &[5.0, 10.0, 20.0, 50.0, 100.0];
static QUIET_TRACING_INIT: Once = Once::new();

#[derive(Clone, Debug, Serialize)]
pub struct TransportSweepRow {
    pub transport_mode: &'static str,
    pub agent_count: usize,
    pub rounds: usize,
    pub round_duration_ms: f64,
    pub logical_updates: usize,
    pub logical_payload_bytes: usize,
    pub physical_messages: usize,
    pub total_bytes_sent: usize,
    pub message_amplification_factor: f64,
    pub average_sender_cpu_ms: f64,
    pub p50_dissemination_latency_ms: f64,
    pub p95_dissemination_latency_ms: f64,
    pub p99_dissemination_latency_ms: f64,
    pub peak_sender_queue_depth: f64,
    pub rounds_over_budget: usize,
    pub stale_view_rate: f64,
    pub late_state_receipts: usize,
    pub late_state_receipt_rate: f64,
    pub final_stock: f64,
    pub sustainability_breaches: usize,
    pub final_stock_delta_vs_oracle: f64,
    pub breach_increase_vs_oracle: isize,
}

#[derive(Clone, Debug, Serialize)]
pub struct PreferenceTransportSweepRow {
    pub transport_mode: &'static str,
    pub agent_count: usize,
    pub rounds: usize,
    pub round_duration_ms: f64,
    pub logical_updates: usize,
    pub logical_payload_bytes: usize,
    pub physical_messages: usize,
    pub total_bytes_sent: usize,
    pub message_amplification_factor: f64,
    pub average_sender_cpu_ms: f64,
    pub p50_dissemination_latency_ms: f64,
    pub p95_dissemination_latency_ms: f64,
    pub p99_dissemination_latency_ms: f64,
    pub peak_sender_queue_depth: f64,
    pub rounds_over_budget: usize,
    pub stale_view_rate: f64,
    pub late_round_receipts: usize,
    pub late_round_receipt_rate: f64,
    pub final_disagreement_l2: f64,
    pub relative_disagreement: f64,
    pub disagreement_delta_vs_oracle: f64,
}

#[derive(Clone, Debug, Serialize)]
pub struct CascadeTransportSweepRow {
    pub transport_mode: &'static str,
    pub stages: usize,
    pub lead_time: usize,
    pub customer_rounds: usize,
    pub round_duration_ms: f64,
    pub stage_budget_ms: f64,
    pub logical_updates: usize,
    pub logical_payload_bytes: usize,
    pub physical_messages: usize,
    pub total_bytes_sent: usize,
    pub message_amplification_factor: f64,
    pub average_sender_cpu_ms: f64,
    pub p50_dissemination_latency_ms: f64,
    pub p95_dissemination_latency_ms: f64,
    pub p99_dissemination_latency_ms: f64,
    pub peak_sender_queue_depth: f64,
    pub updates_over_stage_budget: usize,
    pub late_causal_receipts: usize,
    pub late_causal_receipt_rate: f64,
    pub total_cost: f64,
    pub bullwhip_ratio: f64,
    pub cost_delta_vs_oracle: f64,
    pub bullwhip_delta_vs_oracle: f64,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum TransportMode {
    UnicastFanout,
    SlimGroup,
    InMemoryOracle,
}

impl TransportMode {
    fn all() -> [Self; 3] {
        [Self::UnicastFanout, Self::SlimGroup, Self::InMemoryOracle]
    }

    fn label(self) -> &'static str {
        match self {
            Self::UnicastFanout => "unicast_fanout",
            Self::SlimGroup => "slim_group",
            Self::InMemoryOracle => "in_memory_oracle",
        }
    }
}

#[derive(Clone, Debug, Default)]
struct TransportProfile {
    physical_messages: usize,
    total_bytes_sent: usize,
    average_sender_cpu_ms: f64,
    p50_dissemination_latency_ms: f64,
    p95_dissemination_latency_ms: f64,
    p99_dissemination_latency_ms: f64,
    peak_sender_queue_depth: f64,
    rounds_over_budget: usize,
    stale_view_rate: f64,
}

#[derive(Clone, Debug)]
struct RoundTransportMetrics {
    physical_messages: usize,
    bytes_sent: usize,
    sender_cpu_ms: f64,
    dissemination_latency_ms: f64,
    receipt_latencies_ms: Vec<f64>,
}

#[derive(Clone, Debug)]
struct ReceiptSummary {
    dissemination_latency_ms: f64,
    receipt_latencies_ms: Vec<f64>,
}

#[derive(Clone, Debug, Default)]
struct ResourceTransportOutcome {
    late_state_receipts: usize,
    final_stock: f64,
    sustainability_breaches: usize,
}

#[derive(Clone, Debug, Default)]
struct PreferenceTransportOutcome {
    late_round_receipts: usize,
    final_disagreement_l2: f64,
    relative_disagreement: f64,
    final_proposals: Vec<f64>,
}

#[derive(Clone, Debug, Default)]
struct CascadeTransportOutcome {
    late_causal_receipts: usize,
    total_cost: f64,
    bullwhip_ratio: f64,
    order_history: Vec<Vec<f64>>,
    inventory_history: Vec<Vec<f64>>,
}

#[derive(Clone, Debug)]
struct ReceiveEvent {
    round_index: usize,
    participant_index: usize,
    payload: Vec<u8>,
    received_at: Instant,
}

#[derive(Clone, Debug)]
enum ParticipantMode {
    PointToPoint,
    Group { channel: String },
}

#[derive(Clone, Debug)]
struct TlsMaterial {
    cert: PathBuf,
    key: PathBuf,
    ca: PathBuf,
}

struct BenchmarkDir {
    path: PathBuf,
}

impl BenchmarkDir {
    fn new(label: &str) -> Result<Self, String> {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| format!("system time error: {err}"))?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "shadi-mas-slim-transport-{label}-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path)
            .map_err(|err| format!("failed to create {}: {}", path.display(), err))?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for BenchmarkDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

struct SlimBenchEnvironment {
    _dir: BenchmarkDir,
    endpoint: String,
    node_service: Service,
    sender_tls: TlsMaterial,
    participant_tls_pool: Vec<TlsMaterial>,
}

impl SlimBenchEnvironment {
    fn start() -> Result<Self, String> {
        let dir = BenchmarkDir::new("env")?;
        let tls_dir = generate_test_tls_dir(dir.path())?;
        let endpoint = reserve_test_endpoint()?;
        let sender_tls = client_tls_material(&tls_dir, "avatar")?;
        let participant_tls_pool = PARTICIPANT_CERT_NAMES
            .into_iter()
            .map(|agent_id| client_tls_material(&tls_dir, agent_id))
            .collect::<Result<Vec<_>, _>>()?;
        let server_tls = server_tls_material(&tls_dir)?;
        let node_service = Service::new(unique_service_name("node"));
        node_service
            .run_server(build_server_config(&endpoint, &server_tls))
            .map_err(format_slim_error)?;
        thread::sleep(Duration::from_millis(250));

        Ok(Self {
            _dir: dir,
            endpoint,
            node_service,
            sender_tls,
            participant_tls_pool,
        })
    }

    fn participant_tls(&self, index: usize) -> TlsMaterial {
        self.participant_tls_pool[index % self.participant_tls_pool.len()].clone()
    }
}

impl Drop for SlimBenchEnvironment {
    fn drop(&mut self) {
        let _ = self.node_service.stop_server(self.endpoint.clone());
        let _ = self.node_service.shutdown();
    }
}

struct SpawnedParticipants {
    names: Vec<String>,
    ready_rx: mpsc::Receiver<usize>,
    joined_rx: mpsc::Receiver<usize>,
    receive_rx: mpsc::Receiver<ReceiveEvent>,
    handles: Vec<thread::JoinHandle<Result<(), String>>>,
}

pub fn run_transport_sweep() -> Result<Vec<TransportSweepRow>, String> {
    install_quiet_tracing_subscriber();
    let agent_counts = transport_agent_counts()?;
    let round_durations_ms = transport_round_durations_ms()?;
    let mut rows = Vec::new();
    let environment = SlimBenchEnvironment::start()?;

    for agent_count in agent_counts {
        let (config, execution, payloads) = capture_resource_workload(agent_count, 0.35)?;
        let logical_updates = payloads.len();
        let logical_payload_bytes = payloads.iter().map(Vec::len).sum::<usize>();

        let mut mode_metrics: Vec<(TransportMode, Vec<RoundTransportMetrics>)> = Vec::new();
        for transport_mode in TransportMode::all() {
            mode_metrics.push((
                transport_mode,
                measure_transport(&environment, transport_mode, agent_count, &payloads)?,
            ));
        }

        let oracle_metrics = mode_metrics
            .iter()
            .find_map(|(transport_mode, round_metrics)| {
                (*transport_mode == TransportMode::InMemoryOracle).then_some(round_metrics.as_slice())
            })
            .ok_or_else(|| "missing in-memory oracle transport profile".to_string())?;

        for round_duration_ms in &round_durations_ms {
            let oracle_outcome = simulate_resource_transport_semantics(
                &config,
                oracle_metrics,
                *round_duration_ms,
            )?;
            if (oracle_outcome.final_stock - execution.report.final_stock).abs() > 1e-9
                || oracle_outcome.sustainability_breaches
                    != execution.report.sustainability_breaches
            {
                return Err(format!(
                    concat!(
                        "transport-aware oracle diverged from pure resource execution: ",
                        "expected final_stock={:.6}, breaches={}, got final_stock={:.6}, breaches={}"
                    ),
                    execution.report.final_stock,
                    execution.report.sustainability_breaches,
                    oracle_outcome.final_stock,
                    oracle_outcome.sustainability_breaches,
                ));
            }

            for (transport_mode, round_metrics) in &mode_metrics {
                let profile = summarize_transport(round_metrics, *round_duration_ms);
                let outcome = simulate_resource_transport_semantics(
                    &config,
                    round_metrics,
                    *round_duration_ms,
                )?;
                let budget_critical_receipts = config
                    .rounds
                    .saturating_sub(1)
                    .saturating_mul(agent_count);
                rows.push(TransportSweepRow {
                    transport_mode: transport_mode.label(),
                    agent_count,
                    rounds: config.rounds,
                    round_duration_ms: *round_duration_ms,
                    logical_updates,
                    logical_payload_bytes,
                    physical_messages: profile.physical_messages,
                    total_bytes_sent: profile.total_bytes_sent,
                    message_amplification_factor: if logical_updates > 0 {
                        profile.physical_messages as f64 / logical_updates as f64
                    } else {
                        0.0
                    },
                    average_sender_cpu_ms: profile.average_sender_cpu_ms,
                    p50_dissemination_latency_ms: profile.p50_dissemination_latency_ms,
                    p95_dissemination_latency_ms: profile.p95_dissemination_latency_ms,
                    p99_dissemination_latency_ms: profile.p99_dissemination_latency_ms,
                    peak_sender_queue_depth: profile.peak_sender_queue_depth,
                    rounds_over_budget: profile.rounds_over_budget,
                    stale_view_rate: profile.stale_view_rate,
                    late_state_receipts: outcome.late_state_receipts,
                    late_state_receipt_rate: if budget_critical_receipts > 0 {
                        outcome.late_state_receipts as f64 / budget_critical_receipts as f64
                    } else {
                        0.0
                    },
                    final_stock: outcome.final_stock,
                    sustainability_breaches: outcome.sustainability_breaches,
                    final_stock_delta_vs_oracle: outcome.final_stock - oracle_outcome.final_stock,
                    breach_increase_vs_oracle: outcome.sustainability_breaches as isize
                        - oracle_outcome.sustainability_breaches as isize,
                });
            }
        }
    }

    Ok(rows)
}

pub fn run_preference_transport_sweep() -> Result<Vec<PreferenceTransportSweepRow>, String> {
    install_quiet_tracing_subscriber();
    let agent_counts = transport_agent_counts()?;
    let round_durations_ms = transport_round_durations_ms()?;
    let mut rows = Vec::new();
    let environment = SlimBenchEnvironment::start()?;

    for agent_count in agent_counts {
        let (config, report, payloads) = capture_preference_workload(agent_count)?;
        let logical_updates = payloads.len();
        let logical_payload_bytes = payloads.iter().map(Vec::len).sum::<usize>();

        let mut mode_metrics: Vec<(TransportMode, Vec<RoundTransportMetrics>)> = Vec::new();
        for transport_mode in TransportMode::all() {
            mode_metrics.push((
                transport_mode,
                measure_transport(&environment, transport_mode, agent_count, &payloads)?,
            ));
        }

        let oracle_metrics = mode_metrics
            .iter()
            .find_map(|(transport_mode, round_metrics)| {
                (*transport_mode == TransportMode::InMemoryOracle).then_some(round_metrics.as_slice())
            })
            .ok_or_else(|| "missing in-memory oracle transport profile".to_string())?;

        for round_duration_ms in &round_durations_ms {
            let oracle_outcome =
                simulate_preference_transport_semantics(&config, oracle_metrics, *round_duration_ms)?;
            let expected_final_disagreement = report.disagreement_l2.last().copied().unwrap_or_default();
            if (oracle_outcome.final_disagreement_l2 - expected_final_disagreement).abs() > 1e-9
                || !approx_equal_slice(&oracle_outcome.final_proposals, &report.final_proposals)
            {
                return Err(format!(
                    concat!(
                        "transport-aware preference oracle diverged from pure execution: ",
                        "expected disagreement={:.6}, got disagreement={:.6}"
                    ),
                    expected_final_disagreement,
                    oracle_outcome.final_disagreement_l2,
                ));
            }

            for (transport_mode, round_metrics) in &mode_metrics {
                let profile =
                    summarize_preference_transport(round_metrics, agent_count, *round_duration_ms)?;
                let outcome =
                    simulate_preference_transport_semantics(&config, round_metrics, *round_duration_ms)?;
                let budget_critical_receipts = config
                    .rounds
                    .saturating_sub(1)
                    .saturating_mul(agent_count)
                    .saturating_mul(agent_count);

                rows.push(PreferenceTransportSweepRow {
                    transport_mode: transport_mode.label(),
                    agent_count,
                    rounds: config.rounds,
                    round_duration_ms: *round_duration_ms,
                    logical_updates,
                    logical_payload_bytes,
                    physical_messages: profile.physical_messages,
                    total_bytes_sent: profile.total_bytes_sent,
                    message_amplification_factor: if logical_updates > 0 {
                        profile.physical_messages as f64 / logical_updates as f64
                    } else {
                        0.0
                    },
                    average_sender_cpu_ms: profile.average_sender_cpu_ms,
                    p50_dissemination_latency_ms: profile.p50_dissemination_latency_ms,
                    p95_dissemination_latency_ms: profile.p95_dissemination_latency_ms,
                    p99_dissemination_latency_ms: profile.p99_dissemination_latency_ms,
                    peak_sender_queue_depth: profile.peak_sender_queue_depth,
                    rounds_over_budget: profile.rounds_over_budget,
                    stale_view_rate: profile.stale_view_rate,
                    late_round_receipts: outcome.late_round_receipts,
                    late_round_receipt_rate: if budget_critical_receipts > 0 {
                        outcome.late_round_receipts as f64 / budget_critical_receipts as f64
                    } else {
                        0.0
                    },
                    final_disagreement_l2: outcome.final_disagreement_l2,
                    relative_disagreement: outcome.relative_disagreement,
                    disagreement_delta_vs_oracle: outcome.final_disagreement_l2
                        - oracle_outcome.final_disagreement_l2,
                });
            }
        }
    }

    Ok(rows)
}

pub fn run_cascade_transport_sweep() -> Result<Vec<CascadeTransportSweepRow>, String> {
    install_quiet_tracing_subscriber();
    let stage_counts = transport_agent_counts()?;
    let round_durations_ms = transport_round_durations_ms()?;
    let mut rows = Vec::new();
    let environment = SlimBenchEnvironment::start()?;

    for stages in stage_counts {
        let (config, execution, payloads) = capture_cascade_workload(stages)?;
        let logical_updates = payloads.len();
        let logical_payload_bytes = payloads.iter().map(Vec::len).sum::<usize>();

        let mut mode_metrics: Vec<(TransportMode, Vec<RoundTransportMetrics>)> = Vec::new();
        for transport_mode in TransportMode::all() {
            mode_metrics.push((
                transport_mode,
                measure_transport(&environment, transport_mode, stages, &payloads)?,
            ));
        }

        let oracle_metrics = mode_metrics
            .iter()
            .find_map(|(transport_mode, round_metrics)| {
                (*transport_mode == TransportMode::InMemoryOracle).then_some(round_metrics.as_slice())
            })
            .ok_or_else(|| "missing in-memory oracle transport profile".to_string())?;

        for round_duration_ms in &round_durations_ms {
            let oracle_outcome =
                simulate_cascade_transport_semantics(&config, oracle_metrics, *round_duration_ms)?;
            if (oracle_outcome.total_cost - execution.report.total_cost).abs() > 1e-9
                || (oracle_outcome.bullwhip_ratio - execution.report.bullwhip_ratio).abs() > 1e-9
                || !approx_equal_matrix(&oracle_outcome.order_history, &execution.report.order_history)
                || !approx_equal_matrix(
                    &oracle_outcome.inventory_history,
                    &execution.report.inventory_history,
                )
            {
                return Err(format!(
                    concat!(
                        "transport-aware cascade oracle diverged from pure execution: ",
                        "expected total_cost={:.6}, bullwhip_ratio={:.6}, got total_cost={:.6}, bullwhip_ratio={:.6}"
                    ),
                    execution.report.total_cost,
                    execution.report.bullwhip_ratio,
                    oracle_outcome.total_cost,
                    oracle_outcome.bullwhip_ratio,
                ));
            }

            for (transport_mode, round_metrics) in &mode_metrics {
                let stage_budget_ms = cascade_stage_budget_ms(config.stages, *round_duration_ms);
                let profile = summarize_transport(round_metrics, stage_budget_ms);
                let outcome =
                    simulate_cascade_transport_semantics(&config, round_metrics, *round_duration_ms)?;
                let budget_critical_receipts = config
                    .customer_demand
                    .len()
                    .saturating_mul(config.stages.saturating_sub(1));

                rows.push(CascadeTransportSweepRow {
                    transport_mode: transport_mode.label(),
                    stages: config.stages,
                    lead_time: config.lead_time,
                    customer_rounds: config.customer_demand.len(),
                    round_duration_ms: *round_duration_ms,
                    stage_budget_ms,
                    logical_updates,
                    logical_payload_bytes,
                    physical_messages: profile.physical_messages,
                    total_bytes_sent: profile.total_bytes_sent,
                    message_amplification_factor: if logical_updates > 0 {
                        profile.physical_messages as f64 / logical_updates as f64
                    } else {
                        0.0
                    },
                    average_sender_cpu_ms: profile.average_sender_cpu_ms,
                    p50_dissemination_latency_ms: profile.p50_dissemination_latency_ms,
                    p95_dissemination_latency_ms: profile.p95_dissemination_latency_ms,
                    p99_dissemination_latency_ms: profile.p99_dissemination_latency_ms,
                    peak_sender_queue_depth: profile.peak_sender_queue_depth,
                    updates_over_stage_budget: profile.rounds_over_budget,
                    late_causal_receipts: outcome.late_causal_receipts,
                    late_causal_receipt_rate: if budget_critical_receipts > 0 {
                        outcome.late_causal_receipts as f64 / budget_critical_receipts as f64
                    } else {
                        0.0
                    },
                    total_cost: outcome.total_cost,
                    bullwhip_ratio: outcome.bullwhip_ratio,
                    cost_delta_vs_oracle: outcome.total_cost - oracle_outcome.total_cost,
                    bullwhip_delta_vs_oracle: outcome.bullwhip_ratio - oracle_outcome.bullwhip_ratio,
                });
            }
        }
    }

    Ok(rows)
}

fn transport_agent_counts() -> Result<Vec<usize>, String> {
    parse_usize_list_env("SHADI_TRANSPORT_AGENT_COUNTS")
        .map(|value| value.unwrap_or_else(|| TRANSPORT_AGENT_COUNTS.to_vec()))
}

fn transport_round_durations_ms() -> Result<Vec<f64>, String> {
    parse_f64_list_env("SHADI_TRANSPORT_ROUND_DURATIONS_MS")
        .map(|value| value.unwrap_or_else(|| TRANSPORT_ROUND_DURATIONS_MS.to_vec()))
}

fn parse_usize_list_env(name: &str) -> Result<Option<Vec<usize>>, String> {
    match std::env::var(name) {
        Ok(raw) => {
            let values = raw
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| {
                    value
                        .parse::<usize>()
                        .map_err(|err| format!("failed to parse {name} value '{value}': {err}"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            if values.is_empty() {
                Err(format!("{name} must contain at least one comma-separated value"))
            } else {
                Ok(Some(values))
            }
        }
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(err) => Err(format!("failed to read {name}: {err}")),
    }
}

fn parse_f64_list_env(name: &str) -> Result<Option<Vec<f64>>, String> {
    match std::env::var(name) {
        Ok(raw) => {
            let values = raw
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| {
                    value
                        .parse::<f64>()
                        .map_err(|err| format!("failed to parse {name} value '{value}': {err}"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            if values.is_empty() {
                Err(format!("{name} must contain at least one comma-separated value"))
            } else {
                Ok(Some(values))
            }
        }
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(err) => Err(format!("failed to read {name}: {err}")),
    }
}

fn install_quiet_tracing_subscriber() {
    QUIET_TRACING_INIT.call_once(|| {
        let _ = tracing::subscriber::set_global_default(tracing::subscriber::NoSubscriber::default());
    });
}

pub fn render_transport_summary_text(rows: &[TransportSweepRow]) -> String {
    let mut content = String::from("slim_transport_analysis\n");
    for row in rows {
        content.push_str(&format!(
            concat!(
                "mode: {}, agents: {}, round_duration_ms: {:.1}, amplification: {:.2}, ",
                "bytes_sent: {}, p95_latency_ms: {:.3}, peak_queue_depth: {:.3}, stale_view_rate: {:.3}, ",
                "late_state_rate: {:.3}, final_stock: {:.3}, stock_delta_vs_oracle: {:.3}, breaches: {}\n"
            ),
            row.transport_mode,
            row.agent_count,
            row.round_duration_ms,
            row.message_amplification_factor,
            row.total_bytes_sent,
            row.p95_dissemination_latency_ms,
            row.peak_sender_queue_depth,
            row.stale_view_rate,
            row.late_state_receipt_rate,
            row.final_stock,
            row.final_stock_delta_vs_oracle,
            row.sustainability_breaches,
        ));
    }
    content
}

pub fn render_preference_transport_summary_text(rows: &[PreferenceTransportSweepRow]) -> String {
    let mut content = String::from("slim_preference_transport_analysis\n");
    for row in rows {
        content.push_str(&format!(
            concat!(
                "mode: {}, agents: {}, round_duration_ms: {:.1}, amplification: {:.2}, ",
                "bytes_sent: {}, p95_latency_ms: {:.3}, late_round_rate: {:.3}, ",
                "final_disagreement_l2: {:.3}, relative_disagreement: {:.3}, disagreement_delta_vs_oracle: {:.3}\n"
            ),
            row.transport_mode,
            row.agent_count,
            row.round_duration_ms,
            row.message_amplification_factor,
            row.total_bytes_sent,
            row.p95_dissemination_latency_ms,
            row.late_round_receipt_rate,
            row.final_disagreement_l2,
            row.relative_disagreement,
            row.disagreement_delta_vs_oracle,
        ));
    }
    content
}

pub fn render_cascade_transport_summary_text(rows: &[CascadeTransportSweepRow]) -> String {
    let mut content = String::from("slim_cascade_transport_analysis\n");
    for row in rows {
        content.push_str(&format!(
            concat!(
                "mode: {}, stages: {}, round_duration_ms: {:.1}, stage_budget_ms: {:.3}, ",
                "amplification: {:.2}, p95_latency_ms: {:.3}, late_causal_rate: {:.3}, ",
                "total_cost: {:.3}, cost_delta_vs_oracle: {:.3}, bullwhip_ratio: {:.3}, bullwhip_delta_vs_oracle: {:.3}\n"
            ),
            row.transport_mode,
            row.stages,
            row.round_duration_ms,
            row.stage_budget_ms,
            row.message_amplification_factor,
            row.p95_dissemination_latency_ms,
            row.late_causal_receipt_rate,
            row.total_cost,
            row.cost_delta_vs_oracle,
            row.bullwhip_ratio,
            row.bullwhip_delta_vs_oracle,
        ));
    }
    content
}

pub fn render_transport_csv(rows: &[TransportSweepRow]) -> String {
    let mut content = String::from(
        "transport_mode,agent_count,rounds,round_duration_ms,logical_updates,logical_payload_bytes,physical_messages,total_bytes_sent,message_amplification_factor,average_sender_cpu_ms,p50_dissemination_latency_ms,p95_dissemination_latency_ms,p99_dissemination_latency_ms,peak_sender_queue_depth,rounds_over_budget,stale_view_rate,late_state_receipts,late_state_receipt_rate,final_stock,sustainability_breaches,final_stock_delta_vs_oracle,breach_increase_vs_oracle\n",
    );
    for row in rows {
        content.push_str(&format!(
            "{},{},{},{:.1},{},{},{},{},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{},{:.6},{},{:.6},{:.6},{},{:.6},{}\n",
            row.transport_mode,
            row.agent_count,
            row.rounds,
            row.round_duration_ms,
            row.logical_updates,
            row.logical_payload_bytes,
            row.physical_messages,
            row.total_bytes_sent,
            row.message_amplification_factor,
            row.average_sender_cpu_ms,
            row.p50_dissemination_latency_ms,
            row.p95_dissemination_latency_ms,
            row.p99_dissemination_latency_ms,
            row.peak_sender_queue_depth,
            row.rounds_over_budget,
            row.stale_view_rate,
            row.late_state_receipts,
            row.late_state_receipt_rate,
            row.final_stock,
            row.sustainability_breaches,
            row.final_stock_delta_vs_oracle,
            row.breach_increase_vs_oracle,
        ));
    }
    content
}

pub fn render_preference_transport_csv(rows: &[PreferenceTransportSweepRow]) -> String {
    let mut content = String::from(
        "transport_mode,agent_count,rounds,round_duration_ms,logical_updates,logical_payload_bytes,physical_messages,total_bytes_sent,message_amplification_factor,average_sender_cpu_ms,p50_dissemination_latency_ms,p95_dissemination_latency_ms,p99_dissemination_latency_ms,peak_sender_queue_depth,rounds_over_budget,stale_view_rate,late_round_receipts,late_round_receipt_rate,final_disagreement_l2,relative_disagreement,disagreement_delta_vs_oracle\n",
    );
    for row in rows {
        content.push_str(&format!(
            "{},{},{},{:.1},{},{},{},{},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{},{:.6},{},{:.6},{:.6},{:.6},{:.6}\n",
            row.transport_mode,
            row.agent_count,
            row.rounds,
            row.round_duration_ms,
            row.logical_updates,
            row.logical_payload_bytes,
            row.physical_messages,
            row.total_bytes_sent,
            row.message_amplification_factor,
            row.average_sender_cpu_ms,
            row.p50_dissemination_latency_ms,
            row.p95_dissemination_latency_ms,
            row.p99_dissemination_latency_ms,
            row.peak_sender_queue_depth,
            row.rounds_over_budget,
            row.stale_view_rate,
            row.late_round_receipts,
            row.late_round_receipt_rate,
            row.final_disagreement_l2,
            row.relative_disagreement,
            row.disagreement_delta_vs_oracle,
        ));
    }
    content
}

pub fn render_cascade_transport_csv(rows: &[CascadeTransportSweepRow]) -> String {
    let mut content = String::from(
        "transport_mode,stages,lead_time,customer_rounds,round_duration_ms,stage_budget_ms,logical_updates,logical_payload_bytes,physical_messages,total_bytes_sent,message_amplification_factor,average_sender_cpu_ms,p50_dissemination_latency_ms,p95_dissemination_latency_ms,p99_dissemination_latency_ms,peak_sender_queue_depth,updates_over_stage_budget,late_causal_receipts,late_causal_receipt_rate,total_cost,bullwhip_ratio,cost_delta_vs_oracle,bullwhip_delta_vs_oracle\n",
    );
    for row in rows {
        content.push_str(&format!(
            "{},{},{},{},{:.1},{:.6},{},{},{},{},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{},{},{:.6},{:.6},{:.6},{:.6},{:.6}\n",
            row.transport_mode,
            row.stages,
            row.lead_time,
            row.customer_rounds,
            row.round_duration_ms,
            row.stage_budget_ms,
            row.logical_updates,
            row.logical_payload_bytes,
            row.physical_messages,
            row.total_bytes_sent,
            row.message_amplification_factor,
            row.average_sender_cpu_ms,
            row.p50_dissemination_latency_ms,
            row.p95_dissemination_latency_ms,
            row.p99_dissemination_latency_ms,
            row.peak_sender_queue_depth,
            row.updates_over_stage_budget,
            row.late_causal_receipts,
            row.late_causal_receipt_rate,
            row.total_cost,
            row.bullwhip_ratio,
            row.cost_delta_vs_oracle,
            row.bullwhip_delta_vs_oracle,
        ));
    }
    content
}

fn simulate_cascade_transport_semantics(
    config: &CascadeExperimentConfig,
    updates: &[RoundTransportMetrics],
    round_duration_ms: f64,
) -> Result<CascadeTransportOutcome, String> {
    if config.stages == 0 {
        return Err("cascade transport simulation requires at least one stage".to_string());
    }
    if config.lead_time == 0 {
        return Err("cascade transport simulation requires lead_time >= 1".to_string());
    }
    if config.customer_demand.is_empty() {
        return Err("cascade transport simulation requires a non-empty customer demand trace".to_string());
    }

    let expected_updates = config
        .customer_demand
        .len()
        .checked_mul(config.stages)
        .ok_or_else(|| "cascade transport update count overflow".to_string())?;
    if updates.len() != expected_updates {
        return Err(format!(
            "cascade transport simulation expected {} updates, got {}",
            expected_updates,
            updates.len()
        ));
    }

    let baseline_demand = config.customer_demand[0];
    let stage_budget_ms = cascade_stage_budget_ms(config.stages, round_duration_ms);
    let mut inventory = vec![config.initial_inventory; config.stages];
    let mut previous_order = vec![baseline_demand; config.stages];
    let mut pipelines = vec![VecDeque::from(vec![baseline_demand; config.lead_time]); config.stages];
    let mut order_history = vec![Vec::with_capacity(config.customer_demand.len()); config.stages];
    let mut inventory_history = vec![Vec::with_capacity(config.customer_demand.len()); config.stages];
    let mut total_cost = 0.0;
    let mut late_causal_receipts = 0usize;

    for (round_index, &customer_demand) in config.customer_demand.iter().enumerate() {
        for stage in 0..config.stages {
            let delivery = pipelines[stage]
                .pop_front()
                .ok_or_else(|| "cascade pipeline unexpectedly empty".to_string())?;
            inventory[stage] += delivery;
        }

        for stage in 0..config.stages {
            let scheduled_stage_time_ms =
                round_index as f64 * round_duration_ms + stage as f64 * stage_budget_ms;
            let downstream_order = if stage == 0 {
                customer_demand
            } else {
                let mut visible = baseline_demand;
                for source_round in 0..=round_index {
                    let Some(&published_order) = order_history[stage - 1].get(source_round) else {
                        break;
                    };
                    let update_index = cascade_update_index(source_round, stage - 1, config.stages);
                    let round_metrics = &updates[update_index];
                    if round_metrics.receipt_latencies_ms.len() != config.stages {
                        return Err(format!(
                            "cascade update {} expected {} receipt latencies, got {}",
                            update_index,
                            config.stages,
                            round_metrics.receipt_latencies_ms.len()
                        ));
                    }
                    let delivery_time_ms = source_round as f64 * round_duration_ms
                        + (stage - 1) as f64 * stage_budget_ms
                        + round_metrics.receipt_latencies_ms[stage];
                    if delivery_time_ms <= scheduled_stage_time_ms {
                        visible = published_order;
                    }
                }
                visible
            };

            inventory[stage] -= downstream_order;
            total_cost += config.holding_cost * inventory[stage].max(0.0);
            total_cost += config.backlog_cost * (-inventory[stage]).max(0.0);

            let inventory_position = inventory[stage] + pipelines[stage].iter().sum::<f64>();
            let base_stock_target =
                config.target_inventory + downstream_order * config.lead_time as f64;
            let planned_order = (base_stock_target - inventory_position).max(0.0);

            total_cost +=
                config.adjustment_penalty * (planned_order - previous_order[stage]).abs();
            previous_order[stage] = planned_order;
            pipelines[stage].push_back(planned_order);
            order_history[stage].push(planned_order);
            inventory_history[stage].push(inventory[stage]);

            let update_index = cascade_update_index(round_index, stage, config.stages);
            let round_metrics = &updates[update_index];
            if round_metrics.receipt_latencies_ms.len() != config.stages {
                return Err(format!(
                    "cascade update {} expected {} receipt latencies, got {}",
                    update_index,
                    config.stages,
                    round_metrics.receipt_latencies_ms.len()
                ));
            }
            if stage + 1 < config.stages
                && round_metrics.receipt_latencies_ms[stage + 1] > stage_budget_ms
            {
                late_causal_receipts += 1;
            }
        }
    }

    let customer_demand_variance = cascade_variance(&config.customer_demand);
    let upstream_orders = order_history
        .last()
        .cloned()
        .ok_or_else(|| "cascade transport simulation produced no upstream orders".to_string())?;
    let upstream_order_variance = cascade_variance(&upstream_orders);
    let bullwhip_ratio = if customer_demand_variance > 0.0 {
        upstream_order_variance / customer_demand_variance
    } else {
        0.0
    };

    Ok(CascadeTransportOutcome {
        late_causal_receipts,
        total_cost,
        bullwhip_ratio,
        order_history,
        inventory_history,
    })
}

fn simulate_preference_transport_semantics(
    config: &PreferenceExperimentConfig,
    updates: &[RoundTransportMetrics],
    round_duration_ms: f64,
) -> Result<PreferenceTransportOutcome, String> {
    let agent_count = config.preferred_scores.len();
    let expected_updates = config
        .rounds
        .checked_mul(agent_count)
        .ok_or_else(|| "preference transport update count overflow".to_string())?;
    if updates.len() != expected_updates {
        return Err(format!(
            "preference transport simulation expected {} updates, got {}",
            expected_updates,
            updates.len()
        ));
    }
    for (update_index, update_metrics) in updates.iter().enumerate() {
        if update_metrics.receipt_latencies_ms.len() != agent_count {
            return Err(format!(
                "preference update {} expected {} receipt latencies, got {}",
                update_index,
                agent_count,
                update_metrics.receipt_latencies_ms.len()
            ));
        }
    }

    let initial = match &config.initial_proposals {
        Some(values) => values.clone(),
        None => config.preferred_scores.clone(),
    };
    let average_score = config.preferred_scores.iter().sum::<f64>() / agent_count as f64;
    let initial_disagreement = preference_l2_disagreement(&initial, average_score);
    let mut published_round_states: Vec<Vec<f64>> = Vec::with_capacity(config.rounds);
    let mut current = initial.clone();
    let mut late_round_receipts = 0usize;

    for round_index in 0..config.rounds {
        let scheduled_start_ms = round_index as f64 * round_duration_ms;
        let mut visible_round_states = vec![initial.clone(); agent_count];

        for receiver in 0..agent_count {
            let mut visible = initial.clone();
            for prior_round in 0..round_index {
                for sender in 0..agent_count {
                    let update_index = preference_update_index(prior_round, sender, agent_count);
                    let delivery_time_ms = prior_round as f64 * round_duration_ms
                        + updates[update_index].receipt_latencies_ms[receiver];
                    if delivery_time_ms <= scheduled_start_ms {
                        visible[sender] = published_round_states[prior_round][sender];
                    }
                }
            }
            visible_round_states[receiver] = visible;
        }

        let mut next = vec![0.0; agent_count];
        for index in 0..agent_count {
            let neighbors = &config.adjacency[index];
            let degree = neighbors.len() as f64;
            let neighbor_sum = neighbors
                .iter()
                .map(|&neighbor| visible_round_states[index][neighbor])
                .sum::<f64>();
            next[index] =
                (config.preferred_scores[index] + 2.0 * config.beta * neighbor_sum)
                    / (1.0 + 2.0 * config.beta * degree);
        }

        if round_index + 1 < config.rounds {
            late_round_receipts += (0..agent_count)
                .map(|sender| {
                    let update_index = preference_update_index(round_index, sender, agent_count);
                    updates[update_index]
                        .receipt_latencies_ms
                        .iter()
                        .filter(|&&latency_ms| latency_ms > round_duration_ms)
                        .count()
                })
                .sum::<usize>();
        }

        published_round_states.push(next.clone());
        current = next;
    }

    let final_disagreement_l2 = preference_l2_disagreement(&current, average_score);
    Ok(PreferenceTransportOutcome {
        late_round_receipts,
        final_disagreement_l2,
        relative_disagreement: if initial_disagreement > 0.0 {
            final_disagreement_l2 / initial_disagreement
        } else {
            0.0
        },
        final_proposals: current,
    })
}

fn simulate_resource_transport_semantics(
    config: &ResourceExperimentConfig,
    rounds: &[RoundTransportMetrics],
    round_duration_ms: f64,
) -> Result<ResourceTransportOutcome, String> {
    let agent_count = config.desired_extraction.len();
    if rounds.len() != config.rounds {
        return Err(format!(
            "resource transport simulation expected {} rounds, got {}",
            config.rounds,
            rounds.len()
        ));
    }

    let initial_lambda = config.initial_lambda.max(0.0);
    let mut stock = config.initial_stock;
    let mut lambda = initial_lambda;
    let mut extractions = vec![0.0; agent_count];
    let mut published_lambdas = Vec::with_capacity(config.rounds);
    let mut late_state_receipts = 0usize;
    let mut sustainability_breaches = 0usize;

    for (round_index, round_metrics) in rounds.iter().enumerate() {
        if round_metrics.receipt_latencies_ms.len() != agent_count {
            return Err(format!(
                "round {} expected {} receipt latencies, got {}",
                round_index,
                agent_count,
                round_metrics.receipt_latencies_ms.len()
            ));
        }

        let scheduled_start_ms = round_index as f64 * round_duration_ms;
        let mut visible_lambdas = vec![initial_lambda; agent_count];

        for agent in 0..agent_count {
            let mut visible_lambda = initial_lambda;
            for prior_round in 0..round_index {
                let delivery_time_ms = prior_round as f64 * round_duration_ms
                    + rounds[prior_round].receipt_latencies_ms[agent];
                if delivery_time_ms <= scheduled_start_ms {
                    visible_lambda = published_lambdas[prior_round];
                }
            }
            visible_lambdas[agent] = visible_lambda;
        }

        let sustainable_capacity = ((stock - config.min_stock).max(0.0) * config.sustainable_fraction)
            .min(stock.max(0.0));

        for agent in 0..agent_count {
            let updated = extractions[agent]
                + config.eta * (config.desired_extraction[agent] - visible_lambdas[agent]);
            extractions[agent] = updated.clamp(0.0, config.max_extraction[agent]);
        }

        let total_round_extraction = extractions.iter().sum::<f64>();
        lambda = (lambda + config.alpha * (total_round_extraction - sustainable_capacity)).max(0.0);

        let regenerated = stock
            + config.regeneration_rate * stock * (1.0 - stock / config.carrying_capacity);
        stock = (regenerated - total_round_extraction).clamp(0.0, config.carrying_capacity);
        if stock < config.min_stock {
            sustainability_breaches += 1;
        }

        if round_index + 1 < config.rounds {
            late_state_receipts += round_metrics
                .receipt_latencies_ms
                .iter()
                .filter(|&&latency_ms| latency_ms > round_duration_ms)
                .count();
        }
        published_lambdas.push(lambda);
    }

    Ok(ResourceTransportOutcome {
        late_state_receipts,
        final_stock: stock,
        sustainability_breaches,
    })
}

fn capture_resource_workload(
    agent_count: usize,
    alpha: f64,
) -> Result<
    (
        ResourceExperimentConfig,
        shadi_mas::experiments::ExperimentExecution<ResourceExperimentReport>,
        Vec<Vec<u8>>,
    ),
    String,
> {
    let config = build_resource_scaling_config(agent_count, alpha);
    let messaging = RecordingMessagingAdapter::default();
    let tools: [&dyn ToolAdapter; 0] = [];
    let execution = run_resource_experiment_with_adapters(&config, Some(&messaging), None, &tools)?;
    let payloads = messaging
        .published_messages()?
        .into_iter()
        .map(|message| message.payload)
        .collect::<Vec<_>>();

    Ok((config, execution, payloads))
}

fn capture_preference_workload(
    agent_count: usize,
) -> Result<
    (
        PreferenceExperimentConfig,
        PreferenceExperimentReport,
        Vec<Vec<u8>>,
    ),
    String,
> {
    let config = build_preference_transport_config(agent_count);
    let messaging = RecordingMessagingAdapter::default();
    let tools: [&dyn ToolAdapter; 0] = [];
    let execution =
        run_preference_experiment_with_adapters(&config, Some(&messaging), None, &tools)?;
    let payloads = messaging
        .published_messages()?
        .into_iter()
        .map(|message| message.payload)
        .collect::<Vec<_>>();
    Ok((config, execution.report, payloads))
}

fn capture_cascade_workload(
    stages: usize,
) -> Result<
    (
        CascadeExperimentConfig,
        shadi_mas::experiments::ExperimentExecution<CascadeExperimentReport>,
        Vec<Vec<u8>>,
    ),
    String,
> {
    let config = build_cascade_transport_config(stages);
    let messaging = RecordingMessagingAdapter::default();
    let tools: [&dyn ToolAdapter; 0] = [];
    let execution =
        run_cascade_experiment_with_adapters(&config, Some(&messaging), None, &tools)?;
    let payloads = messaging
        .published_messages()?
        .into_iter()
        .map(|message| message.payload)
        .collect::<Vec<_>>();

    Ok((config, execution, payloads))
}

fn measure_transport(
    environment: &SlimBenchEnvironment,
    transport_mode: TransportMode,
    agent_count: usize,
    payloads: &[Vec<u8>],
) -> Result<Vec<RoundTransportMetrics>, String> {
    match transport_mode {
        TransportMode::UnicastFanout => benchmark_unicast(environment, agent_count, payloads),
        TransportMode::SlimGroup => benchmark_group(environment, agent_count, payloads),
        TransportMode::InMemoryOracle => Ok(payloads
            .iter()
            .map(|_| RoundTransportMetrics {
                physical_messages: 0,
                bytes_sent: 0,
                sender_cpu_ms: 0.0,
                dissemination_latency_ms: 0.0,
                receipt_latencies_ms: vec![0.0; agent_count],
            })
            .collect()),
    }
}

fn summarize_transport(rounds: &[RoundTransportMetrics], round_duration_ms: f64) -> TransportProfile {
    let mut latencies = rounds
        .iter()
        .map(|round| round.dissemination_latency_ms)
        .collect::<Vec<_>>();
    let mut physical_messages = 0usize;
    let mut total_bytes_sent = 0usize;
    let mut total_sender_cpu_ms = 0.0;
    for round in rounds {
        physical_messages += round.physical_messages;
        total_bytes_sent += round.bytes_sent;
        total_sender_cpu_ms += round.sender_cpu_ms;
    }

    latencies.sort_by(|left, right| left.partial_cmp(right).unwrap_or(std::cmp::Ordering::Equal));
    let rounds_count = rounds.len();
    let (peak_sender_queue_depth, rounds_over_budget) = derive_budget_pressure(rounds, round_duration_ms);

    TransportProfile {
        physical_messages,
        total_bytes_sent,
        average_sender_cpu_ms: if rounds_count > 0 {
            total_sender_cpu_ms / rounds_count as f64
        } else {
            0.0
        },
        p50_dissemination_latency_ms: quantile(&latencies, 0.50),
        p95_dissemination_latency_ms: quantile(&latencies, 0.95),
        p99_dissemination_latency_ms: quantile(&latencies, 0.99),
        peak_sender_queue_depth,
        rounds_over_budget,
        stale_view_rate: if rounds_count > 0 {
            rounds_over_budget as f64 / rounds_count as f64
        } else {
            0.0
        },
    }
}

// Queue pressure is derived from measured dissemination completion times
// against the configured round cadence.
fn derive_budget_pressure(
    rounds: &[RoundTransportMetrics],
    round_duration_ms: f64,
) -> (f64, usize) {
    let mut completion_times_ms = Vec::with_capacity(rounds.len());
    let mut peak_queue_depth = 0usize;
    let mut rounds_over_budget = 0usize;

    for (round_index, round) in rounds.iter().enumerate() {
        let scheduled_start_ms = round_index as f64 * round_duration_ms;
        let backlog = completion_times_ms
            .iter()
            .filter(|&&completion_ms| completion_ms > scheduled_start_ms)
            .count();
        peak_queue_depth = peak_queue_depth.max(backlog);

        if round.dissemination_latency_ms > round_duration_ms {
            rounds_over_budget += 1;
        }

        completion_times_ms.push(scheduled_start_ms + round.dissemination_latency_ms);
    }

    (peak_queue_depth as f64, rounds_over_budget)
}

fn summarize_preference_transport(
    updates: &[RoundTransportMetrics],
    agent_count: usize,
    round_duration_ms: f64,
) -> Result<TransportProfile, String> {
    if agent_count == 0 {
        return Err("preference transport summary requires at least one agent".to_string());
    }
    if updates.len() % agent_count != 0 {
        return Err(format!(
            "preference transport summary expected a multiple of {} updates, got {}",
            agent_count,
            updates.len()
        ));
    }

    let mut latencies = updates
        .iter()
        .map(|update| update.dissemination_latency_ms)
        .collect::<Vec<_>>();
    let mut physical_messages = 0usize;
    let mut total_bytes_sent = 0usize;
    let mut total_sender_cpu_ms = 0.0;
    for update in updates {
        physical_messages += update.physical_messages;
        total_bytes_sent += update.bytes_sent;
        total_sender_cpu_ms += update.sender_cpu_ms;
    }

    latencies.sort_by(|left, right| left.partial_cmp(right).unwrap_or(std::cmp::Ordering::Equal));
    let rounds_count = updates.len() / agent_count;
    let (peak_sender_queue_depth, rounds_over_budget) =
        derive_grouped_budget_pressure(updates, agent_count, round_duration_ms)?;

    Ok(TransportProfile {
        physical_messages,
        total_bytes_sent,
        average_sender_cpu_ms: if !updates.is_empty() {
            total_sender_cpu_ms / updates.len() as f64
        } else {
            0.0
        },
        p50_dissemination_latency_ms: quantile(&latencies, 0.50),
        p95_dissemination_latency_ms: quantile(&latencies, 0.95),
        p99_dissemination_latency_ms: quantile(&latencies, 0.99),
        peak_sender_queue_depth,
        rounds_over_budget,
        stale_view_rate: if rounds_count > 0 {
            rounds_over_budget as f64 / rounds_count as f64
        } else {
            0.0
        },
    })
}

fn derive_grouped_budget_pressure(
    updates: &[RoundTransportMetrics],
    group_size: usize,
    round_duration_ms: f64,
) -> Result<(f64, usize), String> {
    if group_size == 0 {
        return Err("grouped budget pressure requires a positive group size".to_string());
    }
    if updates.len() % group_size != 0 {
        return Err(format!(
            "grouped budget pressure expected a multiple of {} updates, got {}",
            group_size,
            updates.len()
        ));
    }

    let mut completion_times_ms = Vec::with_capacity(updates.len() / group_size);
    let mut peak_queue_depth = 0usize;
    let mut rounds_over_budget = 0usize;

    for (round_index, round_updates) in updates.chunks(group_size).enumerate() {
        let scheduled_start_ms = round_index as f64 * round_duration_ms;
        let backlog = completion_times_ms
            .iter()
            .filter(|&&completion_ms| completion_ms > scheduled_start_ms)
            .count();
        peak_queue_depth = peak_queue_depth.max(backlog);

        let round_completion_ms = round_updates
            .iter()
            .map(|update| update.dissemination_latency_ms)
            .fold(0.0, f64::max);
        if round_completion_ms > round_duration_ms {
            rounds_over_budget += 1;
        }

        completion_times_ms.push(scheduled_start_ms + round_completion_ms);
    }

    Ok((peak_queue_depth as f64, rounds_over_budget))
}

fn quantile(values: &[f64], quantile: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let index = ((values.len() - 1) as f64 * quantile).round() as usize;
    values[index.min(values.len() - 1)]
}

fn build_resource_scaling_config(agent_count: usize, alpha: f64) -> ResourceExperimentConfig {
    let desired_extraction = (0..agent_count)
        .map(|index| match index % 3 {
            1 => 2.5,
            _ => 2.0,
        })
        .collect();

    ResourceExperimentConfig {
        desired_extraction,
        max_extraction: vec![3.0; agent_count],
        rounds: 12,
        initial_stock: 8.0 * agent_count as f64,
        min_stock: 2.0 * agent_count as f64,
        carrying_capacity: 10.0 * agent_count as f64,
        regeneration_rate: 0.2,
        sustainable_fraction: 0.25,
        eta: 0.4,
        alpha,
        initial_lambda: 0.0,
    }
}

fn build_preference_transport_config(agent_count: usize) -> PreferenceExperimentConfig {
    let adjacency = (0..agent_count)
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
        .collect();
    let preferred_scores = if agent_count == 1 {
        vec![4.0]
    } else {
        (0..agent_count)
            .map(|index| 8.0 * index as f64 / (agent_count - 1) as f64)
            .collect()
    };

    PreferenceExperimentConfig {
        adjacency,
        preferred_scores,
        beta: 0.75,
        rounds: 12,
        initial_proposals: None,
    }
}

fn build_cascade_transport_config(stages: usize) -> CascadeExperimentConfig {
    let mut customer_demand = vec![4.0; 3];
    customer_demand.extend([8.0; 3]);
    customer_demand.extend([4.0; 6]);

    CascadeExperimentConfig {
        stages,
        lead_time: 2,
        customer_demand,
        initial_inventory: 8.0,
        target_inventory: 8.0,
        holding_cost: 1.0,
        backlog_cost: 2.0,
        adjustment_penalty: 0.25,
    }
}

fn cascade_stage_budget_ms(stages: usize, round_duration_ms: f64) -> f64 {
    let _ = stages;
    round_duration_ms
}

fn preference_update_index(round_index: usize, agent_index: usize, agent_count: usize) -> usize {
    round_index * agent_count + agent_index
}

fn cascade_update_index(round_index: usize, stage: usize, stages: usize) -> usize {
    round_index * stages + stage
}

fn preference_l2_disagreement(values: &[f64], average: f64) -> f64 {
    values
        .iter()
        .map(|value| {
            let delta = value - average;
            delta * delta
        })
        .sum::<f64>()
        .sqrt()
}

fn cascade_variance(values: &[f64]) -> f64 {
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

fn approx_equal_slice(left: &[f64], right: &[f64]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right.iter())
            .all(|(lhs, rhs)| (lhs - rhs).abs() <= 1e-9)
}

fn approx_equal_matrix(left: &[Vec<f64>], right: &[Vec<f64>]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right.iter())
            .all(|(lhs, rhs)| approx_equal_slice(lhs, rhs))
}

fn benchmark_unicast(
    environment: &SlimBenchEnvironment,
    agent_count: usize,
    payloads: &[Vec<u8>],
) -> Result<Vec<RoundTransportMetrics>, String> {
    let benchmark_id = format!("unicast-{}", unique_suffix());
    let participants = spawn_participants(
        environment,
        &benchmark_id,
        agent_count,
        payloads.len(),
        ParticipantMode::PointToPoint,
    )?;
    wait_for_participants(&participants.ready_rx, agent_count, "participant readiness")?;
    thread::sleep(Duration::from_millis(200));

    let service = Service::new(unique_service_name("unicast-sender"));
    let sender_name = Arc::new(parse_name(&sender_name(&benchmark_id))?);
    let connection_id = service
        .connect(build_client_config(&environment.endpoint, &environment.sender_tls))
        .map_err(format_slim_error)?;
    let app = service
        .create_app_with_secret(sender_name.clone(), BENCHMARK_SHARED_SECRET.to_string())
        .map_err(format_slim_error)?;
    app.subscribe(sender_name.clone(), Some(connection_id))
        .map_err(format_slim_error)?;

    let mut sessions = Vec::with_capacity(participants.names.len());
    for participant_name in &participants.names {
        let participant = Arc::new(parse_name(participant_name)?);
        app.set_route(participant.clone(), connection_id)
            .map_err(format_slim_error)?;
        let session = app
            .create_session_and_wait(point_to_point_session_config(), participant)
            .map_err(format_slim_error)?;
        sessions.push(session);
    }
    wait_for_participants(&participants.joined_rx, agent_count, "session join")?;

    let mut metrics = Vec::with_capacity(payloads.len());
    for (round_index, payload) in payloads.iter().enumerate() {
        let round_started = Instant::now();
        let mut sender_elapsed = Duration::ZERO;
        for session in &sessions {
            let send_started = Instant::now();
            session
                .publish_and_wait(payload.clone(), None, Some(HashMap::new()))
                .map_err(format_slim_error)?;
            sender_elapsed += send_started.elapsed();
        }
        let receipts = collect_round_receipts(
            &participants.receive_rx,
            round_index,
            payload,
            agent_count,
            round_started,
        )?;

        metrics.push(RoundTransportMetrics {
            physical_messages: agent_count,
            bytes_sent: payload.len() * agent_count,
            sender_cpu_ms: duration_ms(sender_elapsed),
            dissemination_latency_ms: receipts.dissemination_latency_ms,
            receipt_latencies_ms: receipts.receipt_latencies_ms,
        });
    }

    cleanup_sender(&app, &sessions, &[sender_name], connection_id, service)?;
    join_participants(participants.handles)?;
    Ok(metrics)
}

fn benchmark_group(
    environment: &SlimBenchEnvironment,
    agent_count: usize,
    payloads: &[Vec<u8>],
) -> Result<Vec<RoundTransportMetrics>, String> {
    let benchmark_id = format!("group-{}", unique_suffix());
    let channel = channel_name(&benchmark_id);
    let participants = spawn_participants(
        environment,
        &benchmark_id,
        agent_count,
        payloads.len(),
        ParticipantMode::Group {
            channel: channel.clone(),
        },
    )?;
    wait_for_participants(&participants.ready_rx, agent_count, "participant readiness")?;
    thread::sleep(Duration::from_millis(200));

    let service = Service::new(unique_service_name("group-sender"));
    let sender_name = Arc::new(parse_name(&sender_name(&benchmark_id))?);
    let channel_name = Arc::new(parse_name(&channel)?);
    let connection_id = service
        .connect(build_client_config(&environment.endpoint, &environment.sender_tls))
        .map_err(format_slim_error)?;
    let app = service
        .create_app_with_secret(sender_name.clone(), BENCHMARK_SHARED_SECRET.to_string())
        .map_err(format_slim_error)?;
    app.subscribe(sender_name.clone(), Some(connection_id))
        .map_err(format_slim_error)?;

    let session = app
        .create_session_and_wait(group_session_config(), channel_name.clone())
        .map_err(format_slim_error)?;
    for participant_name in &participants.names {
        let participant = Arc::new(parse_name(participant_name)?);
        app.set_route(participant.clone(), connection_id)
            .map_err(format_slim_error)?;
        session.invite_and_wait(participant).map_err(format_slim_error)?;
    }
    wait_for_participants(&participants.joined_rx, agent_count, "session join")?;

    let mut metrics = Vec::with_capacity(payloads.len());
    for (round_index, payload) in payloads.iter().enumerate() {
        let round_started = Instant::now();
        let send_started = Instant::now();
        session
            .publish_and_wait(payload.clone(), None, Some(HashMap::new()))
            .map_err(format_slim_error)?;
        let receipts = collect_round_receipts(
            &participants.receive_rx,
            round_index,
            payload,
            agent_count,
            round_started,
        )?;

        metrics.push(RoundTransportMetrics {
            physical_messages: 1,
            bytes_sent: payload.len(),
            sender_cpu_ms: duration_ms(send_started.elapsed()),
            dissemination_latency_ms: receipts.dissemination_latency_ms,
            receipt_latencies_ms: receipts.receipt_latencies_ms,
        });
    }

    cleanup_sender(&app, &[session], &[sender_name, channel_name], connection_id, service)?;
    join_participants(participants.handles)?;
    Ok(metrics)
}

fn spawn_participants(
    environment: &SlimBenchEnvironment,
    benchmark_id: &str,
    agent_count: usize,
    payload_count: usize,
    mode: ParticipantMode,
) -> Result<SpawnedParticipants, String> {
    let (ready_tx, ready_rx) = mpsc::channel();
    let (joined_tx, joined_rx) = mpsc::channel();
    let (receive_tx, receive_rx) = mpsc::channel();
    let mut names = Vec::with_capacity(agent_count);
    let mut handles = Vec::with_capacity(agent_count);

    for participant_index in 0..agent_count {
        let participant_name = participant_name(benchmark_id, participant_index);
        let participant_tls = environment.participant_tls(participant_index);
        let endpoint = environment.endpoint.clone();
        let mode = mode.clone();
        let ready_tx = ready_tx.clone();
        let joined_tx = joined_tx.clone();
        let receive_tx = receive_tx.clone();
        let participant_name_for_thread = participant_name.clone();

        handles.push(thread::spawn(move || {
            participant_loop(
                &endpoint,
                participant_tls,
                participant_index,
                participant_name_for_thread,
                payload_count,
                mode,
                ready_tx,
                joined_tx,
                receive_tx,
            )
        }));
        names.push(participant_name);
    }

    Ok(SpawnedParticipants {
        names,
        ready_rx,
        joined_rx,
        receive_rx,
        handles,
    })
}

fn participant_loop(
    endpoint: &str,
    tls: TlsMaterial,
    participant_index: usize,
    participant_name: String,
    payload_count: usize,
    mode: ParticipantMode,
    ready_tx: mpsc::Sender<usize>,
    joined_tx: mpsc::Sender<usize>,
    receive_tx: mpsc::Sender<ReceiveEvent>,
) -> Result<(), String> {
    let service = Service::new(unique_service_name("participant"));
    let participant_name = Arc::new(parse_name(&participant_name)?);
    let connection_id = service
        .connect(build_client_config(endpoint, &tls))
        .map_err(format_slim_error)?;
    let app = service
        .create_app_with_secret(participant_name.clone(), BENCHMARK_SHARED_SECRET.to_string())
        .map_err(format_slim_error)?;
    let mut subscriptions = vec![participant_name.clone()];
    app.subscribe(participant_name.clone(), Some(connection_id))
        .map_err(format_slim_error)?;

    if let ParticipantMode::Group { channel } = &mode {
        let channel = Arc::new(parse_name(channel)?);
        app.subscribe(channel.clone(), Some(connection_id))
            .map_err(format_slim_error)?;
        subscriptions.push(channel);
    }

    ready_tx
        .send(participant_index)
        .map_err(|err| err.to_string())?;
    let session = app
        .listen_for_session(Some(SESSION_TIMEOUT))
        .map_err(format_slim_error)?;
    joined_tx
        .send(participant_index)
        .map_err(|err| err.to_string())?;

    for round_index in 0..payload_count {
        let payload = session
            .get_message(Some(SESSION_TIMEOUT))
            .map_err(format_slim_error)?
            .payload;
        receive_tx
            .send(ReceiveEvent {
                round_index,
                participant_index,
                payload,
                received_at: Instant::now(),
            })
            .map_err(|err| err.to_string())?;
    }

    cleanup_participant(app, session, subscriptions, connection_id, service)
}

fn cleanup_sender(
    app: &Arc<App>,
    sessions: &[Arc<Session>],
    subscriptions: &[Arc<Name>],
    connection_id: u64,
    service: Service,
) -> Result<(), String> {
    for session in sessions {
        let _ = app.delete_session_and_wait(session.clone());
    }
    for subscription in subscriptions {
        let _ = app.unsubscribe(subscription.clone(), Some(connection_id));
    }
    service.disconnect(connection_id).map_err(format_slim_error)?;
    service.shutdown().map_err(format_slim_error)
}

fn cleanup_participant(
    app: Arc<App>,
    session: Arc<Session>,
    subscriptions: Vec<Arc<Name>>,
    connection_id: u64,
    service: Service,
) -> Result<(), String> {
    let _ = app.delete_session_and_wait(session);
    for subscription in subscriptions {
        let _ = app.unsubscribe(subscription, Some(connection_id));
    }
    service.disconnect(connection_id).map_err(format_slim_error)?;
    service.shutdown().map_err(format_slim_error)
}

fn wait_for_participants(
    receiver: &mpsc::Receiver<usize>,
    count: usize,
    label: &str,
) -> Result<(), String> {
    for _ in 0..count {
        receiver
            .recv_timeout(SESSION_TIMEOUT)
            .map_err(|err| format!("timed out waiting for {label}: {err}"))?;
    }
    Ok(())
}

fn collect_round_receipts(
    receiver: &mpsc::Receiver<ReceiveEvent>,
    round_index: usize,
    expected_payload: &[u8],
    participant_count: usize,
    round_started: Instant,
) -> Result<ReceiptSummary, String> {
    let mut received = 0usize;
    let mut latest_receipt = round_started;
    let mut receipt_latencies_ms = vec![0.0; participant_count];

    while received < participant_count {
        let event = receiver
            .recv_timeout(SESSION_TIMEOUT)
            .map_err(|err| format!("timed out waiting for round {round_index} receipt: {err}"))?;
        if event.round_index != round_index {
            return Err(format!(
                "received round {} while waiting for round {}",
                event.round_index, round_index
            ));
        }
        if event.payload != expected_payload {
            return Err(format!(
                "participant {} received an unexpected payload in round {}",
                event.participant_index, round_index
            ));
        }
        if event.participant_index >= participant_count {
            return Err(format!(
                "participant {} exceeded expected count {} in round {}",
                event.participant_index,
                participant_count,
                round_index
            ));
        }
        receipt_latencies_ms[event.participant_index] =
            duration_ms(event.received_at.duration_since(round_started));
        latest_receipt = latest_receipt.max(event.received_at);
        received += 1;
    }

    Ok(ReceiptSummary {
        dissemination_latency_ms: duration_ms(latest_receipt.duration_since(round_started)),
        receipt_latencies_ms,
    })
}

fn join_participants(handles: Vec<thread::JoinHandle<Result<(), String>>>) -> Result<(), String> {
    for handle in handles {
        let joined = handle
            .join()
            .map_err(|_| "participant thread panicked".to_string())?;
        joined?;
    }
    Ok(())
}

fn generate_test_tls_dir(base_dir: &Path) -> Result<PathBuf, String> {
    let tls_dir = base_dir.join("shadi-slim-mtls");
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tools")
        .join("generate_slim_mtls_certs.sh");
    let output = Command::new("bash")
        .arg(&script)
        .arg(&tls_dir)
        .output()
        .map_err(|err| format!("failed to run {}: {}", script.display(), err))?;
    if !output.status.success() {
        return Err(format!(
            "failed to generate SLIM benchmark certs: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(tls_dir)
}

fn reserve_test_endpoint() -> Result<String, String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|err| format!("failed to bind ephemeral port: {err}"))?;
    let endpoint = listener
        .local_addr()
        .map_err(|err| format!("failed to read local addr: {err}"))?
        .to_string();
    drop(listener);
    Ok(endpoint)
}

fn client_tls_material(base_dir: &Path, agent_id: &str) -> Result<TlsMaterial, String> {
    let cert = base_dir.join(format!("client-{agent_id}.crt"));
    let key = base_dir.join(format!("client-{agent_id}.key"));
    let ca = base_dir.join("ca.crt");
    ensure_file_exists(&cert, "SLIM client certificate")?;
    ensure_file_exists(&key, "SLIM client key")?;
    ensure_file_exists(&ca, "SLIM CA certificate")?;
    Ok(TlsMaterial { cert, key, ca })
}

fn server_tls_material(base_dir: &Path) -> Result<TlsMaterial, String> {
    let cert = base_dir.join("server.crt");
    let key = base_dir.join("server.key");
    let ca = base_dir.join("ca.crt");
    ensure_file_exists(&cert, "SLIM server certificate")?;
    ensure_file_exists(&key, "SLIM server key")?;
    ensure_file_exists(&ca, "SLIM CA certificate")?;
    Ok(TlsMaterial { cert, key, ca })
}

fn build_client_config(endpoint: &str, tls: &TlsMaterial) -> ClientConfig {
    let mut config = ClientConfig::default();
    config.endpoint = format!("https://{endpoint}");
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

fn build_server_config(endpoint: &str, tls: &TlsMaterial) -> ServerConfig {
    let mut config = ServerConfig::default();
    config.endpoint = endpoint.to_string();
    config.tls = TlsServerConfig {
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
    };
    config
}

fn point_to_point_session_config() -> SessionConfig {
    SessionConfig {
        session_type: SessionType::PointToPoint,
        enable_mls: true,
        max_retries: Some(5),
        interval: Some(Duration::from_secs(5)),
        metadata: HashMap::new(),
    }
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

fn parse_name(value: &str) -> Result<Name, String> {
    Name::from_string(value.to_string()).map_err(format_slim_error)
}

fn format_slim_error(err: SlimError) -> String {
    err.to_string()
}

fn ensure_file_exists(path: &Path, label: &str) -> Result<(), String> {
    if path.is_file() {
        Ok(())
    } else {
        Err(format!("{} not found at {}", label, path.display()))
    }
}

fn unique_service_name(label: &str) -> String {
    format!("shadi-mas-transport-{label}-{}", unique_suffix())
}

fn unique_suffix() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}

fn sender_name(benchmark_id: &str) -> String {
    format!("agntcy/shadi/{benchmark_id}-sender")
}

fn participant_name(benchmark_id: &str, participant_index: usize) -> String {
    format!("agntcy/shadi/{benchmark_id}-participant-{participant_index}")
}

fn channel_name(benchmark_id: &str) -> String {
    format!("agntcy/shadi/{benchmark_id}-channel")
}

fn duration_ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}