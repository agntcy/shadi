#[path = "common/live_protocol_support.rs"]
mod live_protocol_support;

use std::fmt::Write;
use std::fs;

use live_protocol_support::{
    demo_bot_binary, parse_output_dir, prepare_live_env, repo_root, run_live_case,
    run_with_recording_protocol_counts, LiveProtocolConfig,
};
use serde::Serialize;
use shadi_mas::experiments::{
    calibrated_live_cascade_config, calibrated_live_preference_config,
    run_cascade_experiment_with_adapters,
    run_preference_experiment_with_adapters, run_resource_experiment_with_adapters,
    run_resource_experiment_with_sustainable_capacity_cap,
    validate_tool_invocations, CommandToolInvocationRecord, ExperimentInteractionSummary,
    ResourceExperimentConfig, ToolInvocationValidationSummary,
};

const DEFAULT_SCALES: &[usize] = &[1, 2, 3, 4, 5];
const EXECUTION_MODE: &str = "mixed_protocol_replay";

fn main() -> Result<(), String> {
    let output_dir = parse_output_dir("artifacts/experiments/mas_live_protocol_sweep")?;
    fs::create_dir_all(&output_dir)
        .map_err(|err| format!("failed to create {}: {}", output_dir.display(), err))?;

    let config = LiveProtocolConfig::from_env()?;
    let scales = parse_scales()?;
    let repo_root = repo_root()?;
    let demo_bot = demo_bot_binary(&repo_root)?;
    prepare_live_env(&config);

    let mut cases = Vec::new();
    for &scale in &scales {
        cases.push(run_preference_case(&config, &demo_bot, &output_dir, scale)?);
    }
    for &scale in &scales {
        cases.push(run_cascade_case(&config, &demo_bot, &output_dir, scale)?);
    }
    for &scale in &scales {
        cases.push(run_resource_case(&config, &demo_bot, &output_dir, scale)?);
    }
    let tool_outputs_affect_state = cases
        .iter()
        .any(|case| case.interactions.llm_state_updates > 0);

    let summary = LiveProtocolSweepSummary {
        endpoint: config.endpoint.clone(),
        llm_backend: config.llm_backend.clone(),
        llm_model: config.llm_model.clone(),
        local_agent_id: config.local_agent_id.clone(),
        peer_agent_id: config.peer_agent_id.clone(),
        execution_mode: EXECUTION_MODE.to_string(),
        tool_outputs_affect_state,
        scales,
        cases,
    };

    let summary_json = serde_json::to_string_pretty(&summary)
        .map_err(|err| format!("failed to encode live protocol sweep summary: {}", err))?;
    fs::write(output_dir.join("live_protocol_sweep.json"), summary_json)
        .map_err(|err| format!("failed to write live_protocol_sweep.json: {}", err))?;
    fs::write(
        output_dir.join("live_protocol_sweep.csv"),
        render_live_protocol_sweep_csv(&summary),
    )
    .map_err(|err| format!("failed to write live_protocol_sweep.csv: {}", err))?;
    fs::write(
        output_dir.join("live_protocol_sweep.txt"),
        render_live_protocol_sweep_text(&summary),
    )
    .map_err(|err| format!("failed to write live_protocol_sweep.txt: {}", err))?;

    println!("{}", output_dir.display());
    Ok(())
}

fn parse_scales() -> Result<Vec<usize>, String> {
    let Some(raw) = std::env::var_os("SHADI_LIVE_SWEEP_SCALES") else {
        return Ok(DEFAULT_SCALES.to_vec());
    };

    let values = raw
        .to_string_lossy()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|err| format!("invalid SHADI_LIVE_SWEEP_SCALES entry `{}`: {}", value, err))
        })
        .collect::<Result<Vec<_>, _>>()?;

    if values.is_empty() {
        Err("SHADI_LIVE_SWEEP_SCALES must contain at least one positive integer".to_string())
    } else if values.iter().any(|value| *value == 0) {
        Err("SHADI_LIVE_SWEEP_SCALES must not contain zero".to_string())
    } else {
        Ok(values)
    }
}

fn run_preference_case(
    config: &LiveProtocolConfig,
    demo_bot: &std::path::Path,
    output_dir: &std::path::Path,
    scale: usize,
) -> Result<SweepCaseSummary, String> {
    let experiment = calibrated_live_preference_config(scale)?;
    let recording = run_with_recording_protocol_counts(|messaging, tasks| {
        run_preference_experiment_with_adapters(&experiment, Some(messaging), Some(tasks), &[])
    })?;
    let live = run_live_case(
        config,
        demo_bot,
        output_dir,
        &format!("preference-{}", scale),
        recording.interactions.dispatched_tasks,
        recording.interactions.published_messages,
        scale,
        |messaging, tasks, tools| {
            run_preference_experiment_with_adapters(&experiment, Some(messaging), Some(tasks), tools)
        },
    )?;
    let live_metrics = SweepCaseMetrics::Preference {
        final_disagreement_l2: live
            .execution
            .report
            .disagreement_l2
            .last()
            .copied()
            .unwrap_or_default(),
        average_score: live.execution.report.average_score,
    };
    let oracle_metrics = SweepCaseMetrics::Preference {
        final_disagreement_l2: recording
            .report
            .disagreement_l2
            .last()
            .copied()
            .unwrap_or_default(),
        average_score: recording.report.average_score,
    };
    let report_details = SweepCaseReportDetails::Preference {
        trajectory: live.execution.report.trajectory.clone(),
        disagreement_l2: live.execution.report.disagreement_l2.clone(),
        final_proposals: live.execution.report.final_proposals.clone(),
    };

    Ok(build_sweep_case_summary(
        "preference",
        scale,
        scale,
        live,
        live_metrics,
        oracle_metrics,
        report_details,
    ))
}

fn run_cascade_case(
    config: &LiveProtocolConfig,
    demo_bot: &std::path::Path,
    output_dir: &std::path::Path,
    scale: usize,
) -> Result<SweepCaseSummary, String> {
    let experiment = calibrated_live_cascade_config(scale)?;
    let recording = run_with_recording_protocol_counts(|messaging, tasks| {
        run_cascade_experiment_with_adapters(&experiment, Some(messaging), Some(tasks), &[])
    })?;
    let live = run_live_case(
        config,
        demo_bot,
        output_dir,
        &format!("cascade-{}", scale),
        recording.interactions.dispatched_tasks,
        recording.interactions.published_messages,
        scale,
        |messaging, tasks, tools| {
            run_cascade_experiment_with_adapters(&experiment, Some(messaging), Some(tasks), tools)
        },
    )?;
    let live_metrics = SweepCaseMetrics::Cascade {
        total_cost: live.execution.report.total_cost,
        bullwhip_ratio: live.execution.report.bullwhip_ratio,
    };
    let oracle_metrics = SweepCaseMetrics::Cascade {
        total_cost: recording.report.total_cost,
        bullwhip_ratio: recording.report.bullwhip_ratio,
    };
    let report_details = SweepCaseReportDetails::Cascade {
        order_history: live.execution.report.order_history.clone(),
        inventory_history: live.execution.report.inventory_history.clone(),
        customer_demand_variance: live.execution.report.customer_demand_variance,
        upstream_order_variance: live.execution.report.upstream_order_variance,
    };

    Ok(build_sweep_case_summary(
        "cascade",
        scale,
        scale,
        live,
        live_metrics,
        oracle_metrics,
        report_details,
    ))
}

fn run_resource_case(
    config: &LiveProtocolConfig,
    demo_bot: &std::path::Path,
    output_dir: &std::path::Path,
    scale: usize,
) -> Result<SweepCaseSummary, String> {
    let experiment = build_resource_scaling_config(scale, 0.35);
    let recording = run_with_recording_protocol_counts(|messaging, tasks| {
        run_resource_experiment_with_adapters(&experiment, Some(messaging), Some(tasks), &[])
    })?;
    let live = run_live_case(
        config,
        demo_bot,
        output_dir,
        &format!("resource-{}", scale),
        recording.interactions.dispatched_tasks,
        recording.interactions.published_messages,
        scale,
        |messaging, tasks, tools| {
            run_resource_experiment_with_adapters(&experiment, Some(messaging), Some(tasks), tools)
        },
    )?;
    let live_metrics = SweepCaseMetrics::Resource {
        final_stock: live.execution.report.final_stock,
        sustainability_breaches: live.execution.report.sustainability_breaches,
    };
    let capped_baseline = run_resource_experiment_with_sustainable_capacity_cap(&experiment)?;
    let oracle_metrics = SweepCaseMetrics::Resource {
        final_stock: capped_baseline.final_stock,
        sustainability_breaches: capped_baseline.sustainability_breaches,
    };
    let report_details = SweepCaseReportDetails::Resource {
        stock_history: live.execution.report.stock_history.clone(),
        lambda_history: live.execution.report.lambda_history.clone(),
        extraction_history: live.execution.report.extraction_history.clone(),
        total_extraction: live.execution.report.total_extraction,
    };

    Ok(build_sweep_case_summary(
        "resource",
        scale,
        scale,
        live,
        live_metrics,
        oracle_metrics,
        report_details,
    ))
}

fn build_sweep_case_summary<R>(
    family: &str,
    scale: usize,
    slim_peer_count: usize,
    live: live_protocol_support::LiveCaseResult<R>,
    live_metrics: SweepCaseMetrics,
    oracle_metrics: SweepCaseMetrics,
    report_details: SweepCaseReportDetails,
) -> SweepCaseSummary {
    let a2a_responses = live
        .task_dispatches
        .iter()
        .map(|record| record.response.clone())
        .collect();
    let slim_acknowledgements = live.slim_acknowledgements.clone();
    let llm_outputs = live
        .tool_invocations
        .iter()
        .map(|record| record.final_output.clone())
        .collect();
    let llm_invocations = live
        .tool_invocations
        .iter()
        .map(ToolInvocationLogEntry::from_record)
        .collect();
    let llm_validation = validate_tool_invocations(&live.tool_invocations);
    let a2a_latency = summarize_latencies(
        &live
            .task_dispatches
            .iter()
            .map(|record| record.elapsed_ms)
            .collect::<Vec<_>>(),
    );
    let slim_latency = summarize_latencies(
        &live
            .slim_exchanges
            .iter()
            .map(|record| record.round_trip_ms)
            .collect::<Vec<_>>(),
    );
    let llm_latency = summarize_latencies(
        &live
            .tool_invocations
            .iter()
            .map(|record| record.elapsed_ms)
            .collect::<Vec<_>>(),
    );
    let live_protocol_support::LiveCaseResult {
        execution,
        runtime_ms,
        a2a_peer_output,
        slim_peer_output,
        ..
    } = live;
    let shadi_mas::experiments::ExperimentExecution { interactions, .. } = execution;

    SweepCaseSummary {
        family: family.to_string(),
        scale,
        slim_mode: if slim_peer_count > 0 {
            "group".to_string()
        } else {
            "disabled".to_string()
        },
        slim_peer_count,
        interactions,
        runtime_ms,
        a2a_latency,
        slim_latency,
        llm_latency,
        a2a_responses,
        slim_acknowledgements,
        llm_outputs,
        llm_invocations,
        llm_validation,
        live_metrics,
        oracle_metrics,
        report_details,
        a2a_peer_output,
        slim_peer_output,
    }
}

fn decode_bytes(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
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

fn summarize_latencies(samples: &[f64]) -> LatencyStats {
    let count = samples.len();
    let total_ms: f64 = samples.iter().sum();
    let mean_ms = if count == 0 {
        0.0
    } else {
        total_ms / count as f64
    };
    let max_ms = samples.iter().copied().fold(0.0, f64::max);

    LatencyStats {
        count,
        total_ms,
        mean_ms,
        max_ms,
    }
}

#[derive(Serialize)]
struct LiveProtocolSweepSummary {
    endpoint: String,
    llm_backend: String,
    llm_model: String,
    local_agent_id: String,
    peer_agent_id: String,
    execution_mode: String,
    tool_outputs_affect_state: bool,
    scales: Vec<usize>,
    cases: Vec<SweepCaseSummary>,
}

#[derive(Serialize)]
struct SweepCaseSummary {
    family: String,
    scale: usize,
    slim_mode: String,
    slim_peer_count: usize,
    interactions: ExperimentInteractionSummary,
    runtime_ms: f64,
    a2a_latency: LatencyStats,
    slim_latency: LatencyStats,
    llm_latency: LatencyStats,
    a2a_responses: Vec<String>,
    slim_acknowledgements: Vec<String>,
    llm_outputs: Vec<String>,
    llm_invocations: Vec<ToolInvocationLogEntry>,
    llm_validation: ToolInvocationValidationSummary,
    live_metrics: SweepCaseMetrics,
    oracle_metrics: SweepCaseMetrics,
    report_details: SweepCaseReportDetails,
    a2a_peer_output: String,
    slim_peer_output: String,
}

#[derive(Serialize)]
struct ToolInvocationLogEntry {
    provider: String,
    tool_name: String,
    target: Option<String>,
    correlation_id: Option<String>,
    epoch: u64,
    arguments: String,
    prompt: String,
    raw_output: String,
    final_output: String,
    elapsed_ms: f64,
}

impl ToolInvocationLogEntry {
    fn from_record(record: &CommandToolInvocationRecord) -> Self {
        Self {
            provider: format!("{:?}", record.request.provider),
            tool_name: record.request.tool_name.clone(),
            target: record.request.target.clone(),
            correlation_id: record.request.correlation_id.clone(),
            epoch: record.request.epoch.0,
            arguments: decode_bytes(&record.request.arguments),
            prompt: record.prompt.clone(),
            raw_output: record.raw_output.clone(),
            final_output: record.final_output.clone(),
            elapsed_ms: record.elapsed_ms,
        }
    }
}

#[derive(Serialize)]
struct LatencyStats {
    count: usize,
    total_ms: f64,
    mean_ms: f64,
    max_ms: f64,
}

#[derive(Serialize)]
#[serde(tag = "kind")]
enum SweepCaseMetrics {
    Preference {
        final_disagreement_l2: f64,
        average_score: f64,
    },
    Cascade {
        total_cost: f64,
        bullwhip_ratio: f64,
    },
    Resource {
        final_stock: f64,
        sustainability_breaches: usize,
    },
}

#[derive(Serialize)]
#[serde(tag = "kind")]
enum SweepCaseReportDetails {
    Preference {
        trajectory: Vec<Vec<f64>>,
        disagreement_l2: Vec<f64>,
        final_proposals: Vec<f64>,
    },
    Cascade {
        order_history: Vec<Vec<f64>>,
        inventory_history: Vec<Vec<f64>>,
        customer_demand_variance: f64,
        upstream_order_variance: f64,
    },
    Resource {
        stock_history: Vec<f64>,
        lambda_history: Vec<f64>,
        extraction_history: Vec<Vec<f64>>,
        total_extraction: f64,
    },
}

fn render_live_protocol_sweep_text(summary: &LiveProtocolSweepSummary) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "endpoint: {}", summary.endpoint);
    let _ = writeln!(output, "llm_backend: {}", summary.llm_backend);
    let _ = writeln!(output, "llm_model: {}", summary.llm_model);
    let _ = writeln!(output, "local_agent_id: {}", summary.local_agent_id);
    let _ = writeln!(output, "peer_agent_id: {}", summary.peer_agent_id);
    let _ = writeln!(output, "execution_mode: {}", summary.execution_mode);
    let _ = writeln!(output, "tool_outputs_affect_state: {}", summary.tool_outputs_affect_state);
    let _ = writeln!(output, "scales: {:?}", summary.scales);

    for family in ["preference", "cascade", "resource"] {
        let _ = writeln!(output);
        let _ = writeln!(output, "{}", family);
        for case in summary.cases.iter().filter(|case| case.family == family) {
            let _ = writeln!(
                output,
                concat!(
                    "scale={} slim_mode={} slim_peers={} runtime_ms={:.3} messages={} tasks={} tools={} ",
                    "a2a_mean_ms={:.3} slim_mean_ms={:.3} llm_mean_ms={:.3} llm_valid={}/{} ",
                    "llm_state_updates={} llm_state_fallbacks={} ",
                    "live_metrics={} ",
                    "oracle_metrics={} ",
                    "llm_sample={}"
                ),
                case.scale,
                case.slim_mode,
                case.slim_peer_count,
                case.runtime_ms,
                case.interactions.published_messages,
                case.interactions.dispatched_tasks,
                case.interactions.agentskills_tool_calls,
                case.a2a_latency.mean_ms,
                case.slim_latency.mean_ms,
                case.llm_latency.mean_ms,
                case.llm_validation.valid_invocations,
                case.llm_validation.total_invocations,
                case.interactions.llm_state_updates,
                case.interactions.llm_state_fallbacks,
                render_metrics_text(&case.live_metrics),
                render_metrics_text(&case.oracle_metrics),
                case.llm_outputs.first().cloned().unwrap_or_default(),
            );
        }
    }

    output
}

fn render_live_protocol_sweep_csv(summary: &LiveProtocolSweepSummary) -> String {
    let mut output = String::from(
        "family,scale,execution_mode,tool_outputs_affect_state,slim_mode,slim_peer_count,runtime_ms,published_messages,dispatched_tasks,agentskills_tool_calls,llm_state_updates,llm_state_fallbacks,mean_a2a_ms,max_a2a_ms,mean_slim_ms,max_slim_ms,mean_llm_ms,max_llm_ms,llm_validation_total,llm_validation_valid,llm_validation_ratio,live_final_disagreement_l2,live_average_score,live_total_cost,live_bullwhip_ratio,live_final_stock,live_sustainability_breaches,oracle_final_disagreement_l2,oracle_average_score,oracle_total_cost,oracle_bullwhip_ratio,oracle_final_stock,oracle_sustainability_breaches\n",
    );

    for case in &summary.cases {
        let (
            live_final_disagreement_l2,
            live_average_score,
            live_total_cost,
            live_bullwhip_ratio,
            live_final_stock,
            live_sustainability_breaches,
        ) = render_metric_columns(&case.live_metrics);
        let (
            oracle_final_disagreement_l2,
            oracle_average_score,
            oracle_total_cost,
            oracle_bullwhip_ratio,
            oracle_final_stock,
            oracle_sustainability_breaches,
        ) = render_metric_columns(&case.oracle_metrics);
        let _ = writeln!(
            output,
            "{},{},{},{},{},{},{:.6},{},{},{},{},{},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{},{},{:.6},{},{},{},{},{},{},{},{},{},{},{},{}",
            case.family,
            case.scale,
            summary.execution_mode,
            summary.tool_outputs_affect_state,
            case.slim_mode,
            case.slim_peer_count,
            case.runtime_ms,
            case.interactions.published_messages,
            case.interactions.dispatched_tasks,
            case.interactions.agentskills_tool_calls,
            case.interactions.llm_state_updates,
            case.interactions.llm_state_fallbacks,
            case.a2a_latency.mean_ms,
            case.a2a_latency.max_ms,
            case.slim_latency.mean_ms,
            case.slim_latency.max_ms,
            case.llm_latency.mean_ms,
            case.llm_latency.max_ms,
            case.llm_validation.total_invocations,
            case.llm_validation.valid_invocations,
            case.llm_validation.valid_ratio,
            live_final_disagreement_l2,
            live_average_score,
            live_total_cost,
            live_bullwhip_ratio,
            live_final_stock,
            live_sustainability_breaches,
            oracle_final_disagreement_l2,
            oracle_average_score,
            oracle_total_cost,
            oracle_bullwhip_ratio,
            oracle_final_stock,
            oracle_sustainability_breaches,
        );
    }

    output
}

fn render_metrics_text(metrics: &SweepCaseMetrics) -> String {
    match metrics {
        SweepCaseMetrics::Preference {
            final_disagreement_l2,
            average_score,
        } => format!(
            "final_disagreement_l2={:.6}, average_score={:.6}",
            final_disagreement_l2, average_score
        ),
        SweepCaseMetrics::Cascade {
            total_cost,
            bullwhip_ratio,
        } => format!(
            "total_cost={:.6}, bullwhip_ratio={:.6}",
            total_cost, bullwhip_ratio
        ),
        SweepCaseMetrics::Resource {
            final_stock,
            sustainability_breaches,
        } => format!(
            "final_stock={:.6}, sustainability_breaches={}",
            final_stock, sustainability_breaches
        ),
    }
}

fn render_metric_columns(metrics: &SweepCaseMetrics) -> (String, String, String, String, String, String) {
    match metrics {
        SweepCaseMetrics::Preference {
            final_disagreement_l2,
            average_score,
        } => (
            format!("{:.6}", final_disagreement_l2),
            format!("{:.6}", average_score),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
        ),
        SweepCaseMetrics::Cascade {
            total_cost,
            bullwhip_ratio,
        } => (
            String::new(),
            String::new(),
            format!("{:.6}", total_cost),
            format!("{:.6}", bullwhip_ratio),
            String::new(),
            String::new(),
        ),
        SweepCaseMetrics::Resource {
            final_stock,
            sustainability_breaches,
        } => (
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            format!("{:.6}", final_stock),
            sustainability_breaches.to_string(),
        ),
    }
}