#[path = "common/live_protocol_support.rs"]
mod live_protocol_support;

use std::fs;
use std::path::Path;

use live_protocol_support::{
    demo_bot_binary, parse_output_dir, prepare_live_env, repo_root, run_live_case,
    run_with_recording_protocol_counts, LiveProtocolConfig,
};
use serde::Serialize;
use shadi_mas::experiments::{
    calibrated_live_cascade_config, calibrated_live_preference_config,
    run_cascade_experiment_with_adapters,
    run_preference_experiment_with_adapters, run_resource_experiment_with_adapters,
    validate_tool_invocations, ExperimentInteractionSummary, InteractionTraceEvent,
    ResourceExperimentConfig, ToolInvocationValidationSummary,
};

const EXECUTION_MODE: &str = "mixed_protocol_replay";

fn main() -> Result<(), String> {
    let output_dir = parse_output_dir("artifacts/experiments/mas_live_protocol_spotcheck")?;
    fs::create_dir_all(&output_dir)
        .map_err(|err| format!("failed to create {}: {}", output_dir.display(), err))?;

    let config = LiveProtocolConfig::from_env()?;
    let repo_root = repo_root()?;
    let demo_bot = demo_bot_binary(&repo_root)?;
    prepare_live_env(&config);

    let preference = run_preference_spotcheck(&config, &demo_bot, &output_dir)?;
    let cascade = run_cascade_spotcheck(&config, &demo_bot, &output_dir)?;
    let resource = run_resource_spotcheck(&config, &demo_bot, &output_dir)?;
    let tool_outputs_affect_state = preference.interactions.llm_state_updates > 0
        || cascade.interactions.llm_state_updates > 0
        || resource.interactions.llm_state_updates > 0;

    let summary = LiveProtocolSummary {
        endpoint: config.endpoint.clone(),
        llm_backend: config.llm_backend.clone(),
        llm_model: config.llm_model.clone(),
        local_agent_id: config.local_agent_id.clone(),
        peer_agent_id: config.peer_agent_id.clone(),
        execution_mode: EXECUTION_MODE.to_string(),
        tool_outputs_affect_state,
        preference,
        cascade,
        resource,
    };

    let summary_json = serde_json::to_string_pretty(&summary)
        .map_err(|err| format!("failed to encode live protocol summary: {}", err))?;
    fs::write(output_dir.join("live_protocol_summary.json"), summary_json)
        .map_err(|err| format!("failed to write live_protocol_summary.json: {}", err))?;
    fs::write(
        output_dir.join("live_protocol_summary.txt"),
        render_live_protocol_summary_text(&summary),
    )
    .map_err(|err| format!("failed to write live_protocol_summary.txt: {}", err))?;

    println!("{}", output_dir.display());
    Ok(())
}

fn run_preference_spotcheck(
    config: &LiveProtocolConfig,
    demo_bot: &Path,
    output_dir: &Path,
) -> Result<LiveWorkloadSummary, String> {
    let experiment = calibrated_live_preference_config(3)?;

    let recording = run_with_recording_protocol_counts(|messaging, tasks| {
        run_preference_experiment_with_adapters(&experiment, Some(messaging), Some(tasks), &[])
    })?;

    let live = run_live_case(
        config,
        demo_bot,
        output_dir,
        "preference",
        recording.interactions.dispatched_tasks,
        recording.interactions.published_messages,
        experiment.preferred_scores.len(),
        |messaging, tasks, tools| {
            run_preference_experiment_with_adapters(&experiment, Some(messaging), Some(tasks), tools)
        },
    )?;

    let baseline_metrics = LiveMetrics::Preference {
        final_disagreement_l2: live
            .execution
            .report
            .disagreement_l2
            .last()
            .copied()
            .unwrap_or_default(),
        average_score: live.execution.report.average_score,
    };
    let live_protocol_support::LiveCaseResult {
        execution,
        task_dispatches,
        slim_acknowledgements,
        tool_results,
        tool_invocations,
        a2a_peer_output,
        slim_peer_output,
        ..
    } = live;
    let shadi_mas::experiments::ExperimentExecution {
        interactions,
        trace,
        ..
    } = execution;

    Ok(LiveWorkloadSummary {
        slim_mode: "group".to_string(),
        slim_peer_count: experiment.preferred_scores.len(),
        interactions,
        baseline_metrics,
        llm_validation: validate_tool_invocations(&tool_invocations),
        trace,
        a2a_responses: task_dispatches
            .into_iter()
            .map(|record| record.response)
            .collect(),
        slim_acknowledgements,
        llm_outputs: tool_results
            .into_iter()
            .map(|result| String::from_utf8_lossy(&result.payload).trim().to_string())
            .collect(),
        a2a_peer_output,
        slim_peer_output,
    })
}

fn run_cascade_spotcheck(
    config: &LiveProtocolConfig,
    demo_bot: &Path,
    output_dir: &Path,
) -> Result<LiveWorkloadSummary, String> {
    let experiment = calibrated_live_cascade_config(1)?;

    let recording = run_with_recording_protocol_counts(|messaging, tasks| {
        run_cascade_experiment_with_adapters(&experiment, Some(messaging), Some(tasks), &[])
    })?;

    let live = run_live_case(
        config,
        demo_bot,
        output_dir,
        "cascade",
        recording.interactions.dispatched_tasks,
        recording.interactions.published_messages,
        experiment.stages,
        |messaging, tasks, tools| {
            run_cascade_experiment_with_adapters(&experiment, Some(messaging), Some(tasks), tools)
        },
    )?;

    let baseline_metrics = LiveMetrics::Cascade {
        total_cost: live.execution.report.total_cost,
        bullwhip_ratio: live.execution.report.bullwhip_ratio,
    };
    let live_protocol_support::LiveCaseResult {
        execution,
        task_dispatches,
        slim_acknowledgements,
        tool_results,
        tool_invocations,
        a2a_peer_output,
        slim_peer_output,
        ..
    } = live;
    let shadi_mas::experiments::ExperimentExecution {
        interactions,
        trace,
        ..
    } = execution;

    Ok(LiveWorkloadSummary {
        slim_mode: "group".to_string(),
        slim_peer_count: experiment.stages,
        interactions,
        baseline_metrics,
        llm_validation: validate_tool_invocations(&tool_invocations),
        trace,
        a2a_responses: task_dispatches
            .into_iter()
            .map(|record| record.response)
            .collect(),
        slim_acknowledgements,
        llm_outputs: tool_results
            .into_iter()
            .map(|result| String::from_utf8_lossy(&result.payload).trim().to_string())
            .collect(),
        a2a_peer_output,
        slim_peer_output,
    })
}

fn run_resource_spotcheck(
    config: &LiveProtocolConfig,
    demo_bot: &Path,
    output_dir: &Path,
) -> Result<LiveWorkloadSummary, String> {
    let experiment = ResourceExperimentConfig {
        desired_extraction: vec![2.0],
        max_extraction: vec![3.0],
        rounds: 1,
        initial_stock: 24.0,
        min_stock: 6.0,
        carrying_capacity: 30.0,
        regeneration_rate: 0.2,
        sustainable_fraction: 0.25,
        eta: 0.4,
        alpha: 0.35,
        initial_lambda: 0.0,
    };

    let recording = run_with_recording_protocol_counts(|messaging, tasks| {
        run_resource_experiment_with_adapters(&experiment, Some(messaging), Some(tasks), &[])
    })?;

    let live = run_live_case(
        config,
        demo_bot,
        output_dir,
        "resource",
        recording.interactions.dispatched_tasks,
        recording.interactions.published_messages,
        experiment.desired_extraction.len(),
        |messaging, tasks, tools| {
            run_resource_experiment_with_adapters(&experiment, Some(messaging), Some(tasks), tools)
        },
    )?;

    let baseline_metrics = LiveMetrics::Resource {
        final_stock: live.execution.report.final_stock,
        sustainability_breaches: live.execution.report.sustainability_breaches,
    };
    let live_protocol_support::LiveCaseResult {
        execution,
        task_dispatches,
        slim_acknowledgements,
        tool_results,
        tool_invocations,
        a2a_peer_output,
        slim_peer_output,
        ..
    } = live;
    let shadi_mas::experiments::ExperimentExecution {
        interactions,
        trace,
        ..
    } = execution;

    Ok(LiveWorkloadSummary {
        slim_mode: "group".to_string(),
        slim_peer_count: experiment.desired_extraction.len(),
        interactions,
        baseline_metrics,
        llm_validation: validate_tool_invocations(&tool_invocations),
        trace,
        a2a_responses: task_dispatches
            .into_iter()
            .map(|record| record.response)
            .collect(),
        slim_acknowledgements,
        llm_outputs: tool_results
            .into_iter()
            .map(|result| String::from_utf8_lossy(&result.payload).trim().to_string())
            .collect(),
        a2a_peer_output,
        slim_peer_output,
    })
}

#[derive(Serialize)]
struct LiveProtocolSummary {
    endpoint: String,
    llm_backend: String,
    llm_model: String,
    local_agent_id: String,
    peer_agent_id: String,
    execution_mode: String,
    tool_outputs_affect_state: bool,
    preference: LiveWorkloadSummary,
    cascade: LiveWorkloadSummary,
    resource: LiveWorkloadSummary,
}

#[derive(Serialize)]
struct LiveWorkloadSummary {
    slim_mode: String,
    slim_peer_count: usize,
    interactions: ExperimentInteractionSummary,
    baseline_metrics: LiveMetrics,
    llm_validation: ToolInvocationValidationSummary,
    trace: Vec<InteractionTraceEvent>,
    a2a_responses: Vec<String>,
    slim_acknowledgements: Vec<String>,
    llm_outputs: Vec<String>,
    a2a_peer_output: String,
    slim_peer_output: String,
}

#[derive(Serialize)]
#[serde(tag = "kind")]
enum LiveMetrics {
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

fn render_live_protocol_summary_text(summary: &LiveProtocolSummary) -> String {
    format!(
        concat!(
            "endpoint: {}\n",
            "llm_backend: {}\n",
            "llm_model: {}\n",
            "local_agent_id: {}\n",
            "execution_mode: {}\n",
            "tool_outputs_affect_state: {}\n",
            "peer_agent_id: {}\n\n",
            "preference\n",
            "{}\n\n",
            "cascade\n",
            "{}\n\n",
            "resource\n",
            "{}\n"
        ),
        summary.endpoint,
        summary.llm_backend,
        summary.llm_model,
        summary.local_agent_id,
        summary.execution_mode,
        summary.tool_outputs_affect_state,
        summary.peer_agent_id,
        render_workload_text(&summary.preference),
        render_workload_text(&summary.cascade),
        render_workload_text(&summary.resource),
    )
}

fn render_workload_text(summary: &LiveWorkloadSummary) -> String {
    let llm_sample = summary.llm_outputs.first().cloned().unwrap_or_default();
    let a2a_sample = summary.a2a_responses.first().cloned().unwrap_or_default();
    let slim_sample = summary
        .slim_acknowledgements
        .first()
        .cloned()
        .unwrap_or_default();
    format!(
        concat!(
            "slim_mode: {} peer_count: {}\n",
            "interactions: messages={}, tasks={}, mcp={}, agentskills={}, llm_state_updates={}, llm_state_fallbacks={}\n",
            "llm_valid: {}/{} ({:.1}%)\n",
            "baseline_metrics: {}\n",
            "a2a_sample: {}\n",
            "slim_sample: {}\n",
            "llm_sample: {}"
        ),
        summary.slim_mode,
        summary.slim_peer_count,
        summary.interactions.published_messages,
        summary.interactions.dispatched_tasks,
        summary.interactions.mcp_tool_calls,
        summary.interactions.agentskills_tool_calls,
        summary.interactions.llm_state_updates,
        summary.interactions.llm_state_fallbacks,
        summary.llm_validation.valid_invocations,
        summary.llm_validation.total_invocations,
        summary.llm_validation.valid_ratio * 100.0,
        render_metrics_text(&summary.baseline_metrics),
        a2a_sample,
        slim_sample,
        llm_sample,
    )
}

fn render_metrics_text(metrics: &LiveMetrics) -> String {
    match metrics {
        LiveMetrics::Preference {
            final_disagreement_l2,
            average_score,
        } => format!(
            "final_disagreement_l2={:.6}, average_score={:.6}",
            final_disagreement_l2, average_score
        ),
        LiveMetrics::Cascade {
            total_cost,
            bullwhip_ratio,
        } => format!(
            "total_cost={:.6}, bullwhip_ratio={:.6}",
            total_cost, bullwhip_ratio
        ),
        LiveMetrics::Resource {
            final_stock,
            sustainability_breaches,
        } => format!(
            "final_stock={:.6}, sustainability_breaches={}",
            final_stock, sustainability_breaches
        ),
    }
}