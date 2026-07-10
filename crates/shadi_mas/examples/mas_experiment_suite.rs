use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};

#[path = "common/slim_transport.rs"]
mod slim_transport;

use serde::Serialize;
use shadi_mas::experiments::{
    run_cascade_experiment, run_cascade_experiment_with_adapters,
    run_preference_experiment_with_adapters,
    run_resource_experiment, run_resource_experiment_with_adapters, CascadeExperimentConfig,
    ExperimentExecution, ExperimentInteractionSummary, InteractionTraceEvent,
    PreferenceExperimentConfig, PreferenceExperimentReport, RecordingMessagingAdapter,
    RecordingTaskAdapter, RecordingToolAdapter, ResourceExperimentConfig, ResourceExperimentReport,
};
use shadi_mas::{ToolAdapter, ToolProvider};
use slim_transport::{
    render_cascade_transport_csv, render_cascade_transport_summary_text,
    render_preference_transport_csv, render_preference_transport_summary_text, render_transport_csv,
    render_transport_summary_text, run_cascade_transport_sweep, run_preference_transport_sweep,
    run_transport_sweep, TransportSweepRow,
};

const REGIME_AGENT_COUNTS: [usize; 10] = [1, 2, 3, 4, 5, 10, 17, 33, 65, 100];

fn main() -> Result<(), String> {
    let output_dir = parse_output_dir()?;
    fs::create_dir_all(&output_dir)
        .map_err(|err| format!("failed to create {}: {}", output_dir.display(), err))?;

    let preference_config = PreferenceExperimentConfig {
        adjacency: vec![vec![1], vec![0, 2], vec![1]],
        preferred_scores: vec![0.0, 4.0, 8.0],
        beta: 0.75,
        rounds: 8,
        initial_proposals: None,
    };
    let cascade_config = CascadeExperimentConfig {
        stages: 4,
        lead_time: 2,
        customer_demand: vec![4.0, 4.0, 4.0, 8.0, 8.0, 8.0, 4.0, 4.0],
        initial_inventory: 8.0,
        target_inventory: 8.0,
        holding_cost: 1.0,
        backlog_cost: 2.0,
        adjustment_penalty: 0.25,
    };
    let coordinated_resource_config = ResourceExperimentConfig {
        desired_extraction: vec![2.0, 2.5, 2.0],
        max_extraction: vec![3.0, 3.0, 3.0],
        rounds: 12,
        initial_stock: 24.0,
        min_stock: 6.0,
        carrying_capacity: 30.0,
        regeneration_rate: 0.2,
        sustainable_fraction: 0.25,
        eta: 0.4,
        alpha: 0.35,
        initial_lambda: 0.0,
    };
    let uncontrolled_resource_config = ResourceExperimentConfig {
        alpha: 0.0,
        ..coordinated_resource_config.clone()
    };

    let preference = run_with_recording_adapters(|messaging, tasks, tools| {
        run_preference_experiment_with_adapters(&preference_config, Some(messaging), Some(tasks), tools)
    })?;
    let cascade = run_with_recording_adapters(|messaging, tasks, tools| {
        run_cascade_experiment_with_adapters(&cascade_config, Some(messaging), Some(tasks), tools)
    })?;
    let resource = run_with_recording_adapters(|messaging, tasks, tools| {
        run_resource_experiment_with_adapters(
            &coordinated_resource_config,
            Some(messaging),
            Some(tasks),
            tools,
        )
    })?;
    let uncontrolled_resource = run_resource_experiment(&uncontrolled_resource_config)?;

    write_preference_metrics_csv(&output_dir.join("preference_metrics.csv"), &preference.report)?;
    write_trace_csv(&output_dir.join("preference_trace.csv"), &preference.trace)?;
    write_cascade_metrics_csv(&output_dir.join("cascade_metrics.csv"), &cascade.report)?;
    write_trace_csv(&output_dir.join("cascade_trace.csv"), &cascade.trace)?;
    write_resource_metrics_csv(&output_dir.join("resource_coordinated_metrics.csv"), &resource.report)?;
    write_trace_csv(&output_dir.join("resource_coordinated_trace.csv"), &resource.trace)?;
    write_resource_metrics_csv(&output_dir.join("resource_uncontrolled_metrics.csv"), &uncontrolled_resource)?;

    let scaling = run_scaling_suite()?;
    write_preference_scaling_csv(&output_dir.join("preference_scaling.csv"), &scaling.preference)?;
    write_cascade_scaling_csv(&output_dir.join("cascade_scaling.csv"), &scaling.cascade)?;
    write_resource_scaling_csv(&output_dir.join("resource_scaling.csv"), &scaling.resource)?;

    let scaling_guidance = run_scaling_guidance_suite()?;
    write_preference_topology_scaling_csv(
        &output_dir.join("preference_topology_scaling.csv"),
        &scaling_guidance.preference,
    )?;
    write_cascade_depth_delay_scaling_csv(
        &output_dir.join("cascade_depth_delay_scaling.csv"),
        &scaling_guidance.cascade,
    )?;
    write_resource_contention_scaling_csv(
        &output_dir.join("resource_contention_scaling.csv"),
        &scaling_guidance.resource,
    )?;

    let placement = run_placement_suite()?;
    write_preference_placement_scaling_csv(
        &output_dir.join("preference_placement_scaling.csv"),
        &placement.preference,
    )?;
    write_cascade_placement_scaling_csv(
        &output_dir.join("cascade_placement_scaling.csv"),
        &placement.cascade,
    )?;
    write_resource_placement_scaling_csv(
        &output_dir.join("resource_placement_scaling.csv"),
        &placement.resource,
    )?;

    let slim_transport = run_transport_sweep()?;
    fs::write(
        output_dir.join("slim_transport_analysis.csv"),
        render_transport_csv(&slim_transport),
    )
    .map_err(|err| format!("failed to write slim_transport_analysis.csv: {}", err))?;

    let slim_preference_transport = run_preference_transport_sweep()?;
    fs::write(
        output_dir.join("slim_preference_transport_analysis.csv"),
        render_preference_transport_csv(&slim_preference_transport),
    )
    .map_err(|err| format!("failed to write slim_preference_transport_analysis.csv: {}", err))?;

    let slim_cascade_transport = run_cascade_transport_sweep()?;
    fs::write(
        output_dir.join("slim_cascade_transport_analysis.csv"),
        render_cascade_transport_csv(&slim_cascade_transport),
    )
    .map_err(|err| format!("failed to write slim_cascade_transport_analysis.csv: {}", err))?;

    let summary = SuiteSummary {
        preference: PreferenceSummary {
            rounds: preference_config.rounds,
            initial_disagreement_l2: preference.report.disagreement_l2.first().copied().unwrap_or_default(),
            final_disagreement_l2: preference.report.disagreement_l2.last().copied().unwrap_or_default(),
            average_score: preference.report.average_score,
            final_proposals: preference.report.final_proposals.clone(),
            interactions: preference.interactions.clone(),
        },
        cascade: CascadeSummary {
            stages: cascade_config.stages,
            lead_time: cascade_config.lead_time,
            total_cost: cascade.report.total_cost,
            bullwhip_ratio: cascade.report.bullwhip_ratio,
            upstream_order_variance: cascade.report.upstream_order_variance,
            interactions: cascade.interactions.clone(),
        },
        resource: ResourceComparisonSummary {
            coordinated: ResourceSummary {
                rounds: coordinated_resource_config.rounds,
                final_stock: resource.report.final_stock,
                total_extraction: resource.report.total_extraction,
                sustainability_breaches: resource.report.sustainability_breaches,
                interactions: Some(resource.interactions.clone()),
            },
            uncontrolled: ResourceSummary {
                rounds: uncontrolled_resource_config.rounds,
                final_stock: uncontrolled_resource.final_stock,
                total_extraction: uncontrolled_resource.total_extraction,
                sustainability_breaches: uncontrolled_resource.sustainability_breaches,
                interactions: None,
            },
            final_stock_gain: resource.report.final_stock - uncontrolled_resource.final_stock,
            breach_reduction: uncontrolled_resource.sustainability_breaches as isize
                - resource.report.sustainability_breaches as isize,
        },
    };

    let summary_json = serde_json::to_string_pretty(&summary)
        .map_err(|err| format!("failed to encode suite summary: {}", err))?;
    fs::write(output_dir.join("suite_summary.json"), summary_json)
        .map_err(|err| format!("failed to write suite_summary.json: {}", err))?;
    fs::write(output_dir.join("suite_summary.txt"), render_summary_text(&summary))
        .map_err(|err| format!("failed to write suite_summary.txt: {}", err))?;

    let scaling_json = serde_json::to_string_pretty(&scaling)
        .map_err(|err| format!("failed to encode scaling summary: {}", err))?;
    fs::write(output_dir.join("scaling_summary.json"), scaling_json)
        .map_err(|err| format!("failed to write scaling_summary.json: {}", err))?;
    fs::write(output_dir.join("scaling_summary.txt"), render_scaling_summary_text(&scaling))
        .map_err(|err| format!("failed to write scaling_summary.txt: {}", err))?;

    let scaling_guidance_json = serde_json::to_string_pretty(&scaling_guidance)
        .map_err(|err| format!("failed to encode scaling guidance summary: {}", err))?;
    fs::write(output_dir.join("scaling_guidance_summary.json"), scaling_guidance_json)
        .map_err(|err| format!("failed to write scaling_guidance_summary.json: {}", err))?;
    fs::write(
        output_dir.join("scaling_guidance_summary.txt"),
        render_scaling_guidance_summary_text(&scaling_guidance),
    )
    .map_err(|err| format!("failed to write scaling_guidance_summary.txt: {}", err))?;

    let placement_json = serde_json::to_string_pretty(&placement)
        .map_err(|err| format!("failed to encode placement summary: {}", err))?;
    fs::write(output_dir.join("placement_summary.json"), placement_json)
        .map_err(|err| format!("failed to write placement_summary.json: {}", err))?;
    fs::write(
        output_dir.join("placement_summary.txt"),
        render_placement_summary_text(&placement),
    )
    .map_err(|err| format!("failed to write placement_summary.txt: {}", err))?;

    let slim_transport_json = serde_json::to_string_pretty(&slim_transport)
        .map_err(|err| format!("failed to encode slim transport summary: {}", err))?;
    fs::write(output_dir.join("slim_transport_summary.json"), slim_transport_json)
        .map_err(|err| format!("failed to write slim_transport_summary.json: {}", err))?;
    fs::write(
        output_dir.join("slim_transport_summary.txt"),
        render_slim_transport_summary_text(&slim_transport),
    )
    .map_err(|err| format!("failed to write slim_transport_summary.txt: {}", err))?;

    let slim_preference_transport_json = serde_json::to_string_pretty(&slim_preference_transport)
        .map_err(|err| format!("failed to encode slim preference transport summary: {}", err))?;
    fs::write(
        output_dir.join("slim_preference_transport_summary.json"),
        slim_preference_transport_json,
    )
    .map_err(|err| format!("failed to write slim_preference_transport_summary.json: {}", err))?;
    fs::write(
        output_dir.join("slim_preference_transport_summary.txt"),
        render_preference_transport_summary_text(&slim_preference_transport),
    )
    .map_err(|err| format!("failed to write slim_preference_transport_summary.txt: {}", err))?;

    let slim_cascade_transport_json = serde_json::to_string_pretty(&slim_cascade_transport)
        .map_err(|err| format!("failed to encode slim cascade transport summary: {}", err))?;
    fs::write(
        output_dir.join("slim_cascade_transport_summary.json"),
        slim_cascade_transport_json,
    )
    .map_err(|err| format!("failed to write slim_cascade_transport_summary.json: {}", err))?;
    fs::write(
        output_dir.join("slim_cascade_transport_summary.txt"),
        render_cascade_transport_summary_text(&slim_cascade_transport),
    )
    .map_err(|err| format!("failed to write slim_cascade_transport_summary.txt: {}", err))?;

    println!("{}", output_dir.display());
    Ok(())
}

fn parse_output_dir() -> Result<PathBuf, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => Ok(PathBuf::from("artifacts/experiments/mas_suite")),
        [value] => Ok(PathBuf::from(value)),
        [flag, value] if flag == "--output-dir" => Ok(PathBuf::from(value)),
        _ => Err("usage: [--output-dir PATH]".to_string()),
    }
}

fn run_with_recording_adapters<R, F>(run: F) -> Result<ExperimentExecution<R>, String>
where
    F: FnOnce(
        &RecordingMessagingAdapter,
        &RecordingTaskAdapter,
        &[&dyn ToolAdapter],
    ) -> Result<ExperimentExecution<R>, String>,
{
    let messaging = RecordingMessagingAdapter::default();
    let tasks = RecordingTaskAdapter::default();
    let mcp = RecordingToolAdapter::new(ToolProvider::Mcp);
    let agentskills = RecordingToolAdapter::new(ToolProvider::AgentSkills);
    let tools: [&dyn ToolAdapter; 2] = [&mcp, &agentskills];
    run(&messaging, &tasks, &tools)
}

fn write_preference_metrics_csv(path: &Path, report: &PreferenceExperimentReport) -> Result<(), String> {
    let mut content = String::from("round,node,proposal,disagreement_l2\n");
    for (round, proposals) in report.trajectory.iter().enumerate() {
        let disagreement = report.disagreement_l2[round];
        for (node, proposal) in proposals.iter().enumerate() {
            content.push_str(&format!("{round},{node},{proposal:.6},{disagreement:.6}\n"));
        }
    }
    fs::write(path, content).map_err(|err| format!("failed to write {}: {}", path.display(), err))
}

fn write_cascade_metrics_csv(path: &Path, report: &shadi_mas::experiments::CascadeExperimentReport) -> Result<(), String> {
    let mut content = String::from("round,stage,inventory,order\n");
    let rounds = report.order_history.first().map(|history| history.len()).unwrap_or(0);
    for round in 0..rounds {
        for stage in 0..report.order_history.len() {
            content.push_str(&format!(
                "{round},{stage},{:.6},{:.6}\n",
                report.inventory_history[stage][round],
                report.order_history[stage][round]
            ));
        }
    }
    fs::write(path, content).map_err(|err| format!("failed to write {}: {}", path.display(), err))
}

fn write_resource_metrics_csv(path: &Path, report: &ResourceExperimentReport) -> Result<(), String> {
    let mut content = String::from("round,agent,extraction,stock,lambda\n");
    for round in 0..report.extraction_history.len() {
        let stock = report.stock_history[round + 1];
        let lambda = report.lambda_history[round + 1];
        for agent in 0..report.extraction_history[round].len() {
            let extraction = report.extraction_history[round][agent];
            content.push_str(&format!(
                "{round},{agent},{extraction:.6},{stock:.6},{lambda:.6}\n"
            ));
        }
    }
    fs::write(path, content).map_err(|err| format!("failed to write {}: {}", path.display(), err))
}

fn write_trace_csv(path: &Path, trace: &[InteractionTraceEvent]) -> Result<(), String> {
    let mut content = String::from(InteractionTraceEvent::csv_header());
    content.push('\n');
    for event in trace {
        content.push_str(&event.to_csv_row());
        content.push('\n');
    }
    fs::write(path, content).map_err(|err| format!("failed to write {}: {}", path.display(), err))
}

fn write_preference_scaling_csv(path: &Path, rows: &[PreferenceScalingPoint]) -> Result<(), String> {
    let mut content = String::from(
        "agent_count,rounds,initial_disagreement_l2,final_disagreement_l2,relative_disagreement,published_messages,dispatched_tasks,mcp_tool_calls,agentskills_tool_calls\n",
    );
    for row in rows {
        content.push_str(&format!(
            "{},{},{:.6},{:.6},{:.6},{},{},{},{}\n",
            row.agent_count,
            row.rounds,
            row.initial_disagreement_l2,
            row.final_disagreement_l2,
            row.relative_disagreement,
            row.interactions.published_messages,
            row.interactions.dispatched_tasks,
            row.interactions.mcp_tool_calls,
            row.interactions.agentskills_tool_calls,
        ));
    }
    fs::write(path, content).map_err(|err| format!("failed to write {}: {}", path.display(), err))
}

fn write_cascade_scaling_csv(path: &Path, rows: &[CascadeScalingPoint]) -> Result<(), String> {
    let mut content = String::from(
        "agent_count,lead_time,total_cost,bullwhip_ratio,upstream_order_variance,peak_upstream_order,published_messages,dispatched_tasks,mcp_tool_calls,agentskills_tool_calls\n",
    );
    for row in rows {
        content.push_str(&format!(
            "{},{},{:.6},{:.6},{:.6},{:.6},{},{},{},{}\n",
            row.agent_count,
            row.lead_time,
            row.total_cost,
            row.bullwhip_ratio,
            row.upstream_order_variance,
            row.peak_upstream_order,
            row.interactions.published_messages,
            row.interactions.dispatched_tasks,
            row.interactions.mcp_tool_calls,
            row.interactions.agentskills_tool_calls,
        ));
    }
    fs::write(path, content).map_err(|err| format!("failed to write {}: {}", path.display(), err))
}

fn write_resource_scaling_csv(path: &Path, rows: &[ResourceScalingPoint]) -> Result<(), String> {
    let mut content = String::from(
        "agent_count,rounds,coordinated_final_stock,uncontrolled_final_stock,stock_gain,coordinated_breaches,uncontrolled_breaches,breach_reduction,coordinated_total_extraction,uncontrolled_total_extraction,published_messages,dispatched_tasks,mcp_tool_calls,agentskills_tool_calls\n",
    );
    for row in rows {
        content.push_str(&format!(
            "{},{},{:.6},{:.6},{:.6},{},{},{},{:.6},{:.6},{},{},{},{}\n",
            row.agent_count,
            row.rounds,
            row.coordinated_final_stock,
            row.uncontrolled_final_stock,
            row.stock_gain,
            row.coordinated_breaches,
            row.uncontrolled_breaches,
            row.breach_reduction,
            row.coordinated_total_extraction,
            row.uncontrolled_total_extraction,
            row.interactions.published_messages,
            row.interactions.dispatched_tasks,
            row.interactions.mcp_tool_calls,
            row.interactions.agentskills_tool_calls,
        ));
    }
    fs::write(path, content).map_err(|err| format!("failed to write {}: {}", path.display(), err))
}

fn write_preference_topology_scaling_csv(
    path: &Path,
    rows: &[PreferenceTopologyScalingPoint],
) -> Result<(), String> {
    let mut content = String::from(
        "topology,agent_count,rounds,edge_count,mean_degree,diameter,initial_disagreement_l2,final_disagreement_l2,relative_disagreement,rounds_to_half_disagreement,neighbor_exchange_count,disagreement_reduction_per_exchange,published_messages,dispatched_tasks,mcp_tool_calls,agentskills_tool_calls\n",
    );
    for row in rows {
        let rounds_to_half = row
            .rounds_to_half_disagreement
            .map(|value| value.to_string())
            .unwrap_or_default();
        content.push_str(&format!(
            "{},{},{},{},{:.6},{},{:.6},{:.6},{:.6},{},{},{:.9},{},{},{},{}\n",
            row.topology,
            row.agent_count,
            row.rounds,
            row.edge_count,
            row.mean_degree,
            row.diameter,
            row.initial_disagreement_l2,
            row.final_disagreement_l2,
            row.relative_disagreement,
            rounds_to_half,
            row.neighbor_exchange_count,
            row.disagreement_reduction_per_exchange,
            row.interactions.published_messages,
            row.interactions.dispatched_tasks,
            row.interactions.mcp_tool_calls,
            row.interactions.agentskills_tool_calls,
        ));
    }
    fs::write(path, content).map_err(|err| format!("failed to write {}: {}", path.display(), err))
}

fn write_cascade_depth_delay_scaling_csv(
    path: &Path,
    rows: &[CascadeDepthDelayScalingPoint],
) -> Result<(), String> {
    let mut content = String::from(
        "stages,lead_time,critical_path_hops,total_cost,cost_per_stage,no_shock_total_cost,shock_cost_ratio,bullwhip_ratio,bullwhip_per_stage,peak_upstream_order,published_messages,dispatched_tasks,mcp_tool_calls,agentskills_tool_calls\n",
    );
    for row in rows {
        content.push_str(&format!(
            "{},{},{},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{},{},{},{}\n",
            row.stages,
            row.lead_time,
            row.critical_path_hops,
            row.total_cost,
            row.cost_per_stage,
            row.no_shock_total_cost,
            row.shock_cost_ratio,
            row.bullwhip_ratio,
            row.bullwhip_per_stage,
            row.peak_upstream_order,
            row.interactions.published_messages,
            row.interactions.dispatched_tasks,
            row.interactions.mcp_tool_calls,
            row.interactions.agentskills_tool_calls,
        ));
    }
    fs::write(path, content).map_err(|err| format!("failed to write {}: {}", path.display(), err))
}

fn write_resource_contention_scaling_csv(
    path: &Path,
    rows: &[ResourceContentionScalingPoint],
) -> Result<(), String> {
    let mut content = String::from(
        "agent_count,contention_multiplier,rounds,coordinated_final_stock_per_agent,uncontrolled_final_stock_per_agent,stock_gain_per_agent,coordinated_breaches_per_agent_round,uncontrolled_breaches_per_agent_round,breach_reduction_per_agent_round,coordinated_total_extraction_per_agent,uncontrolled_total_extraction_per_agent,published_messages,dispatched_tasks,mcp_tool_calls,agentskills_tool_calls\n",
    );
    for row in rows {
        content.push_str(&format!(
            "{},{:.2},{},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{},{},{},{}\n",
            row.agent_count,
            row.contention_multiplier,
            row.rounds,
            row.coordinated_final_stock_per_agent,
            row.uncontrolled_final_stock_per_agent,
            row.stock_gain_per_agent,
            row.coordinated_breaches_per_agent_round,
            row.uncontrolled_breaches_per_agent_round,
            row.breach_reduction_per_agent_round,
            row.coordinated_total_extraction_per_agent,
            row.uncontrolled_total_extraction_per_agent,
            row.interactions.published_messages,
            row.interactions.dispatched_tasks,
            row.interactions.mcp_tool_calls,
            row.interactions.agentskills_tool_calls,
        ));
    }
    fs::write(path, content).map_err(|err| format!("failed to write {}: {}", path.display(), err))
}

fn write_preference_placement_scaling_csv(
    path: &Path,
    rows: &[PreferencePlacementScalingPoint],
) -> Result<(), String> {
    let mut content = String::from(
        "placement_mode,topology,agent_count,rounds,complexity_multiplier,relative_disagreement,critical_path_ms,deadline_ms,deadline_slack_ms,tardiness_utility,queue_delay_ms\n",
    );
    for row in rows {
        content.push_str(&format!(
            "{},{},{},{},{:.2},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6}\n",
            row.placement_mode,
            row.topology,
            row.agent_count,
            row.rounds,
            row.complexity_multiplier,
            row.relative_disagreement,
            row.critical_path_ms,
            row.deadline_ms,
            row.deadline_slack_ms,
            row.tardiness_utility,
            row.queue_delay_ms,
        ));
    }
    fs::write(path, content).map_err(|err| format!("failed to write {}: {}", path.display(), err))
}

fn write_cascade_placement_scaling_csv(
    path: &Path,
    rows: &[CascadePlacementScalingPoint],
) -> Result<(), String> {
    let mut content = String::from(
        "placement_mode,stages,lead_time,complexity_multiplier,bullwhip_ratio,shock_cost_ratio,critical_path_ms,deadline_ms,deadline_slack_ms,tardiness_utility,queue_delay_ms\n",
    );
    for row in rows {
        content.push_str(&format!(
            "{},{},{},{:.2},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6}\n",
            row.placement_mode,
            row.stages,
            row.lead_time,
            row.complexity_multiplier,
            row.bullwhip_ratio,
            row.shock_cost_ratio,
            row.critical_path_ms,
            row.deadline_ms,
            row.deadline_slack_ms,
            row.tardiness_utility,
            row.queue_delay_ms,
        ));
    }
    fs::write(path, content).map_err(|err| format!("failed to write {}: {}", path.display(), err))
}

fn write_resource_placement_scaling_csv(
    path: &Path,
    rows: &[ResourcePlacementScalingPoint],
) -> Result<(), String> {
    let mut content = String::from(
        "placement_mode,agent_count,contention_multiplier,rounds,complexity_multiplier,stock_gain_per_agent,breach_reduction_per_agent_round,critical_path_ms,deadline_ms,deadline_slack_ms,tardiness_utility,queue_delay_ms\n",
    );
    for row in rows {
        content.push_str(&format!(
            "{},{},{:.2},{},{:.2},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6}\n",
            row.placement_mode,
            row.agent_count,
            row.contention_multiplier,
            row.rounds,
            row.complexity_multiplier,
            row.stock_gain_per_agent,
            row.breach_reduction_per_agent_round,
            row.critical_path_ms,
            row.deadline_ms,
            row.deadline_slack_ms,
            row.tardiness_utility,
            row.queue_delay_ms,
        ));
    }
    fs::write(path, content).map_err(|err| format!("failed to write {}: {}", path.display(), err))
}

fn render_summary_text(summary: &SuiteSummary) -> String {
    format!(
        concat!(
            "preference\n",
            "rounds: {}\n",
            "initial_disagreement_l2: {:.6}\n",
            "final_disagreement_l2: {:.6}\n",
            "average_score: {:.6}\n",
            "final_proposals: {:?}\n",
            "published_messages: {}\n",
            "dispatched_tasks: {}\n",
            "mcp_tool_calls: {}\n",
            "agentskills_tool_calls: {}\n\n",
            "cascade\n",
            "stages: {}\n",
            "lead_time: {}\n",
            "total_cost: {:.6}\n",
            "bullwhip_ratio: {:.6}\n",
            "upstream_order_variance: {:.6}\n",
            "published_messages: {}\n",
            "dispatched_tasks: {}\n",
            "mcp_tool_calls: {}\n",
            "agentskills_tool_calls: {}\n\n",
            "resource_coordinated\n",
            "rounds: {}\n",
            "final_stock: {:.6}\n",
            "total_extraction: {:.6}\n",
            "sustainability_breaches: {}\n",
            "published_messages: {}\n",
            "dispatched_tasks: {}\n",
            "mcp_tool_calls: {}\n",
            "agentskills_tool_calls: {}\n\n",
            "resource_uncontrolled\n",
            "rounds: {}\n",
            "final_stock: {:.6}\n",
            "total_extraction: {:.6}\n",
            "sustainability_breaches: {}\n\n",
            "resource_comparison\n",
            "final_stock_gain: {:.6}\n",
            "breach_reduction: {}\n"
        ),
        summary.preference.rounds,
        summary.preference.initial_disagreement_l2,
        summary.preference.final_disagreement_l2,
        summary.preference.average_score,
        summary.preference.final_proposals,
        summary.preference.interactions.published_messages,
        summary.preference.interactions.dispatched_tasks,
        summary.preference.interactions.mcp_tool_calls,
        summary.preference.interactions.agentskills_tool_calls,
        summary.cascade.stages,
        summary.cascade.lead_time,
        summary.cascade.total_cost,
        summary.cascade.bullwhip_ratio,
        summary.cascade.upstream_order_variance,
        summary.cascade.interactions.published_messages,
        summary.cascade.interactions.dispatched_tasks,
        summary.cascade.interactions.mcp_tool_calls,
        summary.cascade.interactions.agentskills_tool_calls,
        summary.resource.coordinated.rounds,
        summary.resource.coordinated.final_stock,
        summary.resource.coordinated.total_extraction,
        summary.resource.coordinated.sustainability_breaches,
        summary.resource.coordinated.interactions.as_ref().map(|i| i.published_messages).unwrap_or(0),
        summary.resource.coordinated.interactions.as_ref().map(|i| i.dispatched_tasks).unwrap_or(0),
        summary.resource.coordinated.interactions.as_ref().map(|i| i.mcp_tool_calls).unwrap_or(0),
        summary.resource.coordinated.interactions.as_ref().map(|i| i.agentskills_tool_calls).unwrap_or(0),
        summary.resource.uncontrolled.rounds,
        summary.resource.uncontrolled.final_stock,
        summary.resource.uncontrolled.total_extraction,
        summary.resource.uncontrolled.sustainability_breaches,
        summary.resource.final_stock_gain,
        summary.resource.breach_reduction,
    )
}

fn render_scaling_summary_text(summary: &ScalingSummary) -> String {
    let mut content = String::new();
    content.push_str("preference_scaling\n");
    for row in &summary.preference {
        content.push_str(&format!(
            "agents: {}, rounds: {}, disagreement: {:.6} -> {:.6}, relative: {:.6}\n",
            row.agent_count,
            row.rounds,
            row.initial_disagreement_l2,
            row.final_disagreement_l2,
            row.relative_disagreement,
        ));
    }

    content.push_str("\ncascade_scaling\n");
    for row in &summary.cascade {
        content.push_str(&format!(
            "agents: {}, total_cost: {:.6}, bullwhip_ratio: {:.6}, peak_upstream_order: {:.6}\n",
            row.agent_count,
            row.total_cost,
            row.bullwhip_ratio,
            row.peak_upstream_order,
        ));
    }

    content.push_str("\nresource_scaling\n");
    for row in &summary.resource {
        content.push_str(&format!(
            "agents: {}, coordinated_stock: {:.6}, uncontrolled_stock: {:.6}, stock_gain: {:.6}, breach_reduction: {}\n",
            row.agent_count,
            row.coordinated_final_stock,
            row.uncontrolled_final_stock,
            row.stock_gain,
            row.breach_reduction,
        ));
    }

    content
}

fn render_scaling_guidance_summary_text(summary: &ScalingGuidanceSummary) -> String {
    let mut content = String::new();
    content.push_str("preference_topology_scaling\n");
    for row in &summary.preference {
        content.push_str(&format!(
            "topology: {}, agents: {}, relative_disagreement: {:.6}, diameter: {}, rounds_to_half: {:?}\n",
            row.topology,
            row.agent_count,
            row.relative_disagreement,
            row.diameter,
            row.rounds_to_half_disagreement,
        ));
    }

    content.push_str("\ncascade_depth_delay_scaling\n");
    for row in &summary.cascade {
        content.push_str(&format!(
            "stages: {}, lead_time: {}, cost_per_stage: {:.6}, shock_cost_ratio: {:.6}, bullwhip_ratio: {:.6}\n",
            row.stages,
            row.lead_time,
            row.cost_per_stage,
            row.shock_cost_ratio,
            row.bullwhip_ratio,
        ));
    }

    content.push_str("\nresource_contention_scaling\n");
    for row in &summary.resource {
        content.push_str(&format!(
            "agents: {}, pressure: {:.2}, stock_gain_per_agent: {:.6}, breach_reduction_per_agent_round: {:.6}\n",
            row.agent_count,
            row.contention_multiplier,
            row.stock_gain_per_agent,
            row.breach_reduction_per_agent_round,
        ));
    }

    content
}

fn render_placement_summary_text(summary: &PlacementSummary) -> String {
    let mut content = String::new();
    content.push_str("preference_placement_scaling\n");
    for row in &summary.preference {
        content.push_str(&format!(
            "mode: {}, complexity: {:.2}, critical_path_ms: {:.6}, utility: {:.6}\n",
            row.placement_mode,
            row.complexity_multiplier,
            row.critical_path_ms,
            row.tardiness_utility,
        ));
    }

    content.push_str("\ncascade_placement_scaling\n");
    for row in &summary.cascade {
        content.push_str(&format!(
            "mode: {}, complexity: {:.2}, critical_path_ms: {:.6}, utility: {:.6}\n",
            row.placement_mode,
            row.complexity_multiplier,
            row.critical_path_ms,
            row.tardiness_utility,
        ));
    }

    content.push_str("\nresource_placement_scaling\n");
    for row in &summary.resource {
        content.push_str(&format!(
            "mode: {}, complexity: {:.2}, critical_path_ms: {:.6}, utility: {:.6}\n",
            row.placement_mode,
            row.complexity_multiplier,
            row.critical_path_ms,
            row.tardiness_utility,
        ));
    }

    content
}

fn render_slim_transport_summary_text(rows: &[TransportSweepRow]) -> String {
    render_transport_summary_text(rows)
}

fn run_scaling_suite() -> Result<ScalingSummary, String> {
    let preference_agent_counts = REGIME_AGENT_COUNTS;
    let cascade_agent_counts = REGIME_AGENT_COUNTS;
    let resource_agent_counts = REGIME_AGENT_COUNTS;

    let mut preference = Vec::with_capacity(preference_agent_counts.len());
    for agent_count in preference_agent_counts {
        let config = build_preference_scaling_config(agent_count);
        let execution = run_with_recording_adapters(|messaging, tasks, tools| {
            run_preference_experiment_with_adapters(&config, Some(messaging), Some(tasks), tools)
        })?;
        let initial = execution
            .report
            .disagreement_l2
            .first()
            .copied()
            .unwrap_or_default();
        let final_value = execution
            .report
            .disagreement_l2
            .last()
            .copied()
            .unwrap_or_default();
        preference.push(PreferenceScalingPoint {
            agent_count,
            rounds: config.rounds,
            initial_disagreement_l2: initial,
            final_disagreement_l2: final_value,
            relative_disagreement: if initial > 0.0 { final_value / initial } else { 0.0 },
            interactions: execution.interactions,
        });
    }

    let mut cascade = Vec::with_capacity(cascade_agent_counts.len());
    for agent_count in cascade_agent_counts {
        let config = build_cascade_scaling_config(agent_count);
        let execution = run_with_recording_adapters(|messaging, tasks, tools| {
            run_cascade_experiment_with_adapters(&config, Some(messaging), Some(tasks), tools)
        })?;
        let peak_upstream_order = execution
            .report
            .order_history
            .last()
            .and_then(|orders| orders.iter().copied().reduce(f64::max))
            .unwrap_or_default();
        cascade.push(CascadeScalingPoint {
            agent_count,
            lead_time: config.lead_time,
            total_cost: execution.report.total_cost,
            bullwhip_ratio: execution.report.bullwhip_ratio,
            upstream_order_variance: execution.report.upstream_order_variance,
            peak_upstream_order,
            interactions: execution.interactions,
        });
    }

    let mut resource = Vec::with_capacity(resource_agent_counts.len());
    for agent_count in resource_agent_counts {
        let coordinated_config = build_resource_scaling_config(agent_count, 0.35);
        let uncontrolled_config = build_resource_scaling_config(agent_count, 0.0);
        let coordinated = run_with_recording_adapters(|messaging, tasks, tools| {
            run_resource_experiment_with_adapters(
                &coordinated_config,
                Some(messaging),
                Some(tasks),
                tools,
            )
        })?;
        let uncontrolled = run_resource_experiment(&uncontrolled_config)?;
        resource.push(ResourceScalingPoint {
            agent_count,
            rounds: coordinated_config.rounds,
            coordinated_final_stock: coordinated.report.final_stock,
            uncontrolled_final_stock: uncontrolled.final_stock,
            stock_gain: coordinated.report.final_stock - uncontrolled.final_stock,
            coordinated_breaches: coordinated.report.sustainability_breaches,
            uncontrolled_breaches: uncontrolled.sustainability_breaches,
            breach_reduction: uncontrolled.sustainability_breaches as isize
                - coordinated.report.sustainability_breaches as isize,
            coordinated_total_extraction: coordinated.report.total_extraction,
            uncontrolled_total_extraction: uncontrolled.total_extraction,
            interactions: coordinated.interactions,
        });
    }

    Ok(ScalingSummary {
        preference,
        cascade,
        resource,
    })
}

fn run_scaling_guidance_suite() -> Result<ScalingGuidanceSummary, String> {
    Ok(ScalingGuidanceSummary {
        preference: run_preference_topology_scaling_suite()?,
        cascade: run_cascade_depth_delay_scaling_suite()?,
        resource: run_resource_contention_scaling_suite()?,
    })
}

fn run_placement_suite() -> Result<PlacementSummary, String> {
    Ok(PlacementSummary {
        preference: run_preference_placement_scaling_suite()?,
        cascade: run_cascade_placement_scaling_suite()?,
        resource: run_resource_placement_scaling_suite()?,
    })
}

fn run_preference_topology_scaling_suite() -> Result<Vec<PreferenceTopologyScalingPoint>, String> {
    let agent_counts = REGIME_AGENT_COUNTS;
    let rounds = 12usize;
    let mut rows = Vec::new();

    for agent_count in agent_counts {
        for topology in PreferenceTopology::all() {
            let adjacency = topology.build(agent_count);
            let config = PreferenceExperimentConfig {
                adjacency: adjacency.clone(),
                preferred_scores: evenly_spaced_preferences(agent_count),
                beta: 0.75,
                rounds,
                initial_proposals: None,
            };
            let execution = run_with_recording_adapters(|messaging, tasks, tools| {
                run_preference_experiment_with_adapters(&config, Some(messaging), Some(tasks), tools)
            })?;
            let initial = execution
                .report
                .disagreement_l2
                .first()
                .copied()
                .unwrap_or_default();
            let final_value = execution
                .report
                .disagreement_l2
                .last()
                .copied()
                .unwrap_or_default();
            let edge_count = undirected_edge_count(&adjacency);
            let directed_edge_count = adjacency.iter().map(|neighbors| neighbors.len()).sum::<usize>();
            let rounds_to_half_disagreement = first_round_at_or_below(
                &execution.report.disagreement_l2,
                initial * 0.5,
            );
            let neighbor_exchange_count = directed_edge_count * rounds;

            rows.push(PreferenceTopologyScalingPoint {
                topology: topology.label().to_string(),
                agent_count,
                rounds,
                edge_count,
                mean_degree: if agent_count > 0 {
                    directed_edge_count as f64 / agent_count as f64
                } else {
                    0.0
                },
                diameter: graph_diameter(&adjacency),
                initial_disagreement_l2: initial,
                final_disagreement_l2: final_value,
                relative_disagreement: if initial > 0.0 { final_value / initial } else { 0.0 },
                rounds_to_half_disagreement,
                neighbor_exchange_count,
                disagreement_reduction_per_exchange: if neighbor_exchange_count > 0 {
                    (initial - final_value) / neighbor_exchange_count as f64
                } else {
                    0.0
                },
                interactions: execution.interactions,
            });
        }
    }

    Ok(rows)
}

fn run_cascade_depth_delay_scaling_suite() -> Result<Vec<CascadeDepthDelayScalingPoint>, String> {
    let stage_counts = REGIME_AGENT_COUNTS;
    let lead_times = [1usize, 2, 4];
    let mut rows = Vec::new();

    for stages in stage_counts {
        for lead_time in lead_times {
            let config = build_cascade_depth_delay_config(stages, lead_time, true);
            let no_shock_config = build_cascade_depth_delay_config(stages, lead_time, false);
            let execution = run_with_recording_adapters(|messaging, tasks, tools| {
                run_cascade_experiment_with_adapters(&config, Some(messaging), Some(tasks), tools)
            })?;
            let no_shock = run_cascade_experiment(&no_shock_config)?;
            let peak_upstream_order = execution
                .report
                .order_history
                .last()
                .and_then(|orders| orders.iter().copied().reduce(f64::max))
                .unwrap_or_default();

            rows.push(CascadeDepthDelayScalingPoint {
                stages,
                lead_time,
                critical_path_hops: stages * lead_time,
                total_cost: execution.report.total_cost,
                cost_per_stage: execution.report.total_cost / stages as f64,
                no_shock_total_cost: no_shock.total_cost,
                shock_cost_ratio: if no_shock.total_cost > 0.0 {
                    execution.report.total_cost / no_shock.total_cost
                } else {
                    0.0
                },
                bullwhip_ratio: execution.report.bullwhip_ratio,
                bullwhip_per_stage: execution.report.bullwhip_ratio / stages as f64,
                peak_upstream_order,
                interactions: execution.interactions,
            });
        }
    }

    Ok(rows)
}

fn run_resource_contention_scaling_suite() -> Result<Vec<ResourceContentionScalingPoint>, String> {
    let agent_counts = REGIME_AGENT_COUNTS;
    let contention_multipliers = [0.75f64, 1.0, 1.25, 1.5];
    let mut rows = Vec::new();

    for agent_count in agent_counts {
        for contention_multiplier in contention_multipliers {
            let coordinated_config =
                build_resource_contention_config(agent_count, contention_multiplier, 0.35);
            let uncontrolled_config =
                build_resource_contention_config(agent_count, contention_multiplier, 0.0);
            let coordinated = run_with_recording_adapters(|messaging, tasks, tools| {
                run_resource_experiment_with_adapters(
                    &coordinated_config,
                    Some(messaging),
                    Some(tasks),
                    tools,
                )
            })?;
            let uncontrolled = run_resource_experiment(&uncontrolled_config)?;
            let agent_count_f64 = agent_count as f64;
            let round_denominator = (agent_count * coordinated_config.rounds) as f64;

            rows.push(ResourceContentionScalingPoint {
                agent_count,
                contention_multiplier,
                rounds: coordinated_config.rounds,
                coordinated_final_stock_per_agent: coordinated.report.final_stock / agent_count_f64,
                uncontrolled_final_stock_per_agent: uncontrolled.final_stock / agent_count_f64,
                stock_gain_per_agent: (coordinated.report.final_stock - uncontrolled.final_stock)
                    / agent_count_f64,
                coordinated_breaches_per_agent_round:
                    coordinated.report.sustainability_breaches as f64 / round_denominator,
                uncontrolled_breaches_per_agent_round:
                    uncontrolled.sustainability_breaches as f64 / round_denominator,
                breach_reduction_per_agent_round: (uncontrolled.sustainability_breaches as f64
                    - coordinated.report.sustainability_breaches as f64)
                    / round_denominator,
                coordinated_total_extraction_per_agent:
                    coordinated.report.total_extraction / agent_count_f64,
                uncontrolled_total_extraction_per_agent:
                    uncontrolled.total_extraction / agent_count_f64,
                interactions: coordinated.interactions,
            });
        }
    }

    Ok(rows)
}

fn run_preference_placement_scaling_suite() -> Result<Vec<PreferencePlacementScalingPoint>, String> {
    let topology = PreferenceTopology::Ring;
    let agent_count = 17usize;
    let rounds = 12usize;
    let adjacency = topology.build(agent_count);
    let config = PreferenceExperimentConfig {
        adjacency,
        preferred_scores: evenly_spaced_preferences(agent_count),
        beta: 0.75,
        rounds,
        initial_proposals: None,
    };
    let execution = run_with_recording_adapters(|messaging, tasks, tools| {
        run_preference_experiment_with_adapters(&config, Some(messaging), Some(tasks), tools)
    })?;
    let initial = execution
        .report
        .disagreement_l2
        .first()
        .copied()
        .unwrap_or_default();
    let final_value = execution
        .report
        .disagreement_l2
        .last()
        .copied()
        .unwrap_or_default();
    let relative_disagreement = if initial > 0.0 { final_value / initial } else { 0.0 };
    let scenario = PlacementScenario {
        coordination_ms_per_step: 8.0,
        local_service_ms: 5.0,
        delegated_service_ms: 3.0,
        specialist_service_ms: 1.2,
        remote_rtt_ms: 5.5,
        pool_workers: 8,
        concurrent_requests: agent_count,
        critical_path_steps: rounds,
        deadline_ms: 300.0,
        drop_dead_ms: 420.0,
        tardiness_alpha: 0.6,
        drop_penalty: 20.0,
        base_value: 100.0,
    };

    let mut rows = Vec::new();
    for complexity_multiplier in placement_complexity_multipliers() {
        for mode in PlacementMode::all() {
            let outcome = evaluate_placement(mode, &scenario, complexity_multiplier);
            rows.push(PreferencePlacementScalingPoint {
                placement_mode: mode.label().to_string(),
                topology: topology.label().to_string(),
                agent_count,
                rounds,
                complexity_multiplier,
                relative_disagreement,
                critical_path_ms: outcome.critical_path_ms,
                deadline_ms: scenario.deadline_ms,
                deadline_slack_ms: outcome.deadline_slack_ms,
                tardiness_utility: outcome.tardiness_utility,
                queue_delay_ms: outcome.queue_delay_ms,
            });
        }
    }

    Ok(rows)
}

fn run_cascade_placement_scaling_suite() -> Result<Vec<CascadePlacementScalingPoint>, String> {
    let stages = 8usize;
    let lead_time = 2usize;
    let config = build_cascade_depth_delay_config(stages, lead_time, true);
    let no_shock_config = build_cascade_depth_delay_config(stages, lead_time, false);
    let execution = run_with_recording_adapters(|messaging, tasks, tools| {
        run_cascade_experiment_with_adapters(&config, Some(messaging), Some(tasks), tools)
    })?;
    let no_shock = run_cascade_experiment(&no_shock_config)?;
    let shock_cost_ratio = if no_shock.total_cost > 0.0 {
        execution.report.total_cost / no_shock.total_cost
    } else {
        0.0
    };
    let scenario = PlacementScenario {
        coordination_ms_per_step: 7.0,
        local_service_ms: 7.0,
        delegated_service_ms: 4.0,
        specialist_service_ms: 2.5,
        remote_rtt_ms: 5.5,
        pool_workers: 3,
        concurrent_requests: stages,
        critical_path_steps: stages,
        deadline_ms: 180.0,
        drop_dead_ms: 250.0,
        tardiness_alpha: 1.0,
        drop_penalty: 35.0,
        base_value: 100.0,
    };

    let mut rows = Vec::new();
    for complexity_multiplier in placement_complexity_multipliers() {
        for mode in PlacementMode::all() {
            let outcome = evaluate_placement(mode, &scenario, complexity_multiplier);
            rows.push(CascadePlacementScalingPoint {
                placement_mode: mode.label().to_string(),
                stages,
                lead_time,
                complexity_multiplier,
                bullwhip_ratio: execution.report.bullwhip_ratio,
                shock_cost_ratio,
                critical_path_ms: outcome.critical_path_ms,
                deadline_ms: scenario.deadline_ms,
                deadline_slack_ms: outcome.deadline_slack_ms,
                tardiness_utility: outcome.tardiness_utility,
                queue_delay_ms: outcome.queue_delay_ms,
            });
        }
    }

    Ok(rows)
}

fn run_resource_placement_scaling_suite() -> Result<Vec<ResourcePlacementScalingPoint>, String> {
    let agent_count = 17usize;
    let contention_multiplier = 1.25f64;
    let coordinated_config = build_resource_contention_config(agent_count, contention_multiplier, 0.35);
    let uncontrolled_config = build_resource_contention_config(agent_count, contention_multiplier, 0.0);
    let coordinated = run_with_recording_adapters(|messaging, tasks, tools| {
        run_resource_experiment_with_adapters(&coordinated_config, Some(messaging), Some(tasks), tools)
    })?;
    let uncontrolled = run_resource_experiment(&uncontrolled_config)?;
    let round_denominator = (agent_count * coordinated_config.rounds) as f64;
    let stock_gain_per_agent =
        (coordinated.report.final_stock - uncontrolled.final_stock) / agent_count as f64;
    let breach_reduction_per_agent_round =
        (uncontrolled.sustainability_breaches as f64 - coordinated.report.sustainability_breaches as f64)
            / round_denominator;
    let scenario = PlacementScenario {
        coordination_ms_per_step: 6.0,
        local_service_ms: 5.5,
        delegated_service_ms: 3.2,
        specialist_service_ms: 1.4,
        remote_rtt_ms: 5.0,
        pool_workers: 10,
        concurrent_requests: agent_count,
        critical_path_steps: coordinated_config.rounds,
        deadline_ms: 250.0,
        drop_dead_ms: 320.0,
        tardiness_alpha: 0.6,
        drop_penalty: 20.0,
        base_value: 100.0,
    };

    let mut rows = Vec::new();
    for complexity_multiplier in placement_complexity_multipliers() {
        for mode in PlacementMode::all() {
            let outcome = evaluate_placement(mode, &scenario, complexity_multiplier);
            rows.push(ResourcePlacementScalingPoint {
                placement_mode: mode.label().to_string(),
                agent_count,
                contention_multiplier,
                rounds: coordinated_config.rounds,
                complexity_multiplier,
                stock_gain_per_agent,
                breach_reduction_per_agent_round,
                critical_path_ms: outcome.critical_path_ms,
                deadline_ms: scenario.deadline_ms,
                deadline_slack_ms: outcome.deadline_slack_ms,
                tardiness_utility: outcome.tardiness_utility,
                queue_delay_ms: outcome.queue_delay_ms,
            });
        }
    }

    Ok(rows)
}

fn build_preference_scaling_config(agent_count: usize) -> PreferenceExperimentConfig {
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
        rounds: agent_count * 2,
        initial_proposals: None,
    }
}

fn build_cascade_scaling_config(agent_count: usize) -> CascadeExperimentConfig {
    let mut customer_demand = vec![4.0; 3];
    customer_demand.extend([8.0; 3]);
    customer_demand.extend([4.0; 6]);

    CascadeExperimentConfig {
        stages: agent_count,
        lead_time: 2,
        customer_demand,
        initial_inventory: 8.0,
        target_inventory: 8.0,
        holding_cost: 1.0,
        backlog_cost: 2.0,
        adjustment_penalty: 0.25,
    }
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

fn build_cascade_depth_delay_config(
    stages: usize,
    lead_time: usize,
    include_shock: bool,
) -> CascadeExperimentConfig {
    let mut customer_demand = vec![4.0; 3];
    if include_shock {
        customer_demand.extend([8.0; 3]);
    } else {
        customer_demand.extend([4.0; 3]);
    }
    customer_demand.extend(vec![4.0; 3 * lead_time.max(2)]);

    CascadeExperimentConfig {
        stages,
        lead_time,
        customer_demand,
        initial_inventory: 8.0,
        target_inventory: 8.0,
        holding_cost: 1.0,
        backlog_cost: 2.0,
        adjustment_penalty: 0.25,
    }
}

fn build_resource_contention_config(
    agent_count: usize,
    contention_multiplier: f64,
    alpha: f64,
) -> ResourceExperimentConfig {
    let desired_extraction = (0..agent_count)
        .map(|index| {
            let baseline = match index % 3 {
                1 => 2.5,
                _ => 2.0,
            };
            baseline * contention_multiplier
        })
        .collect();

    ResourceExperimentConfig {
        desired_extraction,
        max_extraction: vec![3.0; agent_count],
        rounds: 16,
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

fn placement_complexity_multipliers() -> [f64; 4] {
    [1.0, 2.0, 4.0, 8.0]
}

fn evenly_spaced_preferences(agent_count: usize) -> Vec<f64> {
    if agent_count <= 1 {
        return vec![4.0; agent_count];
    }

    (0..agent_count)
        .map(|index| 8.0 * index as f64 / (agent_count - 1) as f64)
        .collect()
}

fn first_round_at_or_below(values: &[f64], threshold: f64) -> Option<usize> {
    values.iter().position(|value| *value <= threshold)
}

fn undirected_edge_count(adjacency: &[Vec<usize>]) -> usize {
    adjacency.iter().map(|neighbors| neighbors.len()).sum::<usize>() / 2
}

fn graph_diameter(adjacency: &[Vec<usize>]) -> usize {
    if adjacency.is_empty() {
        return 0;
    }

    let mut diameter = 0usize;
    for start in 0..adjacency.len() {
        let mut distance = vec![usize::MAX; adjacency.len()];
        let mut queue = VecDeque::new();
        distance[start] = 0;
        queue.push_back(start);

        while let Some(node) = queue.pop_front() {
            let next_distance = distance[node] + 1;
            for &neighbor in &adjacency[node] {
                if distance[neighbor] == usize::MAX {
                    distance[neighbor] = next_distance;
                    queue.push_back(neighbor);
                }
            }
        }

        if let Some(max_distance) = distance.iter().copied().filter(|value| *value != usize::MAX).max() {
            diameter = diameter.max(max_distance);
        }
    }

    diameter
}

fn add_undirected_edge(adjacency: &mut [Vec<usize>], left: usize, right: usize) {
    if left == right {
        return;
    }
    adjacency[left].push(right);
    adjacency[right].push(left);
}

#[derive(Copy, Clone)]
enum PlacementMode {
    LocalOnly,
    Delegated,
    SpecialistPool,
}

impl PlacementMode {
    fn all() -> [Self; 3] {
        [Self::LocalOnly, Self::Delegated, Self::SpecialistPool]
    }

    fn label(self) -> &'static str {
        match self {
            Self::LocalOnly => "local_only",
            Self::Delegated => "delegated",
            Self::SpecialistPool => "specialist_pool",
        }
    }
}

struct PlacementScenario {
    coordination_ms_per_step: f64,
    local_service_ms: f64,
    delegated_service_ms: f64,
    specialist_service_ms: f64,
    remote_rtt_ms: f64,
    pool_workers: usize,
    concurrent_requests: usize,
    critical_path_steps: usize,
    deadline_ms: f64,
    drop_dead_ms: f64,
    tardiness_alpha: f64,
    drop_penalty: f64,
    base_value: f64,
}

struct PlacementOutcome {
    critical_path_ms: f64,
    deadline_slack_ms: f64,
    tardiness_utility: f64,
    queue_delay_ms: f64,
}

fn evaluate_placement(
    mode: PlacementMode,
    scenario: &PlacementScenario,
    complexity_multiplier: f64,
) -> PlacementOutcome {
    let (service_ms, remote_rtt_ms) = match mode {
        PlacementMode::LocalOnly => (scenario.local_service_ms, 0.0),
        PlacementMode::Delegated => (scenario.delegated_service_ms, scenario.remote_rtt_ms),
        PlacementMode::SpecialistPool => (scenario.specialist_service_ms, scenario.remote_rtt_ms),
    };
    let queue_pressure = if matches!(mode, PlacementMode::SpecialistPool) && scenario.pool_workers > 0 {
        ((scenario.concurrent_requests as f64 / scenario.pool_workers as f64) - 1.0).max(0.0)
    } else {
        0.0
    };
    let queue_delay_ms = scenario.critical_path_steps as f64
        * service_ms
        * complexity_multiplier
        * queue_pressure
        * 0.5;
    let critical_path_ms = scenario.critical_path_steps as f64
        * (scenario.coordination_ms_per_step + service_ms * complexity_multiplier + remote_rtt_ms)
        + queue_delay_ms;
    let deadline_slack_ms = scenario.deadline_ms - critical_path_ms;
    let tardiness_ms = (-deadline_slack_ms).max(0.0);
    let mut tardiness_utility = scenario.base_value - scenario.tardiness_alpha * tardiness_ms;
    if critical_path_ms > scenario.drop_dead_ms {
        tardiness_utility -= scenario.drop_penalty;
    }

    PlacementOutcome {
        critical_path_ms,
        deadline_slack_ms,
        tardiness_utility,
        queue_delay_ms,
    }
}

#[derive(Copy, Clone)]
enum PreferenceTopology {
    Line,
    Ring,
    Star,
    Hierarchical,
    Complete,
}

impl PreferenceTopology {
    fn all() -> [Self; 5] {
        [Self::Line, Self::Ring, Self::Star, Self::Hierarchical, Self::Complete]
    }

    fn label(self) -> &'static str {
        match self {
            Self::Line => "line",
            Self::Ring => "ring",
            Self::Star => "star",
            Self::Hierarchical => "hierarchical",
            Self::Complete => "complete",
        }
    }

    fn build(self, agent_count: usize) -> Vec<Vec<usize>> {
        let mut adjacency = vec![Vec::new(); agent_count];
        match self {
            Self::Line => {
                for index in 1..agent_count {
                    add_undirected_edge(&mut adjacency, index - 1, index);
                }
            }
            Self::Ring => {
                for index in 1..agent_count {
                    add_undirected_edge(&mut adjacency, index - 1, index);
                }
                if agent_count > 2 {
                    add_undirected_edge(&mut adjacency, 0, agent_count - 1);
                }
            }
            Self::Star => {
                for index in 1..agent_count {
                    add_undirected_edge(&mut adjacency, 0, index);
                }
            }
            Self::Hierarchical => {
                let group_size = 4usize;
                let mut hubs = Vec::new();
                let mut group_start = 0usize;
                while group_start < agent_count {
                    let hub = group_start;
                    hubs.push(hub);
                    let group_end = (group_start + group_size).min(agent_count);
                    for node in (group_start + 1)..group_end {
                        add_undirected_edge(&mut adjacency, hub, node);
                    }
                    group_start = group_end;
                }
                for index in 1..hubs.len() {
                    add_undirected_edge(&mut adjacency, hubs[index - 1], hubs[index]);
                }
            }
            Self::Complete => {
                for left in 0..agent_count {
                    for right in (left + 1)..agent_count {
                        add_undirected_edge(&mut adjacency, left, right);
                    }
                }
            }
        }

        adjacency
    }
}

#[derive(Serialize)]
struct SuiteSummary {
    preference: PreferenceSummary,
    cascade: CascadeSummary,
    resource: ResourceComparisonSummary,
}

#[derive(Serialize)]
struct PreferenceSummary {
    rounds: usize,
    initial_disagreement_l2: f64,
    final_disagreement_l2: f64,
    average_score: f64,
    final_proposals: Vec<f64>,
    interactions: ExperimentInteractionSummary,
}

#[derive(Serialize)]
struct CascadeSummary {
    stages: usize,
    lead_time: usize,
    total_cost: f64,
    bullwhip_ratio: f64,
    upstream_order_variance: f64,
    interactions: ExperimentInteractionSummary,
}

#[derive(Serialize)]
struct ResourceComparisonSummary {
    coordinated: ResourceSummary,
    uncontrolled: ResourceSummary,
    final_stock_gain: f64,
    breach_reduction: isize,
}

#[derive(Serialize)]
struct ResourceSummary {
    rounds: usize,
    final_stock: f64,
    total_extraction: f64,
    sustainability_breaches: usize,
    interactions: Option<ExperimentInteractionSummary>,
}

#[derive(Serialize)]
struct ScalingSummary {
    preference: Vec<PreferenceScalingPoint>,
    cascade: Vec<CascadeScalingPoint>,
    resource: Vec<ResourceScalingPoint>,
}

#[derive(Serialize)]
struct ScalingGuidanceSummary {
    preference: Vec<PreferenceTopologyScalingPoint>,
    cascade: Vec<CascadeDepthDelayScalingPoint>,
    resource: Vec<ResourceContentionScalingPoint>,
}

#[derive(Serialize)]
struct PlacementSummary {
    preference: Vec<PreferencePlacementScalingPoint>,
    cascade: Vec<CascadePlacementScalingPoint>,
    resource: Vec<ResourcePlacementScalingPoint>,
}

#[derive(Serialize)]
struct PreferenceScalingPoint {
    agent_count: usize,
    rounds: usize,
    initial_disagreement_l2: f64,
    final_disagreement_l2: f64,
    relative_disagreement: f64,
    interactions: ExperimentInteractionSummary,
}

#[derive(Serialize)]
struct CascadeScalingPoint {
    agent_count: usize,
    lead_time: usize,
    total_cost: f64,
    bullwhip_ratio: f64,
    upstream_order_variance: f64,
    peak_upstream_order: f64,
    interactions: ExperimentInteractionSummary,
}

#[derive(Serialize)]
struct ResourceScalingPoint {
    agent_count: usize,
    rounds: usize,
    coordinated_final_stock: f64,
    uncontrolled_final_stock: f64,
    stock_gain: f64,
    coordinated_breaches: usize,
    uncontrolled_breaches: usize,
    breach_reduction: isize,
    coordinated_total_extraction: f64,
    uncontrolled_total_extraction: f64,
    interactions: ExperimentInteractionSummary,
}

#[derive(Serialize)]
struct PreferenceTopologyScalingPoint {
    topology: String,
    agent_count: usize,
    rounds: usize,
    edge_count: usize,
    mean_degree: f64,
    diameter: usize,
    initial_disagreement_l2: f64,
    final_disagreement_l2: f64,
    relative_disagreement: f64,
    rounds_to_half_disagreement: Option<usize>,
    neighbor_exchange_count: usize,
    disagreement_reduction_per_exchange: f64,
    interactions: ExperimentInteractionSummary,
}

#[derive(Serialize)]
struct CascadeDepthDelayScalingPoint {
    stages: usize,
    lead_time: usize,
    critical_path_hops: usize,
    total_cost: f64,
    cost_per_stage: f64,
    no_shock_total_cost: f64,
    shock_cost_ratio: f64,
    bullwhip_ratio: f64,
    bullwhip_per_stage: f64,
    peak_upstream_order: f64,
    interactions: ExperimentInteractionSummary,
}

#[derive(Serialize)]
struct ResourceContentionScalingPoint {
    agent_count: usize,
    contention_multiplier: f64,
    rounds: usize,
    coordinated_final_stock_per_agent: f64,
    uncontrolled_final_stock_per_agent: f64,
    stock_gain_per_agent: f64,
    coordinated_breaches_per_agent_round: f64,
    uncontrolled_breaches_per_agent_round: f64,
    breach_reduction_per_agent_round: f64,
    coordinated_total_extraction_per_agent: f64,
    uncontrolled_total_extraction_per_agent: f64,
    interactions: ExperimentInteractionSummary,
}

#[derive(Serialize)]
struct PreferencePlacementScalingPoint {
    placement_mode: String,
    topology: String,
    agent_count: usize,
    rounds: usize,
    complexity_multiplier: f64,
    relative_disagreement: f64,
    critical_path_ms: f64,
    deadline_ms: f64,
    deadline_slack_ms: f64,
    tardiness_utility: f64,
    queue_delay_ms: f64,
}

#[derive(Serialize)]
struct CascadePlacementScalingPoint {
    placement_mode: String,
    stages: usize,
    lead_time: usize,
    complexity_multiplier: f64,
    bullwhip_ratio: f64,
    shock_cost_ratio: f64,
    critical_path_ms: f64,
    deadline_ms: f64,
    deadline_slack_ms: f64,
    tardiness_utility: f64,
    queue_delay_ms: f64,
}

#[derive(Serialize)]
struct ResourcePlacementScalingPoint {
    placement_mode: String,
    agent_count: usize,
    contention_multiplier: f64,
    rounds: usize,
    complexity_multiplier: f64,
    stock_gain_per_agent: f64,
    breach_reduction_per_agent_round: f64,
    critical_path_ms: f64,
    deadline_ms: f64,
    deadline_slack_ms: f64,
    tardiness_utility: f64,
    queue_delay_ms: f64,
}