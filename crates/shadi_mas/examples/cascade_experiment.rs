#[path = "common/mod.rs"]
mod common;

use common::{parse_output_format, print_interaction_summary, print_trace_csv, OutputFormat};
use shadi_mas::experiments::{
    calibrated_live_cascade_config, run_cascade_experiment_with_adapters,
    RecordingMessagingAdapter, RecordingTaskAdapter, RecordingToolAdapter,
};
use shadi_mas::{ToolAdapter, ToolProvider};

fn main() -> Result<(), String> {
    let format = parse_output_format()?;
    let config = calibrated_live_cascade_config(4)?;
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
    )?;

    match format {
        OutputFormat::Summary => {
            println!("cascade_experiment");
            println!("stages: {}", config.stages);
            println!("lead_time: {}", config.lead_time);
            println!("total_cost: {:.6}", execution.report.total_cost);
            println!("bullwhip_ratio: {:.6}", execution.report.bullwhip_ratio);
            println!(
                "upstream_order_variance: {:.6}",
                execution.report.upstream_order_variance
            );
            print_interaction_summary(&execution.interactions);
        }
        OutputFormat::Csv => {
            println!("round,stage,inventory,order");
            for round in 0..config.customer_demand.len() {
                for stage in 0..config.stages {
                    println!(
                        "{round},{stage},{:.6},{:.6}",
                        execution.report.inventory_history[stage][round],
                        execution.report.order_history[stage][round]
                    );
                }
            }
            print_trace_csv(&execution.trace);
        }
    }

    Ok(())
}