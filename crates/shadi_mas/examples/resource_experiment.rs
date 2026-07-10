#[path = "common/mod.rs"]
mod common;

use common::{parse_output_format, print_interaction_summary, print_trace_csv, OutputFormat};
use shadi_mas::experiments::{
    run_resource_experiment_with_adapters, RecordingMessagingAdapter, RecordingTaskAdapter,
    RecordingToolAdapter, ResourceExperimentConfig,
};
use shadi_mas::{ToolAdapter, ToolProvider};

fn main() -> Result<(), String> {
    let format = parse_output_format()?;
    let config = ResourceExperimentConfig {
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
    )?;

    match format {
        OutputFormat::Summary => {
            println!("resource_experiment");
            println!("rounds: {}", config.rounds);
            println!("final_stock: {:.6}", execution.report.final_stock);
            println!("total_extraction: {:.6}", execution.report.total_extraction);
            println!(
                "sustainability_breaches: {}",
                execution.report.sustainability_breaches
            );
            print_interaction_summary(&execution.interactions);
        }
        OutputFormat::Csv => {
            println!("round,agent,extraction,stock,lambda");
            for round in 0..config.rounds {
                let stock = execution.report.stock_history[round + 1];
                let lambda = execution.report.lambda_history[round + 1];
                for agent in 0..config.desired_extraction.len() {
                    let extraction = execution.report.extraction_history[round][agent];
                    println!("{round},{agent},{extraction:.6},{stock:.6},{lambda:.6}");
                }
            }
            print_trace_csv(&execution.trace);
        }
    }

    Ok(())
}