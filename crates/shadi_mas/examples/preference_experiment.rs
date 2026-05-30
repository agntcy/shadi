#[path = "common/mod.rs"]
mod common;

use common::{parse_output_format, print_interaction_summary, print_trace_csv, OutputFormat};
use shadi_mas::experiments::{
    calibrated_live_preference_config, run_preference_experiment_with_adapters,
    RecordingMessagingAdapter, RecordingTaskAdapter, RecordingToolAdapter,
};
use shadi_mas::{ToolAdapter, ToolProvider};

fn main() -> Result<(), String> {
    let format = parse_output_format()?;
    let config = calibrated_live_preference_config(3)?;
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
    )?;

    match format {
        OutputFormat::Summary => {
            println!("preference_experiment");
            println!("rounds: {}", config.rounds);
            println!(
                "initial_disagreement_l2: {:.6}",
                execution.report.disagreement_l2.first().copied().unwrap_or_default()
            );
            println!(
                "final_disagreement_l2: {:.6}",
                execution.report.disagreement_l2.last().copied().unwrap_or_default()
            );
            println!("average_score: {:.6}", execution.report.average_score);
            println!("final_proposals: {:?}", execution.report.final_proposals);
            print_interaction_summary(&execution.interactions);
        }
        OutputFormat::Csv => {
            println!("round,node,proposal,disagreement_l2");
            for (round, proposals) in execution.report.trajectory.iter().enumerate() {
                let disagreement = execution.report.disagreement_l2[round];
                for (node, proposal) in proposals.iter().enumerate() {
                    println!("{round},{node},{proposal:.6},{disagreement:.6}");
                }
            }
            print_trace_csv(&execution.trace);
        }
    }

    Ok(())
}