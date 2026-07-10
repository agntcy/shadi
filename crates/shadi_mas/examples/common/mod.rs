use shadi_mas::experiments::{ExperimentInteractionSummary, InteractionTraceEvent};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Summary,
    Csv,
}

pub fn parse_output_format() -> Result<OutputFormat, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => Ok(OutputFormat::Summary),
        [value] => parse_value(value),
        [flag, value] if flag == "--format" => parse_value(value),
        _ => Err("usage: [--format summary|csv]".to_string()),
    }
}

#[allow(dead_code)]
pub fn print_interaction_summary(summary: &ExperimentInteractionSummary) {
    println!("published_messages: {}", summary.published_messages);
    println!("dispatched_tasks: {}", summary.dispatched_tasks);
    println!("mcp_tool_calls: {}", summary.mcp_tool_calls);
    println!("agentskills_tool_calls: {}", summary.agentskills_tool_calls);
}

#[allow(dead_code)]
pub fn print_trace_csv(trace: &[InteractionTraceEvent]) {
    println!("{}", InteractionTraceEvent::csv_header());
    for event in trace {
        println!("{}", event.to_csv_row());
    }
}

fn parse_value(value: &str) -> Result<OutputFormat, String> {
    match value {
        "summary" => Ok(OutputFormat::Summary),
        "csv" => Ok(OutputFormat::Csv),
        other => Err(format!("unknown output format: {}", other)),
    }
}