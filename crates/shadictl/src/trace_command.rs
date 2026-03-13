use super::*;

pub(crate) fn run_trace_command(cli: TraceCli) -> ExitCode {
    let path = resolve_trace_file(cli.file);
    match &cli.command {
        TraceCommand::List {
            limit,
            name,
            command,
            exit_code,
        } => match trace_list(&path, *limit, name.as_deref(), command.as_deref(), *exit_code) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("{}", err);
                ExitCode::from(1)
            }
        },
        TraceCommand::Summary { limit } => match trace_summary(&path, *limit) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("{}", err);
                ExitCode::from(1)
            }
        },
    }
}

pub(crate) fn resolve_trace_file(cli_path: Option<PathBuf>) -> PathBuf {
    if let Some(path) = cli_path {
        return path;
    }
    if let Ok(path) = std::env::var("SHADI_OTEL_FILE") {
        if !path.trim().is_empty() {
            return PathBuf::from(path);
        }
    }
    PathBuf::from(".shadi/traces.jsonl")
}

pub(crate) fn trace_list(
    path: &Path,
    limit: usize,
    name: Option<&str>,
    command: Option<&str>,
    exit_code: Option<i32>,
) -> Result<(), String> {
    let lines = read_trace_lines(path, limit)?;
    for line in lines {
        if let Some(value) = parse_trace_line(&line) {
            if !trace_matches(&value, name, command, exit_code) {
                continue;
            }
        }
        println!("{}", line);
    }
    Ok(())
}

pub(crate) fn trace_summary(path: &Path, limit: usize) -> Result<(), String> {
    let lines = read_trace_lines(path, limit)?;
    let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for line in lines {
        if let Some(value) = parse_trace_line(&line) {
            if let Some(name) = trace_span_name(&value) {
                *counts.entry(name).or_insert(0) += 1;
            }
        }
    }

    for (name, count) in counts {
        println!("{}\t{}", count, name);
    }
    Ok(())
}

pub(crate) fn read_trace_lines(path: &Path, limit: usize) -> Result<Vec<String>, String> {
    let file = std::fs::File::open(path)
        .map_err(|err| format!("failed to open trace file {}: {}", path.display(), err))?;
    let reader = std::io::BufReader::new(file);
    let mut lines: std::collections::VecDeque<String> = std::collections::VecDeque::new();
    for line in reader.lines() {
        let line = line.map_err(|err| format!("failed to read trace file: {}", err))?;
        if limit == 0 {
            continue;
        }
        lines.push_back(line);
        if lines.len() > limit {
            lines.pop_front();
        }
    }
    Ok(lines.into_iter().collect())
}

pub(crate) fn parse_trace_line(line: &str) -> Option<serde_json::Value> {
    serde_json::from_str(line).ok()
}

pub(crate) fn trace_span_name(value: &serde_json::Value) -> Option<String> {
    if let Some(name) = value
        .get("span")
        .and_then(|span| span.get("name"))
        .and_then(|name| name.as_str())
    {
        return Some(name.to_string());
    }

    if let Some(spans) = value.get("spans").and_then(|spans| spans.as_array()) {
        if let Some(name) = spans
            .iter()
            .filter_map(|span| span.get("name"))
            .filter_map(|name| name.as_str())
            .next()
        {
            return Some(name.to_string());
        }
    }

    None
}

pub(crate) fn trace_matches(
    value: &serde_json::Value,
    name: Option<&str>,
    command: Option<&str>,
    exit_code: Option<i32>,
) -> bool {
    if let Some(expected) = name {
        if trace_span_name(value)
            .as_deref()
            .map(|value| !value.contains(expected))
            .unwrap_or(true)
        {
            return false;
        }
    }

    if let Some(expected) = command {
        let found = value
            .get("fields")
            .and_then(|fields| fields.get("command"))
            .and_then(|value| value.as_str())
            .map(|value| value.contains(expected))
            .unwrap_or(false);
        if !found {
            return false;
        }
    }

    if let Some(expected) = exit_code {
        let found = value
            .get("fields")
            .and_then(|fields| fields.get("exit.code"))
            .and_then(|value| value.as_i64())
            .map(|value| value == expected as i64)
            .unwrap_or(false);
        if !found {
            return false;
        }
    }

    true
}
