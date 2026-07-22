use shadi_mas::{
    Epoch, PatternKind, TaskAdapter, TaskEnvelope,
    experiments::{LiveA2ATaskAdapter, LiveA2ATaskAdapterConfig},
};

/// Delegate a single task to a remote agentbridge adapter over A2A/SLIM.
///
/// The adapter must be registered and listening on the SLIM node. Use
/// `agentbridge register --tool <name>` in a separate terminal first.
/// Coding-agent adapters authenticate via DID/keys only (`SHADI_SLIM_AUTH=did`,
/// `SLIM_HUMAN_SEED`, `SLIM_MEMBER_DIDS`) — shared secrets are not supported.
///
/// Environment variables used (same as `agentbridge register`):
///   SLIM_ENDPOINT, SLIM_TLS_CERT, SLIM_TLS_KEY, SLIM_TLS_CA
pub fn run(
    prompt: &str,
    to_agent_id: &str,
    local_agent_id: &str,
    endpoint: &str,
) -> anyhow::Result<()> {
    // Wire the SLIM endpoint env var that LiveA2ATaskAdapter reads internally.
    std::env::set_var("SLIM_ENDPOINT", endpoint);

    let config = LiveA2ATaskAdapterConfig {
        endpoint: endpoint.to_string(),
        agent_id: local_agent_id.to_string(),
        local_name: Some(format!("agntcy/shadi/{local_agent_id}-a2a")),
        peer_agent_id: to_agent_id.to_string(),
        destination: Some(format!("agntcy/shadi/{to_agent_id}-a2a")),
    };
    let adapter = LiveA2ATaskAdapter::new(config);

    let task_id = uuid::Uuid::new_v4().to_string();
    println!("Delegating task {task_id} to '{to_agent_id}'...");

    let task = TaskEnvelope {
        task_id: task_id.clone(),
        pattern: PatternKind::Development,
        epoch: Epoch(0),
        correlation_id: Some(format!("agentbridge-delegate-{task_id}")),
        body: prompt.as_bytes().to_vec(),
    };

    adapter.dispatch(task).map_err(|e| anyhow::anyhow!("{e}"))?;

    let dispatches = adapter
        .dispatches()
        .map_err(|e| anyhow::anyhow!("failed to read dispatches: {e}"))?;

    if let Some(record) = dispatches.first() {
        println!("Response from '{to_agent_id}' ({:.0}ms):", record.elapsed_ms);
        println!("{}", record.response);
    } else {
        println!("Task dispatched successfully.");
    }

    Ok(())
}
