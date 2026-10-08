use agentbridge::owner_intake::{owner_service_name, render_request};
use shadi_mas::{
    experiments::LiveA2ATaskAdapterConfig, Epoch, PatternKind, TaskAdapter, TaskEnvelope,
};

/// Ask a channel's owner to let `invitee_name` (`invitee_did`) into `channel`.
///
/// `owner` is the owner's SLIM name; the request goes to its
/// `<owner>-owner` service, signed with this agent's DID like any task. The
/// owner's standing rules grant it, refuse it, or hold it for the owner.
pub fn run(
    owner: &str,
    channel: &str,
    invitee_name: &str,
    invitee_did: &str,
    agent_id: &str,
    endpoint: &str,
) -> anyhow::Result<()> {
    let config = LiveA2ATaskAdapterConfig {
        endpoint: endpoint.to_string(),
        agent_id: agent_id.to_string(),
        local_name: Some(format!("agntcy/shadi/{agent_id}-a2a-client")),
        peer_agent_id: owner.to_string(),
        destination: Some(owner_service_name(owner)),
        a2a_url: None,
        a2a_binding: None,
        peer_did: None,
    };
    let adapter = super::egress::live_adapter(config);

    let task_id = uuid::Uuid::new_v4().to_string();
    let task = TaskEnvelope {
        task_id: task_id.clone(),
        pattern: PatternKind::Development,
        epoch: Epoch(0),
        correlation_id: Some(format!("agentbridge-request-invite-{task_id}")),
        body: render_request(channel, invitee_name, invitee_did).into_bytes(),
    };
    adapter.dispatch(task).map_err(|e| anyhow::anyhow!("{e}"))?;

    let dispatches = adapter
        .dispatches()
        .map_err(|e| anyhow::anyhow!("failed to read dispatches: {e}"))?;
    match dispatches.first() {
        Some(record) => println!("{}", record.response),
        None => println!("request sent to {}", owner_service_name(owner)),
    }
    Ok(())
}
