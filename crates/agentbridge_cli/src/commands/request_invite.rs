use agentbridge::owner_intake::{owner_service_name, render_request};
use shadi_mas::{
    experiments::LiveA2ATaskAdapterConfig, Epoch, PatternKind, TaskAdapter, TaskEnvelope,
};

/// The adapter config for the request to `owner`'s intake service.
///
/// It names no peer DID (the owner is addressed by name), so under open
/// admission there is nothing to pin and this refuses before anything is
/// dialled.
fn owner_config(
    owner: &str,
    agent_id: &str,
    endpoint: &str,
) -> anyhow::Result<LiveA2ATaskAdapterConfig> {
    shadi_mas::experiments::require_peer_did_when_open(None, "request-invite")
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(LiveA2ATaskAdapterConfig {
        endpoint: endpoint.to_string(),
        agent_id: agent_id.to_string(),
        local_name: None,
        peer_agent_id: owner.to_string(),
        destination: Some(owner_service_name(owner)),
        a2a_url: None,
        a2a_binding: None,
        peer_did: None,
    })
}

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
    let config = owner_config(owner, agent_id, endpoint)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_invite_needs_a_peer_did_under_open_admission() {
        {
            let _env = crate::commands::MemberDidsEnv::set(None);
            let err = owner_config("owner", "avatar", "127.0.0.1:47357")
                .expect_err("open admission needs a peer DID");
            let err = err.to_string();
            assert!(err.starts_with("request-invite: open admission"), "{err}");
            assert!(err.contains("did:key"), "{err}");
            // `run` stops there, before it builds an adapter or dials.
            let err = run(
                "owner",
                "chan",
                "bob",
                "did:key:zBob",
                "avatar",
                "127.0.0.1:1",
            )
            .expect_err("run refuses")
            .to_string();
            assert!(err.starts_with("request-invite: open admission"), "{err}");
        }
        let _env = crate::commands::MemberDidsEnv::set(Some("did:key:zMember"));
        let config = owner_config("owner", "avatar", "127.0.0.1:47357").expect("closed");
        assert_eq!(config.peer_agent_id, "owner");
        assert_eq!(config.destination, Some(owner_service_name("owner")));
        assert_eq!(config.peer_did, None);
    }
}
