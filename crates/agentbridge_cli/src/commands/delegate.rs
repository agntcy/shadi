use agentbridge::local_registry::LocalAdapterRegistry;
use agentbridge::member_source::{
    parse_peer_did, resolve_adapter_peer, CandidateMember, DirLookupOptions,
};
use shadi_a2a::{A2ABinding, A2ALocator};
use shadi_mas::{
    experiments::{LiveA2ATaskAdapter, LiveA2ATaskAdapterConfig},
    Epoch, PatternKind, TaskAdapter, TaskEnvelope,
};

/// Delegate a single task to a remote agentbridge adapter over A2A.
///
/// `--to` is the portable name: a DID (`did:key:…`), a local tool alias,
/// or the SLIM channel (`agntcy/shadi/<name>-a2a`). The locator is looked
/// up from the current lease (or DIR): a SLIM node (`slim://host:port`)
/// and/or a unicast URL. `--a2a-url` overrides the locator only.
///
/// `--a2a-url` may be `slim://host:port`, `jsonrpc://host:port`, or a bare
/// `http://` URL plus `--a2a-binding`. A bare `http://` without a binding
/// still means gRPC. Two agents can share one locator.
///
/// Remote `TASK_STATE_AUTH_REQUIRED` is handled by `LiveA2ATaskAdapter`:
/// re-prove the agent DID, optionally escalate (`SHADI_AUTH_REQUIRED_POLICY=ask`),
/// then deny with a reason on timeout or repeat bound.
///
/// Coding-agent adapters authenticate via DID/keys only (`SHADI_SLIM_AUTH=did`,
/// `SLIM_HUMAN_SEED`, `SLIM_MEMBER_DIDS`) — shared secrets are not supported.
pub fn run(
    prompt: &str,
    to_agent_id: &str,
    local_agent_id: &str,
    endpoint: &str,
    a2a_url: Option<&str>,
    a2a_binding: Option<A2ABinding>,
) -> anyhow::Result<()> {
    let peer = resolve_delegate_peer(to_agent_id, a2a_url, a2a_binding)?;
    let locator = peer.preferred_locator();

    let (slim_node, unicast) = match locator.as_ref() {
        Some(loc) if loc.binding == A2ABinding::Slim => (loc.slim_node(), None),
        Some(loc) => (endpoint.to_string(), Some(loc.clone())),
        None => (endpoint.to_string(), None),
    };
    if unicast.is_none() {
        std::env::set_var("SLIM_ENDPOINT", &slim_node);
    }

    let config = LiveA2ATaskAdapterConfig {
        endpoint: slim_node.clone(),
        agent_id: local_agent_id.to_string(),
        local_name: Some(format!("agntcy/shadi/{local_agent_id}-a2a")),
        peer_agent_id: peer.name.clone(),
        destination: Some(format!("agntcy/shadi/{}-a2a", peer.name)),
        a2a_url: unicast.as_ref().map(|l| l.url.clone()),
        a2a_binding: unicast.as_ref().map(|l| l.binding),
        peer_did: Some(peer.did.clone()),
    };
    let adapter = LiveA2ATaskAdapter::new(config);

    let task_id = uuid::Uuid::new_v4().to_string();
    let via = match locator.as_ref() {
        Some(loc) => loc.display_uri(),
        None => format!("slim://{slim_node}"),
    };
    println!(
        "Delegating task {task_id} to '{}' (did={}) via {via}...",
        peer.name, peer.did
    );

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
        println!(
            "Response from '{}' ({:.0}ms):",
            peer.name, record.elapsed_ms
        );
        println!("{}", record.response);
    } else {
        println!("Task dispatched successfully.");
    }

    Ok(())
}

fn resolve_delegate_peer(
    to: &str,
    a2a_url_override: Option<&str>,
    a2a_binding: Option<A2ABinding>,
) -> anyhow::Result<CandidateMember> {
    let registry = LocalAdapterRegistry::from_env();
    let dir = DirLookupOptions {
        server_addr: std::env::var("DIRECTORY_SERVER")
            .unwrap_or_else(|_| "prod.gateway.ads.outshift.io:443".to_string()),
        gh_token: std::env::var("DIRECTORY_CLIENT_GITHUB_TOKEN").ok(),
        limit: 5,
    };

    match resolve_adapter_peer(to, &registry, Some(&dir)) {
        Ok(peer) => apply_locator_override(to, Ok(peer), a2a_url_override, a2a_binding)
            .map_err(|e| anyhow::anyhow!("{e}")),
        Err(err) => apply_locator_override(to, Err(err), a2a_url_override, a2a_binding)
            .map_err(|e| anyhow::anyhow!("{e}")),
    }
}

fn apply_parsed_locator(peer: &mut CandidateMember, locator: A2ALocator) {
    if locator.binding == A2ABinding::Slim {
        peer.slim_endpoint = Some(locator.slim_node());
        peer.a2a_url = None;
        peer.a2a_binding = None;
    } else {
        peer.a2a_url = Some(locator.url);
        peer.a2a_binding = Some(locator.binding);
    }
}

fn apply_locator_override(
    to: &str,
    resolved: Result<CandidateMember, String>,
    a2a_url_override: Option<&str>,
    a2a_binding: Option<A2ABinding>,
) -> Result<CandidateMember, String> {
    let parsed = a2a_url_override
        .map(|raw| A2ALocator::parse_with_hint(raw, a2a_binding))
        .transpose()?;
    match resolved {
        Ok(mut peer) => {
            if let Some(locator) = parsed {
                apply_parsed_locator(&mut peer, locator);
            } else if let Some(binding) = a2a_binding {
                if binding.is_unicast() {
                    peer.a2a_binding = Some(binding);
                }
            }
            Ok(peer)
        }
        Err(err) => {
            if let (Some(did), Some(locator)) = (parse_peer_did(to), parsed) {
                let mut peer = CandidateMember {
                    name: did.clone(),
                    did,
                    slim_endpoint: None,
                    a2a_url: None,
                    a2a_binding: None,
                };
                apply_parsed_locator(&mut peer, locator);
                Ok(peer)
            } else if a2a_url_override.is_some() {
                Err(format!(
                    "{err}. --a2a-url is a locator, not a name. Pass --to did:key:… \
                     (the DID stays valid when the URL changes)"
                ))
            } else {
                Err(err)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locator_override_keeps_did_as_the_name() {
        let peer = apply_locator_override(
            "did:key:zMoved",
            Err("not on this host".to_string()),
            Some("http://127.0.0.1:50052"),
            None,
        )
        .expect("DID plus locator override");
        assert_eq!(peer.did, "did:key:zMoved");
        assert_eq!(peer.a2a_url.as_deref(), Some("http://127.0.0.1:50052"));
        assert_eq!(peer.a2a_binding, Some(A2ABinding::Grpc));
    }

    #[test]
    fn url_override_without_did_is_rejected() {
        let err = apply_locator_override(
            "copilot",
            Err("no live adapter named 'copilot'".to_string()),
            Some("http://127.0.0.1:9"),
            None,
        )
        .expect_err("name plus URL is not an identity");
        assert!(err.contains("locator"), "{err}");
        assert!(err.contains("did:key"), "{err}");
    }

    #[test]
    fn locator_override_refreshes_url_on_resolved_did() {
        let peer = apply_locator_override(
            "did:key:zSame",
            Ok(CandidateMember {
                name: "copilot".to_string(),
                did: "did:key:zSame".to_string(),
                slim_endpoint: None,
                a2a_url: Some("http://127.0.0.1:50051".to_string()),
                a2a_binding: Some(A2ABinding::Grpc),
            }),
            Some("http://10.0.0.8:50051"),
            None,
        )
        .expect("refresh locator");
        assert_eq!(peer.did, "did:key:zSame");
        assert_eq!(peer.name, "copilot");
        assert_eq!(peer.a2a_url.as_deref(), Some("http://10.0.0.8:50051"));
        assert_eq!(peer.a2a_binding, Some(A2ABinding::Grpc));
    }

    #[test]
    fn locator_override_none_keeps_resolved_url() {
        let peer = apply_locator_override(
            "did:key:zSame",
            Ok(CandidateMember {
                name: "copilot".to_string(),
                did: "did:key:zSame".to_string(),
                slim_endpoint: None,
                a2a_url: Some("http://127.0.0.1:50051".to_string()),
                a2a_binding: Some(A2ABinding::Grpc),
            }),
            None,
            None,
        )
        .expect("keep locator");
        assert_eq!(peer.a2a_url.as_deref(), Some("http://127.0.0.1:50051"));
        assert_eq!(peer.did, "did:key:zSame");
    }

    #[test]
    fn locator_override_parses_jsonrpc_uri() {
        let peer = apply_locator_override(
            "did:key:zJson",
            Err("not on this host".to_string()),
            Some("jsonrpc://127.0.0.1:8080"),
            None,
        )
        .expect("jsonrpc locator");
        assert_eq!(peer.did, "did:key:zJson");
        assert_eq!(peer.a2a_url.as_deref(), Some("http://127.0.0.1:8080"));
        assert_eq!(peer.a2a_binding, Some(A2ABinding::Jsonrpc));
        assert_eq!(
            peer.unicast_locator().unwrap().display_uri(),
            "jsonrpc://127.0.0.1:8080"
        );
    }

    #[test]
    fn locator_override_hint_binds_bare_http() {
        let peer = apply_locator_override(
            "did:key:zRest",
            Ok(CandidateMember {
                name: "codex".to_string(),
                did: "did:key:zRest".to_string(),
                slim_endpoint: None,
                a2a_url: Some("http://127.0.0.1:50051".to_string()),
                a2a_binding: Some(A2ABinding::Grpc),
            }),
            Some("http://127.0.0.1:8080"),
            Some(A2ABinding::HttpJson),
        )
        .expect("hint");
        assert_eq!(peer.a2a_binding, Some(A2ABinding::HttpJson));
        assert_eq!(peer.a2a_url.as_deref(), Some("http://127.0.0.1:8080"));
    }

    #[test]
    fn locator_override_parses_slim_node() {
        let peer = apply_locator_override(
            "did:key:zSlim",
            Err("not on this host".to_string()),
            Some("slim://127.0.0.1:47357/agntcy/shadi/copilot-a2a"),
            None,
        )
        .expect("slim locator");
        assert_eq!(peer.did, "did:key:zSlim");
        assert_eq!(peer.slim_endpoint.as_deref(), Some("127.0.0.1:47357"));
        assert_eq!(peer.a2a_url, None);
        assert_eq!(
            peer.preferred_locator().unwrap().display_uri(),
            "slim://127.0.0.1:47357"
        );
    }
}
