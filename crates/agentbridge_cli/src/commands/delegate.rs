use agentbridge::local_registry::LocalAdapterRegistry;
use agentbridge::member_source::{
    find_running_peer, parse_peer_did, runtime_not_running, resolve_adapter_peer, CandidateMember, DirLookupOptions,
};
use shadi_a2a::{A2ABinding, A2ALocator};
use shadi_mas::{
    experiments::LiveA2ATaskAdapterConfig, Epoch, PatternKind, TaskAdapter, TaskEnvelope,
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
    runtime: &str,
) -> anyhow::Result<()> {
    let (peer, found) = resolve_delegate_peer(to_agent_id, a2a_url, a2a_binding, runtime)?;
    if found == Found::Runtime {
        eprintln!(
            "[agentbridge] '{}' ({}) was found through dir-runtime {runtime}: its DID and \
             address are what it announced about itself, and nothing checks that the DID \
             answers there yet (agntcy/shadi#504)",
            peer.name, peer.did
        );
    }
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
    let adapter = super::egress::live_adapter(config);

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

/// Where a delegate peer was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Found {
    /// A listener on this host, through its lease.
    Local,
    /// A published, signed record in DIR.
    Directory,
    /// A workload dir-runtime reports, as the agent announced itself:
    /// unverified.
    Runtime,
}

/// Find `to`: a listener on this host (its lease); for a DID, else its signed
/// record in DIR, else what dir-runtime reports; for a name, else dir-runtime,
/// else DIR.
fn resolve_delegate_peer(
    to: &str,
    a2a_url_override: Option<&str>,
    a2a_binding: Option<A2ABinding>,
    runtime: &str,
) -> anyhow::Result<(CandidateMember, Found)> {
    let registry = LocalAdapterRegistry::from_env();
    let dir = DirLookupOptions {
        server_addr: std::env::var("DIRECTORY_SERVER")
            .unwrap_or_else(|_| "prod.gateway.ads.outshift.io:443".to_string()),
        gh_token: std::env::var("DIRECTORY_CLIENT_GITHUB_TOKEN").ok(),
        limit: 5,
    };

    let runtime_opts = DirLookupOptions {
        server_addr: runtime.to_string(),
        gh_token: None,
        limit: 0,
    };
    resolve_peer_found(
        to,
        registry.resolve_live(to).map(|r| r.did),
        || find_running_peer(to, &runtime_opts),
        || resolve_adapter_peer(to, &registry, Some(&dir)),
        a2a_url_override,
        a2a_binding,
        runtime,
    )
    .map_err(|e| anyhow::anyhow!("{e}"))
}

/// [`resolve_peer_found`] without saying where the peer was found.
#[cfg(test)]
fn resolve_peer_with(
    to: &str,
    leased: Result<String, String>,
    running: impl FnOnce() -> Result<Option<CandidateMember>, String>,
    fallback: impl FnOnce() -> Result<CandidateMember, String>,
    a2a_url_override: Option<&str>,
    a2a_binding: Option<A2ABinding>,
    runtime: &str,
) -> Result<CandidateMember, String> {
    resolve_peer_found(
        to,
        leased,
        running,
        fallback,
        a2a_url_override,
        a2a_binding,
        runtime,
    )
    .map(|(peer, _)| peer)
}

/// Pick the peer and say where it was found: a local lease (`leased`: its
/// DID, if one matches); then, for a DID, `fallback` (the lease again, or the
/// signed DIR record) before `running` (dir-runtime), and for a name,
/// `running` before `fallback`. Then apply `--a2a-url` / `--a2a-binding`.
/// Several matching instances are an error unless `to` is a DID and
/// `--a2a-url` picks the instance; so is a name that a lease and a running
/// agent with another DID share.
fn resolve_peer_found(
    to: &str,
    leased: Result<String, String>,
    running: impl FnOnce() -> Result<Option<CandidateMember>, String>,
    fallback: impl FnOnce() -> Result<CandidateMember, String>,
    a2a_url_override: Option<&str>,
    a2a_binding: Option<A2ABinding>,
    runtime: &str,
) -> Result<(CandidateMember, Found), String> {
    let is_did = parse_peer_did(to).is_some();
    // dir-runtime's answer, or why there is none to use.
    let ask_runtime = |running: Box<dyn FnOnce() -> Result<Option<CandidateMember>, String> + '_>| {
        match running() {
            Ok(found) => Ok(found),
            Err(e) if e.contains("ambiguous") => Err(e),
            // No dir-runtime running is normal (it's optional); report
            // anything else.
            Err(e) if runtime_not_running(&e) => Ok(None),
            Err(e) => {
                eprintln!("[agentbridge] couldn't ask dir-runtime {runtime}: {e}");
                Ok(None)
            }
        }
    };

    let resolved = match leased {
        Err(err) if err.contains("ambiguous") => Err(err),
        // A DID: its signed record before what dir-runtime reports.
        Err(_) if is_did => match fallback() {
            Ok(peer) => Ok((peer, Found::Directory)),
            Err(not_in_dir) => match ask_runtime(Box::new(running)) {
                Ok(Some(peer)) => Ok((peer, Found::Runtime)),
                Ok(None) => Err(not_in_dir),
                Err(e) => Err(e),
            },
        },
        Err(_) => match ask_runtime(Box::new(running)) {
            Ok(Some(peer)) => Ok((peer, Found::Runtime)),
            Ok(None) => fallback().map(|peer| (peer, Found::Directory)),
            Err(e) => Err(e),
        },
        Ok(lease_did) if !is_did => match running() {
            Ok(Some(other)) if other.did != lease_did => Err(format!(
                "ambiguous: '{to}' is a local listener ({lease_did}) and a running agent at \
                 dir-runtime {runtime} ({}). Pass --to <did> to pick one",
                other.did
            )),
            Err(e) if e.contains("ambiguous") => Err(e),
            _ => fallback().map(|peer| (peer, Found::Local)),
        },
        Ok(_) => fallback().map(|peer| (peer, Found::Local)),
    };
    let found = resolved.as_ref().map_or(Found::Local, |(_, found)| *found);
    apply_locator_override(
        to,
        resolved.map(|(peer, _)| peer),
        a2a_url_override,
        a2a_binding,
    )
    .map(|peer| (peer, found))
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

    fn instance(port: u16) -> CandidateMember {
        CandidateMember {
            name: "copilot".to_string(),
            did: "did:key:zTwice".to_string(),
            slim_endpoint: None,
            a2a_url: Some(format!("http://127.0.0.1:{port}")),
            a2a_binding: Some(A2ABinding::HttpJson),
        }
    }

    #[test]
    fn a_locator_picks_one_of_several_local_instances_of_a_did() {
        let ambiguous = || Err("ambiguous: 2 live adapters match".to_string());
        let resolve = |to: &str, url: Option<&str>| {
            resolve_peer_with(
                to,
                ambiguous(),
                || panic!("a local match doesn't ask dir-runtime"),
                || panic!("nor fall back"),
                url,
                Some(A2ABinding::HttpJson),
                "localhost:8888",
            )
        };

        let picked = resolve("did:key:zTwice", Some("http://127.0.0.1:2")).unwrap();
        assert_eq!(picked.did, "did:key:zTwice");
        assert_eq!(picked.a2a_url.as_deref(), Some("http://127.0.0.1:2"));
        assert!(resolve("did:key:zTwice", None)
            .unwrap_err()
            .contains("ambiguous"));
        assert!(resolve("copilot", Some("http://127.0.0.1:2"))
            .unwrap_err()
            .contains("ambiguous"));
    }

    #[test]
    fn a_name_shared_by_a_lease_and_another_running_agent_is_ambiguous() {
        let resolve = |running_did: &'static str| {
            resolve_peer_with(
                "copilot",
                Ok("did:key:zLease".to_string()),
                move || {
                    Ok(Some(CandidateMember {
                        did: running_did.to_string(),
                        ..instance(1)
                    }))
                },
                || Ok(instance(2)),
                None,
                None,
                "localhost:8888",
            )
        };

        let err = resolve("did:key:zOther").unwrap_err();
        assert!(err.contains("ambiguous"), "{err}");
        assert!(err.contains("did:key:zLease") && err.contains("did:key:zOther"), "{err}");
        assert!(resolve("did:key:zLease").is_ok(), "the same agent, announced");
    }

    #[test]
    fn a_did_is_taken_from_its_signed_record_before_dir_runtime() {
        let (peer, found) = resolve_peer_found(
            "did:key:zTwice",
            Err("no live adapter".to_string()),
            || panic!("DIR knows the DID, so dir-runtime isn't asked"),
            || Ok(instance(7)),
            None,
            None,
            "localhost:8888",
        )
        .unwrap();
        assert_eq!(found, Found::Directory);
        assert_eq!(peer.a2a_url.as_deref(), Some("http://127.0.0.1:7"));

        let (_, found) = resolve_peer_found(
            "did:key:zTwice",
            Err("no live adapter".to_string()),
            || Ok(Some(instance(1))),
            || Err("DID not found in DIR".to_string()),
            None,
            None,
            "localhost:8888",
        )
        .unwrap();
        assert_eq!(found, Found::Runtime, "only dir-runtime has it: unverified");
    }

    #[test]
    fn a_name_found_through_dir_runtime_is_marked_unverified() {
        let (_, found) = resolve_peer_found(
            "copilot",
            Err("no live adapter".to_string()),
            || Ok(Some(instance(1))),
            || panic!("found in dir-runtime"),
            None,
            None,
            "localhost:8888",
        )
        .unwrap();
        assert_eq!(found, Found::Runtime);
    }

    #[test]
    fn a_locator_picks_one_of_several_running_instances_of_a_did() {
        let resolve = |to: &str, url: Option<&str>| {
            resolve_peer_with(
                to,
                Err("no live adapter".to_string()),
                || Err("ambiguous: 2 running agents match".to_string()),
                || Err("DID not found in DIR".to_string()),
                url,
                Some(A2ABinding::HttpJson),
                "localhost:8888",
            )
        };

        let picked = resolve("did:key:zTwice", Some("http://127.0.0.1:2")).unwrap();
        assert_eq!(picked.a2a_url.as_deref(), Some("http://127.0.0.1:2"));
        assert!(resolve("did:key:zTwice", None)
            .unwrap_err()
            .contains("ambiguous"));
    }

    #[test]
    fn a_running_agent_is_used_when_no_lease_matches() {
        let peer = resolve_peer_with(
            "copilot",
            Err("no live adapter".to_string()),
            || Ok(Some(instance(1))),
            || panic!("found in dir-runtime"),
            None,
            None,
            "localhost:8888",
        )
        .unwrap();
        assert_eq!(peer.a2a_url.as_deref(), Some("http://127.0.0.1:1"));
    }

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
