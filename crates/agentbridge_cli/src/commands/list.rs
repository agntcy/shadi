use agentbridge::local_registry::{LocalAdapterRecord, LocalAdapterRegistry};
use agentbridge::member_source::{
    A2AAgentSearchSource, CandidateMember, DirLookupOptions, MemberSource, RunningAgentSource,
};
use shadi_a2a::A2ALocator;

/// Where `agentbridge list` looks.
pub struct ListOptions<'a> {
    /// Only this host's listeners (`--local`).
    pub local: bool,
    /// DIR records instead of running agents (`--published`).
    pub published: bool,
    /// OASF skills to filter on (`--skill`, any of them).
    pub skills: &'a [String],
    /// dir-runtimes to ask for running agents (`--runtime`).
    pub runtimes: &'a [String],
    /// The Directory for `--published`.
    pub dir_server: &'a str,
    pub gh_token: Option<&'a str>,
}

/// List agentbridge agents.
///
/// By default, the running ones: this host's listeners (leases under
/// `$SHADI_TMP_DIR`, and listeners announced to dir-runtime) and every agent
/// each `--runtime` lists, merged and de-duplicated. `--local` lists only this
/// host's listeners; `--published` searches DIR records (`register
/// --dir-publish`) instead, which say what was published, not what runs.
pub fn run(opts: &ListOptions<'_>) -> anyhow::Result<()> {
    if opts.local {
        return list_local(&LocalAdapterRegistry::from_env());
    }
    if opts.published {
        return list_published(opts);
    }

    let mut candidates = Vec::new();
    // Local listeners carry no skills to filter on, so a skill filter only
    // applies to what runtime discovery reports.
    if opts.skills.is_empty() {
        let records = LocalAdapterRegistry::from_env()
            .list_live()
            .map_err(|e| anyhow::anyhow!("local discovery failed: {e}"))?;
        candidates.extend(records.iter().map(LocalAdapterRecord::to_candidate));
    }
    for runtime in opts.runtimes {
        let source = RunningAgentSource {
            skills: opts.skills.to_vec(),
            runtime: lookup(runtime, opts.gh_token),
        };
        match source.resolve() {
            Ok(found) => candidates.extend(found),
            Err(e) => eprintln!("[agentbridge] skipping dir-runtime {runtime}: {e}"),
        }
    }

    let candidates = dedup(candidates);
    if candidates.is_empty() {
        println!("No running agentbridge agents found.");
        println!("Start one with: agentbridge register --tool <name> --a2a-listen <host:port> [--dir-announce]");
    } else {
        for c in &candidates {
            println!("{}", render_candidate(c));
        }
    }
    Ok(())
}

fn list_published(opts: &ListOptions<'_>) -> anyhow::Result<()> {
    let server_addr = opts.dir_server;
    println!("Searching Agent Directory ({server_addr}) for published A2A agents...\n");

    let source = A2AAgentSearchSource {
        skills: opts.skills.to_vec(),
        dir: lookup(server_addr, opts.gh_token),
    };
    let candidates = source
        .resolve()
        .map_err(|e| anyhow::anyhow!("DIR search failed: {e}"))?;

    if candidates.is_empty() {
        println!("No A2A agents found in DIR.");
        println!("Register one with: agentbridge register --tool <name> --dir-publish");
    } else {
        for c in &candidates {
            println!("{}", render_candidate(c));
        }
    }
    Ok(())
}

fn lookup(server_addr: &str, gh_token: Option<&str>) -> DirLookupOptions {
    DirLookupOptions {
        server_addr: server_addr.to_string(),
        gh_token: gh_token.map(str::to_string),
        limit: 20,
    }
}

/// One entry per agent DID and locator: an announced listener is both a local
/// listener and a running workload.
fn dedup(candidates: Vec<CandidateMember>) -> Vec<CandidateMember> {
    let mut seen = std::collections::HashSet::new();
    let mut out: Vec<CandidateMember> = candidates
        .into_iter()
        .filter(|c| seen.insert((c.did.clone(), c.slim_endpoint.clone(), c.a2a_url.clone())))
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name).then(a.did.cmp(&b.did)));
    out
}

fn list_local(registry: &LocalAdapterRegistry) -> anyhow::Result<()> {
    let records = registry
        .list_live()
        .map_err(|e| anyhow::anyhow!("local discovery failed: {e}"))?;
    print!("{}", render_local_listing(&records));
    Ok(())
}

fn render_candidate(candidate: &CandidateMember) -> String {
    render_candidate_line(&candidate.name, &candidate.did, &candidate.locators())
}

fn render_candidate_line(name: &str, did: &str, locators: &[A2ALocator]) -> String {
    let mut line = format!("{name}  did={did}");
    for locator in locators {
        line.push_str(&format!("  {}", locator.display_uri()));
    }
    if locators.is_empty() {
        line.push_str("  (no A2A address)");
    }
    line
}

fn render_local_listing(records: &[LocalAdapterRecord]) -> String {
    if records.is_empty() {
        return concat!(
            "No local agentbridge adapters.\n",
            "Start one with: agentbridge register --tool <name> --slim-endpoint <host:port>\n",
            "            or: agentbridge register --tool <name> --a2a-listen <host:port> [--a2a-binding grpc|jsonrpc|http+json]\n"
        )
        .to_string();
    }
    let mut out = String::from("Local agentbridge adapters:\n");
    for record in records {
        out.push_str(&render_candidate(&record.to_candidate()));
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadi_a2a::A2ABinding;

    fn candidate(name: &str, did: &str, url: &str) -> CandidateMember {
        CandidateMember {
            name: name.into(),
            did: did.into(),
            slim_endpoint: None,
            a2a_url: Some(url.into()),
            a2a_binding: Some(shadi_a2a::A2ABinding::HttpJson),
        }
    }

    #[test]
    fn an_agent_listed_by_both_sources_appears_once() {
        let merged = dedup(vec![
            candidate("copilot", "did:key:zA", "http://127.0.0.1:1"),
            candidate("codex", "did:key:zB", "http://127.0.0.1:2"),
            candidate("copilot", "did:key:zA", "http://127.0.0.1:1"),
            candidate("copilot", "did:key:zA", "http://127.0.0.1:3"),
        ]);
        let names: Vec<(&str, &str)> = merged
            .iter()
            .map(|c| (c.name.as_str(), c.a2a_url.as_deref().unwrap()))
            .collect();
        assert_eq!(
            names,
            vec![
                ("codex", "http://127.0.0.1:2"),
                ("copilot", "http://127.0.0.1:1"),
                ("copilot", "http://127.0.0.1:3"),
            ]
        );
    }

    #[test]
    fn local_discovery_empty_registry_is_ok() {
        let registry = LocalAdapterRegistry::with_dir(std::path::PathBuf::from(
            "/no/such/agentbridge-local-test-dir",
        ));
        assert!(list_local(&registry).is_ok());
        let rendered = render_local_listing(&[]);
        assert!(rendered.contains("No local agentbridge adapters"));
        assert!(rendered.contains("--a2a-listen"));
    }

    #[test]
    fn local_listing_prints_slim_and_unicast_locators() {
        let records = vec![
            LocalAdapterRecord {
                name: "copilot".to_string(),
                did: "did:key:zLocal".to_string(),
                slim_endpoint: "127.0.0.1:47357".to_string(),
                a2a_url: String::new(),
                a2a_binding: A2ABinding::Grpc,
                pid: 1,
            },
            LocalAdapterRecord {
                name: "codex".to_string(),
                did: "did:key:zGrpc".to_string(),
                slim_endpoint: String::new(),
                a2a_url: "http://127.0.0.1:50051".to_string(),
                a2a_binding: A2ABinding::Grpc,
                pid: 2,
            },
            LocalAdapterRecord {
                name: "goose".to_string(),
                did: "did:key:zJson".to_string(),
                slim_endpoint: String::new(),
                a2a_url: "http://127.0.0.1:8080".to_string(),
                a2a_binding: A2ABinding::Jsonrpc,
                pid: 3,
            },
        ];
        let rendered = render_local_listing(&records);
        assert!(rendered.contains("copilot  did=did:key:zLocal  slim://127.0.0.1:47357"));
        assert!(rendered.contains("codex  did=did:key:zGrpc  grpc://127.0.0.1:50051"));
        assert!(rendered.contains("goose  did=did:key:zJson  jsonrpc://127.0.0.1:8080"));
    }
}
