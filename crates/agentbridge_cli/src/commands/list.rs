use agentbridge::local_registry::{LocalAdapterRecord, LocalAdapterRegistry};
use agentbridge::member_source::{CandidateMember, DirLookupOptions, MemberSource, SkillSearchSource};
use shadi_a2a::A2ALocator;

/// List registered agentbridge adapters.
///
/// `--local` lists listeners this machine started with
/// `register --slim-endpoint` and/or `--a2a-listen` (lease files under
/// `$SHADI_TMP_DIR`). Without `--local`, queries the agntcy Agent Directory
/// for adapters advertising the standard agentbridge skills, resolving each
/// match to a real `{name, did, slim_endpoint, locator}` via
/// [`SkillSearchSource`].
pub fn run(local: bool, server_addr: &str, github_token: Option<&str>) -> anyhow::Result<()> {
    if local {
        return list_local(&LocalAdapterRegistry::from_env());
    }

    println!("Searching Agent Directory ({server_addr}) for agentbridge adapters...\n");

    let source = SkillSearchSource {
        skill: "agent_orchestration/agent_coordination".to_string(),
        dir: DirLookupOptions {
            server_addr: server_addr.to_string(),
            gh_token: github_token.map(str::to_string),
            limit: 20,
        },
    };

    let candidates = source
        .resolve()
        .map_err(|e| anyhow::anyhow!("DIR search failed: {e}"))?;

    if candidates.is_empty() {
        println!("No agentbridge adapters found in DIR.");
        println!("Register one with: agentbridge register --tool <name> --dir-publish");
    } else {
        for c in &candidates {
            println!("{}", render_candidate(c));
        }
    }

    Ok(())
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
