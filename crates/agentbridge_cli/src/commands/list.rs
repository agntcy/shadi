use agentbridge::local_registry::{LocalAdapterRecord, LocalAdapterRegistry};
use agentbridge::member_source::{DirLookupOptions, MemberSource, SkillSearchSource};

/// List registered agentbridge adapters.
///
/// `--local` lists listeners this machine started with
/// `register --slim-endpoint` (lease files under `$SHADI_TMP_DIR`).
/// Without `--local`, queries the agntcy Agent Directory for adapters
/// advertising the standard agentbridge skills, resolving each match to a
/// real `{name, did, slim_endpoint}` via [`SkillSearchSource`] — the same
/// discovery technique a SLIM group moderator uses to pull in members.
pub fn run(
    local: bool,
    server_addr: &str,
    github_token: Option<&str>,
) -> anyhow::Result<()> {
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

    let candidates = source.resolve().map_err(|e| anyhow::anyhow!("DIR search failed: {e}"))?;

    if candidates.is_empty() {
        println!("No agentbridge adapters found in DIR.");
        println!("Register one with: agentbridge register --tool <name> --dir-publish");
    } else {
        for c in &candidates {
            match &c.slim_endpoint {
                Some(endpoint) => println!("{}  did={}  slim://{}", c.name, c.did, endpoint),
                None => println!("{}  did={}  (no SLIM endpoint)", c.name, c.did),
            }
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

fn render_local_listing(records: &[LocalAdapterRecord]) -> String {
    if records.is_empty() {
        return concat!(
            "No local agentbridge adapters.\n",
            "Start one with: agentbridge register --tool <name> --slim-endpoint <host:port>\n"
        )
        .to_string();
    }
    let mut out = String::from("Local agentbridge adapters:\n");
    for record in records {
        out.push_str(&format!(
            "{}  did={}  slim://{}\n",
            record.name, record.did, record.slim_endpoint
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_discovery_empty_registry_is_ok() {
        let registry = LocalAdapterRegistry::with_dir(std::path::PathBuf::from(
            "/no/such/agentbridge-local-test-dir",
        ));
        assert!(list_local(&registry).is_ok());
        assert!(render_local_listing(&[]).contains("No local agentbridge adapters"));
    }

    #[test]
    fn local_listing_prints_name_did_and_endpoint() {
        let records = vec![LocalAdapterRecord {
            name: "copilot".to_string(),
            did: "did:key:zLocal".to_string(),
            slim_endpoint: "127.0.0.1:47357".to_string(),
            pid: 1,
        }];
        let rendered = render_local_listing(&records);
        assert!(rendered.contains("copilot  did=did:key:zLocal  slim://127.0.0.1:47357"));
    }
}
