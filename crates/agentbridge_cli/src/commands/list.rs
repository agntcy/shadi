use agentbridge::member_source::{DirLookupOptions, MemberSource, SkillSearchSource};

/// List registered agentbridge adapters.
///
/// `--local` queries the running SLIM node (Phase 2+).
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
        println!("Local SLIM node discovery: not yet wired (Phase 3).");
        println!("Start an adapter with: agentbridge register --tool generic-stdio --command <cmd>");
        return Ok(());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_discovery_is_a_no_op_stub() {
        // The `--local` path prints guidance and returns Ok without touching
        // the network or requiring dirctl.
        assert!(run(true, "unused-addr:443", None).is_ok());
    }
}
