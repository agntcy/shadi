use agentbridge::dir_registry::{search_adapters, DirError};

/// List registered agentbridge adapters.
///
/// `--local` queries the running SLIM node (Phase 2+).
/// Without `--local`, queries the agntcy Agent Directory via `dirctl search`.
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

    match search_adapters("agent_orchestration/context_handoff", server_addr, 20, github_token) {
        Ok(json) => {
            if json.trim().is_empty() || json.trim() == "[]" || json.trim() == "null" {
                println!("No agentbridge adapters found in DIR.");
                println!("Register one with: agentbridge register --tool <name> --dir-publish");
            } else {
                println!("{json}");
            }
        }
        Err(DirError::DirctlNotFound) => {
            println!("dirctl not found in PATH — DIR discovery unavailable.");
            println!("Install: brew tap agntcy/dir https://github.com/agntcy/dir/ && brew install dirctl");
            println!("\nAlternatively, use --local to query the running SLIM node.");
        }
        Err(e) => {
            anyhow::bail!("DIR search failed: {e}");
        }
    }

    Ok(())
}
