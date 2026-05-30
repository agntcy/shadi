use agentbridge::{
    adapters::{claude_code::ClaudeCodeAdapter, generic_stdio::GenericStdioAdapter},
    dir_registry::{AdapterOasfRecord, DirError},
    CliAdapter,
};

/// Start a registered adapter server for a named tool.
pub fn run(tool: &str, command: Option<&str>, args: &[String]) -> anyhow::Result<()> {
    match tool {
        "generic-stdio" => {
            let command = command.ok_or_else(|| {
                anyhow::anyhow!("--command is required for tool type 'generic-stdio'")
            })?;
            let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            let adapter = GenericStdioAdapter::spawn(tool, command, &args_ref)?;
            println!("Registered adapter '{}' (agent id: {})", tool, adapter.agent_id().0);
            println!("Adapter is running. Press Ctrl-C to stop.");
            std::thread::park();
        }
        "claude-code" => {
            let work_dir = command
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| ".".into()));
            let adapter = ClaudeCodeAdapter::new("claude-code", &work_dir);
            println!(
                "Registered Claude Code adapter (agent id: {}, dir: {})",
                adapter.agent_id().0,
                work_dir.display()
            );
            println!("Adapter ready. Use 'agentbridge handoff' or 'agentbridge coordinate'.");
            // For claude-code, the adapter is used on-demand (no persistent subprocess).
        }
        other => {
            anyhow::bail!(
                "Unknown tool type '{}'. Supported: generic-stdio, claude-code. \
                 Coming soon: copilot, codex.",
                other
            );
        }
    }
    Ok(())
}

/// Publish an OASF record for the given tool to the Agent Directory.
pub fn publish_to_dir(
    tool: &str,
    dir_server: &str,
    gh_token: Option<&str>,
) -> anyhow::Result<()> {
    // Build a minimal stub adapter just to get the agent_id.
    let stub_id = shadi_mas::AgentId(tool.to_string());
    struct StubAdapter(agentbridge::shadi_mas::AgentId);
    impl CliAdapter for StubAdapter {
        fn agent_id(&self) -> &shadi_mas::AgentId { &self.0 }
        fn snapshot_context(&self) -> Result<agentbridge::ContextPacket, agentbridge::CliAdapterError> {
            Ok(agentbridge::ContextPacket::new(self.0.0.clone()))
        }
        fn inject_context(&self, _: &agentbridge::ContextPacket) -> Result<(), agentbridge::CliAdapterError> { Ok(()) }
        fn execute_prompt(&self, _: &str) -> Result<String, agentbridge::CliAdapterError> { Ok(String::new()) }
    }

    let adapter = StubAdapter(stub_id);
    let record = AdapterOasfRecord::for_adapter(&adapter, env!("CARGO_PKG_VERSION"));

    println!("Publishing OASF record for '{}' to {dir_server}...", tool);
    match agentbridge::dir_registry::publish_adapter(&record, dir_server, gh_token) {
        Ok(cid) => println!("Published. CID: {cid}"),
        Err(DirError::DirctlNotFound) => {
            println!("dirctl not found — skipping DIR publish.");
            println!("Install: brew tap agntcy/dir https://github.com/agntcy/dir/ && brew install dirctl");
        }
        Err(e) => anyhow::bail!("DIR publish failed: {e}"),
    }
    Ok(())
}
