use agentbridge::{
    adapters::generic_stdio::GenericStdioAdapter,
    CliAdapter, ContextPacket,
};
use std::path::Path;

/// Transfer context from one CLI tool to another.
///
/// Phase 1 workflow (both tools must be `generic-stdio` subprocess adapters):
///   1. Snapshot the source adapter → `ContextPacket`
///   2. Optionally persist the packet to `--save <path>` for recovery
///   3. Inject the packet into the destination adapter
///
/// Phase 2 will replace the subprocess-based source/dest with native adapters
/// (claude-code, copilot, codex) and route the packet over A2A/SLIM.
pub fn run(
    from_cmd: &str,
    to_cmd: &str,
    save: Option<&str>,
) -> anyhow::Result<()> {
    // Spawn source adapter.
    let src = GenericStdioAdapter::spawn("source", from_cmd, &[])?;
    println!("Source adapter '{}' connected.", from_cmd);

    // Snapshot context.
    let ctx: ContextPacket = src.snapshot_context().map_err(|e| anyhow::anyhow!("{e}"))?;
    println!(
        "Captured context: {} messages, {} files, {} artifacts.",
        ctx.conversation.len(),
        ctx.code_context.files.len(),
        ctx.artifacts.len(),
    );

    // Persist if requested.
    if let Some(path) = save {
        let bytes = ctx.to_bytes()?;
        std::fs::write(path, &bytes)?;
        println!("Context saved to {path}.");
    }

    // Spawn destination adapter.
    let dst = GenericStdioAdapter::spawn("destination", to_cmd, &[])?;
    println!("Destination adapter '{}' connected.", to_cmd);

    // Inject context.
    dst.inject_context(&ctx).map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("Context successfully handed off to '{}'.", to_cmd);

    Ok(())
}

/// Load a previously saved `ContextPacket` from disk and inject it into a
/// destination adapter. Useful for resuming after a crash.
pub fn run_from_file(context_path: &Path, to_cmd: &str) -> anyhow::Result<()> {
    let bytes = std::fs::read(context_path)?;
    let ctx = ContextPacket::from_bytes(&bytes)?;
    println!(
        "Loaded context from '{}': {} messages.",
        context_path.display(),
        ctx.conversation.len(),
    );

    let dst = GenericStdioAdapter::spawn("destination", to_cmd, &[])?;
    dst.inject_context(&ctx).map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("Context injected into '{to_cmd}'.");

    Ok(())
}
