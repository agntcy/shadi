use clap::{Parser, Subcommand};

mod commands;

#[derive(Parser)]
#[command(
    name = "agentbridge",
    about = "Interconnect CLI coding agents (Claude Code, Copilot, Codex, …) \
             via A2A / SLIM with autonomous coordination."
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Register and start a CLI tool adapter.
    Register {
        /// Tool type: generic-stdio | claude-code | copilot | codex | cursor-agent
        #[arg(long)]
        tool: String,

        /// Subprocess command (required for generic-stdio).
        #[arg(long)]
        command: Option<String>,

        /// Extra arguments forwarded to the subprocess.
        #[arg(long = "arg", value_name = "ARG")]
        args: Vec<String>,

        /// Publish an OASF record to the Agent Directory after registering.
        #[arg(long)]
        dir_publish: bool,

        /// Agent Directory server address (used with --dir-publish).
        #[arg(long, default_value = "prod.gateway.ads.outshift.io:443")]
        dir_server: String,

        /// GitHub token for DIR authentication (or set DIRECTORY_CLIENT_GITHUB_TOKEN).
        #[arg(long)]
        gh_token: Option<String>,

        /// Start a SLIM A2A listener so remote callers can reach this adapter.
        /// Authenticates via DID/keys (SHADI_SLIM_AUTH=did, SLIM_HUMAN_SEED,
        /// SLIM_MEMBER_DIDS) — shared secrets are not supported.
        #[arg(long, env = "SLIM_ENDPOINT")]
        slim_endpoint: Option<String>,
    },

    /// List available adapters (Agent Directory or this machine).
    List {
        /// List listeners started by `register --slim-endpoint` on this host.
        #[arg(long)]
        local: bool,

        /// Agent Directory server address.
        #[arg(long, default_value = "prod.gateway.ads.outshift.io:443")]
        dir_server: String,

        /// GitHub token for DIR authentication.
        #[arg(long)]
        gh_token: Option<String>,
    },

    /// Hand off context from one CLI tool to another.
    ///
    /// `--from` / `--to` accept the same specs as `coordinate`
    /// (`claude-code`, `copilot`, `codex`, `cursor-agent`,
    /// `generic-stdio:<cmd>`, `slim:<id>`). A bare command still opens
    /// GenericStdio. The snapshot is an LLM session summary this cycle,
    /// not a true session export.
    Handoff {
        /// Source spec (native tool, generic-stdio:<cmd>, slim:<id>, or a command).
        #[arg(long)]
        from: String,

        /// Destination spec (same forms as --from).
        #[arg(long)]
        to: String,

        /// Save the captured ContextPacket to this path.
        #[arg(long)]
        save: Option<String>,

        /// Load a saved ContextPacket instead of snapshotting a live source.
        #[arg(long, value_name = "FILE")]
        from_file: Option<String>,

        /// SLIM node endpoint used for slim:<id> specs.
        #[arg(long, env = "SLIM_ENDPOINT", default_value = "127.0.0.1:47357")]
        slim_endpoint: String,
    },

    /// Delegate a single task to a remote agentbridge adapter over A2A/SLIM.
    Delegate {
        /// Prompt or task description to send.
        prompt: String,

        /// Agent ID of the destination adapter (must be registered and listening).
        #[arg(long)]
        to: String,

        /// Your local agent ID (registered with the SLIM node).
        #[arg(long, env = "SHADI_AGENT_ID", default_value = "avatar")]
        agent_id: String,

        /// SLIM node endpoint.
        #[arg(long, env = "SLIM_ENDPOINT", default_value = "127.0.0.1:47357")]
        endpoint: String,
    },

    /// Run autonomous multi-round coordination toward a programming goal.
    Coordinate {
        /// The goal to achieve, e.g. "implement a JSON parser in Rust".
        #[arg(long)]
        goal: String,

        /// Comma-separated agent specs.
        /// Formats: claude-code, claude-code:/path, generic-stdio:<command>, slim:<agent-id>, slim:<agent-id>@<host:port>
        #[arg(long, value_delimiter = ',')]
        agents: Vec<String>,

        /// Minimum endorsements to select a winning artifact.
        #[arg(long, default_value = "2")]
        quorum: usize,

        /// Maximum coordination rounds before force-finalizing.
        #[arg(long, default_value = "5")]
        max_rounds: u64,

        /// Write the winning artifact to this file.
        #[arg(long)]
        output: Option<String>,

        /// Require explicit human approval before accepting the result.
        #[arg(long)]
        require_human: bool,

        /// SLIM node endpoint used for slim:<agent-id> specs (env: SLIM_ENDPOINT).
        /// Authenticates via DID/keys (SHADI_SLIM_AUTH=did, SLIM_HUMAN_SEED,
        /// SLIM_MEMBER_DIDS) — shared secrets are not supported.
        #[arg(long, env = "SLIM_ENDPOINT", default_value = "127.0.0.1:47357")]
        slim_endpoint: String,
    },
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::WARN.into()),
        )
        .init();

    let cli = Cli::parse();

    let result = match cli.command {
        Cmd::Register { tool, command, args, dir_publish, dir_server, gh_token, slim_endpoint } => {
            let publish_opts = dir_publish.then_some(commands::register::DirPublishOptions {
                server: dir_server.as_str(),
                gh_token: gh_token.as_deref(),
            });
            commands::register::run(
                &tool,
                command.as_deref(),
                &args,
                slim_endpoint.as_deref(),
                publish_opts,
            )
        }
        Cmd::List { local, dir_server, gh_token } => {
            commands::list::run(local, &dir_server, gh_token.as_deref())
        }
        Cmd::Handoff { from, to, save, from_file, slim_endpoint } => {
            if let Some(file) = from_file {
                commands::handoff::run_from_file(
                    std::path::Path::new(&file),
                    &to,
                    &slim_endpoint,
                )
            } else {
                commands::handoff::run(&from, &to, save.as_deref(), &slim_endpoint)
            }
        }
        Cmd::Delegate { prompt, to, agent_id, endpoint } => {
            commands::delegate::run(&prompt, &to, &agent_id, &endpoint)
        }
        Cmd::Coordinate { goal, agents, quorum, max_rounds, output, require_human, slim_endpoint } => {
            commands::coordinate::run(
                &goal,
                &agents,
                quorum,
                max_rounds,
                output.as_deref(),
                require_human,
                &slim_endpoint,
            )
        }
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn cli_definition_is_valid() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_list_local_subcommand() {
        let cli = Cli::try_parse_from(["agentbridge", "list", "--local"]).expect("parse");
        match cli.command {
            Cmd::List { local, .. } => assert!(local),
            _ => panic!("expected list subcommand"),
        }
    }

    #[test]
    fn parses_coordinate_with_comma_separated_agents() {
        let cli = Cli::try_parse_from([
            "agentbridge",
            "coordinate",
            "--goal",
            "build a parser",
            "--agents",
            "claude-code,copilot",
        ])
        .expect("parse");
        match cli.command {
            Cmd::Coordinate { goal, agents, quorum, .. } => {
                assert_eq!(goal, "build a parser");
                assert_eq!(agents, ["claude-code", "copilot"]);
                assert_eq!(quorum, 2);
            }
            _ => panic!("expected coordinate subcommand"),
        }
    }

    #[test]
    fn rejects_unknown_subcommand() {
        assert!(Cli::try_parse_from(["agentbridge", "nope"]).is_err());
    }

    #[test]
    fn parses_native_handoff_specs() {
        let cli = Cli::try_parse_from([
            "agentbridge",
            "handoff",
            "--from",
            "claude-code",
            "--to",
            "copilot",
        ])
        .expect("parse");
        match cli.command {
            Cmd::Handoff { from, to, .. } => {
                assert_eq!(from, "claude-code");
                assert_eq!(to, "copilot");
            }
            _ => panic!("expected handoff subcommand"),
        }
    }
}
