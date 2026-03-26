use super::*;

#[derive(Parser, Debug)]
#[command(name = "shadi")]
#[command(about = "Secure Host Agentic AI Dynamic Instantiation")]
pub(crate) struct Cli {
    #[arg(long = "profile", value_enum, value_name = "PROFILE")]
    pub(crate) profile: Option<LauncherProfile>,

    #[arg(long = "policy", value_name = "FILE")]
    pub(crate) policy_file: Option<PathBuf>,

    #[arg(long = "allow", value_name = "PATH", action = ArgAction::Append)]
    pub(crate) allow: Vec<PathBuf>,

    #[arg(long = "read", value_name = "PATH", action = ArgAction::Append)]
    pub(crate) read: Vec<PathBuf>,

    #[arg(long = "write", value_name = "PATH", action = ArgAction::Append)]
    pub(crate) write: Vec<PathBuf>,

    #[arg(long = "net-block", action = ArgAction::SetTrue)]
    pub(crate) net_block: bool,

    #[arg(long = "net-allow", value_name = "HOST[:PORT]", action = ArgAction::Append)]
    pub(crate) net_allow: Vec<String>,

    #[arg(long = "allow-command", value_name = "CMD", action = ArgAction::Append)]
    pub(crate) allow_command: Vec<String>,

    #[arg(long = "inject-keychain", value_name = "KEY=ENV", action = ArgAction::Append)]
    pub(crate) inject_keychain: Vec<String>,

    #[arg(long = "trusted-secret", value_name = "KEY=NAME", action = ArgAction::Append)]
    pub(crate) trusted_secret: Vec<String>,

    #[arg(long = "trusted-secret-exec", value_name = "NAME=PROGRAM", action = ArgAction::Append)]
    pub(crate) trusted_secret_exec: Vec<String>,

    #[arg(long = "trusted-secret-fd-env", value_name = "NAME=ENV", action = ArgAction::Append)]
    pub(crate) trusted_secret_fd_env: Vec<String>,

    #[arg(long = "list-keychain", action = ArgAction::SetTrue)]
    pub(crate) list_keychain: bool,

    #[arg(long = "list-prefix", value_name = "PREFIX")]
    pub(crate) list_prefix: Option<String>,

    #[arg(long = "print-policy", action = ArgAction::SetTrue)]
    pub(crate) print_policy: bool,

    #[arg(long = "git-snapshot", action = ArgAction::SetTrue)]
    pub(crate) git_snapshot: bool,

    #[arg(long = "git-snapshot-dir", value_name = "DIR")]
    pub(crate) git_snapshot_dir: Option<PathBuf>,

    #[arg(long = "git-snapshot-untracked", action = ArgAction::SetTrue)]
    pub(crate) git_snapshot_untracked: bool,

    #[arg(long = "watch-policy", action = ArgAction::SetTrue)]
    pub(crate) watch_policy: bool,

    #[command(subcommand)]
    pub(crate) subcommand: Option<Commands>,

    #[arg(last = true)]
    pub(crate) run_command: Vec<String>,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
pub(crate) enum LauncherProfile {
    Strict,
    Balanced,
    Connected,
}

#[derive(Parser, Debug)]
#[command(name = "memory", about = "Query SQLCipher memory using SHADI secrets")]
pub(crate) struct MemoryCli {
    #[arg(long, env = "SHADI_MEMORY_DB", value_name = "PATH")]
    pub(crate) db: PathBuf,

    #[arg(long, env = "SHADI_MEMORY_KEY")]
    pub(crate) key: Option<String>,

    #[arg(long = "key-name", env = "SHADI_MEMORY_KEY_NAME", default_value = "shadi/memory/sqlcipher_key")]
    pub(crate) key_name: String,

    #[command(subcommand)]
    pub(crate) command: MemoryCommand,
}

#[derive(Parser, Debug)]
#[command(name = "trace", about = "Inspect local SHADI trace logs")]
pub(crate) struct TraceCli {
    #[arg(long, value_name = "PATH")]
    pub(crate) file: Option<PathBuf>,

    #[command(subcommand)]
    pub(crate) command: TraceCommand,
}

#[derive(Subcommand, Debug)]
pub(crate) enum Commands {
    #[command(name = "config")]
    Config(ConfigCli),
    #[command(name = "policy")]
    Policy(PolicyCli),
    #[command(name = "memory")]
    Memory(MemoryCli),
    #[command(name = "trace")]
    Trace(TraceCli),
    #[command(name = "slim-mas")]
    SlimMas(SlimMasCli),
    #[command(name = "did-from-gpg")]
    DidFromGpg(DidFromGpgArgs),
    #[command(name = "did-from-github")]
    DidFromGitHub(DidFromGitHubArgs),
    #[command(name = "get-secret")]
    GetSecret(GetSecretArgs),
    #[command(name = "derive-agent-did")]
    DeriveAgentDid(DeriveAgentDidArgs),
    #[command(name = "derive-agent-identity")]
    DeriveAgentIdentity(DeriveAgentIdentityArgs),
    #[command(name = "verify-agent-identity")]
    VerifyAgentIdentity(VerifyAgentIdentityArgs),
    #[command(name = "put-key")]
    PutKey(PutKeyArgs),
    /// Interactive terminal for managing SHADI sandbox sessions
    #[command(name = "shell")]
    Shell(ShellArgs),
}

#[derive(Parser, Debug)]
#[command(name = "config", about = "Inspect effective SHADI configuration")]
pub(crate) struct ConfigCli {
    #[command(subcommand)]
    pub(crate) command: ConfigCommand,
}

#[derive(Subcommand, Debug)]
pub(crate) enum ConfigCommand {
    Show(ConfigShowArgs),
}

#[derive(Parser, Debug)]
#[command(name = "policy", about = "Inspect and diff effective sandbox policy")]
pub(crate) struct PolicyCli {
    #[command(subcommand)]
    pub(crate) command: PolicyCommand,
}

#[derive(Subcommand, Debug)]
pub(crate) enum PolicyCommand {
    Explain(PolicyExplainArgs),
    Diff(PolicyDiffArgs),
    Patch(PolicyPatchArgs),
    Query(PolicyQueryArgs),
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
pub(crate) enum OutputFormat {
    Json,
    Text,
}

#[derive(Parser, Debug)]
#[command(name = "show", about = "Show effective runtime config")]
pub(crate) struct ConfigShowArgs {
    #[arg(long = "profile", value_enum, value_name = "PROFILE")]
    pub(crate) profile: Option<LauncherProfile>,

    #[arg(long = "policy", value_name = "FILE")]
    pub(crate) policy_file: Option<PathBuf>,

    #[arg(long = "allow", value_name = "PATH", action = ArgAction::Append)]
    pub(crate) allow: Vec<PathBuf>,

    #[arg(long = "read", value_name = "PATH", action = ArgAction::Append)]
    pub(crate) read: Vec<PathBuf>,

    #[arg(long = "write", value_name = "PATH", action = ArgAction::Append)]
    pub(crate) write: Vec<PathBuf>,

    #[arg(long = "net-block", action = ArgAction::SetTrue)]
    pub(crate) net_block: bool,

    #[arg(long = "allow-command", value_name = "CMD", action = ArgAction::Append)]
    pub(crate) allow_command: Vec<String>,

    #[arg(long = "format", value_enum, default_value = "json")]
    pub(crate) format: OutputFormat,
}

#[derive(Parser, Debug)]
#[command(name = "explain", about = "Explain resolved policy and source inputs")]
pub(crate) struct PolicyExplainArgs {
    #[arg(long = "profile", value_enum, value_name = "PROFILE")]
    pub(crate) profile: Option<LauncherProfile>,

    #[arg(long = "policy", value_name = "FILE")]
    pub(crate) policy_file: Option<PathBuf>,

    #[arg(long = "allow", value_name = "PATH", action = ArgAction::Append)]
    pub(crate) allow: Vec<PathBuf>,

    #[arg(long = "read", value_name = "PATH", action = ArgAction::Append)]
    pub(crate) read: Vec<PathBuf>,

    #[arg(long = "write", value_name = "PATH", action = ArgAction::Append)]
    pub(crate) write: Vec<PathBuf>,

    #[arg(long = "net-block", action = ArgAction::SetTrue)]
    pub(crate) net_block: bool,

    #[arg(long = "allow-command", value_name = "CMD", action = ArgAction::Append)]
    pub(crate) allow_command: Vec<String>,

    #[arg(long = "format", value_enum, default_value = "json")]
    pub(crate) format: OutputFormat,
}

#[derive(Parser, Debug)]
#[command(name = "diff", about = "Diff effective policy against a baseline")]
pub(crate) struct PolicyDiffArgs {
    #[arg(long = "against", value_name = "TARGET")]
    pub(crate) against: String,

    #[arg(long = "profile", value_enum, value_name = "PROFILE")]
    pub(crate) profile: Option<LauncherProfile>,

    #[arg(long = "policy", value_name = "FILE")]
    pub(crate) policy_file: Option<PathBuf>,

    #[arg(long = "allow", value_name = "PATH", action = ArgAction::Append)]
    pub(crate) allow: Vec<PathBuf>,

    #[arg(long = "read", value_name = "PATH", action = ArgAction::Append)]
    pub(crate) read: Vec<PathBuf>,

    #[arg(long = "write", value_name = "PATH", action = ArgAction::Append)]
    pub(crate) write: Vec<PathBuf>,

    #[arg(long = "net-block", action = ArgAction::SetTrue)]
    pub(crate) net_block: bool,

    #[arg(long = "net-allow", value_name = "HOST[:PORT]", action = ArgAction::Append)]
    pub(crate) net_allow: Vec<String>,

    #[arg(long = "allow-command", value_name = "CMD", action = ArgAction::Append)]
    pub(crate) allow_command: Vec<String>,

    #[arg(long = "format", value_enum, default_value = "json")]
    pub(crate) format: OutputFormat,
}

#[derive(Parser, Debug)]
#[command(name = "patch", about = "Send an incremental policy patch to a running sandbox session")]
pub(crate) struct PolicyPatchArgs {
    #[arg(long = "socket", value_name = "PATH")]
    pub(crate) socket: PathBuf,

    #[arg(long = "add-read", value_name = "PATH", action = ArgAction::Append)]
    pub(crate) add_read: Vec<String>,

    #[arg(long = "add-write", value_name = "PATH", action = ArgAction::Append)]
    pub(crate) add_write: Vec<String>,

    #[arg(long = "add-allow", value_name = "PATH", action = ArgAction::Append)]
    pub(crate) add_allow: Vec<String>,

    #[arg(long = "add-allow-command", value_name = "CMD", action = ArgAction::Append)]
    pub(crate) add_allow_command: Vec<String>,

    #[arg(long = "remove-allow-command", value_name = "CMD", action = ArgAction::Append)]
    pub(crate) remove_allow_command: Vec<String>,

    #[arg(long = "add-block-command", value_name = "CMD", action = ArgAction::Append)]
    pub(crate) add_block_command: Vec<String>,

    #[arg(long = "remove-block-command", value_name = "CMD", action = ArgAction::Append)]
    pub(crate) remove_block_command: Vec<String>,

    #[arg(long = "add-net-allow", value_name = "HOST", action = ArgAction::Append)]
    pub(crate) add_net_allow: Vec<String>,

    #[arg(long = "remove-net-allow", value_name = "HOST", action = ArgAction::Append)]
    pub(crate) remove_net_allow: Vec<String>,

    #[arg(long = "patch-file", value_name = "FILE")]
    pub(crate) patch_file: Option<PathBuf>,

    #[arg(long = "format", value_enum, default_value = "json")]
    pub(crate) format: OutputFormat,
}

#[derive(Parser, Debug)]
#[command(name = "query", about = "Query the effective policy of a running sandbox session")]
pub(crate) struct PolicyQueryArgs {
    #[arg(long = "socket", value_name = "PATH")]
    pub(crate) socket: PathBuf,

    #[arg(long = "format", value_enum, default_value = "json")]
    pub(crate) format: OutputFormat,
}

#[derive(Parser, Debug)]
#[command(name = "shell", about = "Interactive terminal for managing SHADI sandbox sessions")]
pub(crate) struct ShellArgs {
    /// Connect to a running sandbox session by control socket path
    #[arg(long = "socket", value_name = "PATH")]
    pub(crate) socket: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub(crate) enum TraceCommand {
    List {
        #[arg(long, default_value = "50")]
        limit: usize,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        command: Option<String>,
        #[arg(long)]
        exit_code: Option<i32>,
    },
    Summary {
        #[arg(long, default_value = "200")]
        limit: usize,
    },
}

#[derive(Parser, Debug)]
#[command(name = "slim-mas", about = "SLIM multi-agent system moderator helper")]
pub(crate) struct SlimMasCli {
    #[arg(long = "config", value_name = "FILE", default_value = "mas.toml")]
    pub(crate) config: PathBuf,

    #[command(subcommand)]
    pub(crate) command: SlimMasCommand,
}

#[derive(Subcommand, Debug)]
pub(crate) enum SlimMasCommand {
    Admit {
        #[arg(long = "group", value_name = "GROUP")]
        group: Option<String>,

        #[arg(long = "did", value_name = "DID")]
        did: String,

        #[arg(long = "role", value_name = "ROLE")]
        role: Option<String>,
    },
    ListGroups,
    ListMembers {
        #[arg(long = "group", value_name = "GROUP")]
        group: Option<String>,
    },
    Validate,
}

#[derive(Subcommand, Debug)]
pub(crate) enum MemoryCommand {
    Init,
    Put {
        #[arg(long)]
        scope: String,
        #[arg(long = "entry-key")]
        entry_key: String,
        #[arg(long)]
        payload: Option<String>,
        #[arg(long = "payload-file")]
        payload_file: Option<PathBuf>,
    },
    Get {
        #[arg(long)]
        scope: String,
        #[arg(long = "entry-key")]
        entry_key: String,
    },
    Search {
        #[arg(long)]
        scope: Option<String>,
        #[arg(long)]
        query: String,
        #[arg(long, default_value = "10")]
        limit: usize,
    },
    List {
        #[arg(long)]
        scope: Option<String>,
        #[arg(long, default_value = "50")]
        limit: usize,
    },
    Delete {
        #[arg(long)]
        scope: String,
        #[arg(long = "entry-key")]
        entry_key: String,
    },
}

#[derive(Parser, Debug)]
#[command(name = "did-from-gpg", about = "Create did:key DID document from a GPG Ed25519 public key")]
pub(crate) struct DidFromGpgArgs {
    #[arg(
        short = 'k',
        long = "key",
        value_name = "SECRET",
        required_unless_present = "input",
        conflicts_with = "input"
    )]
    pub(crate) key_ref: Option<String>,

    #[arg(
        short = 'i',
        long = "in",
        value_name = "FILE",
        required_unless_present = "key_ref",
        conflicts_with = "key_ref"
    )]
    pub(crate) input: Option<PathBuf>,

    #[arg(short = 'o', long = "out", value_name = "FILE", default_value = "did-document.json")]
    pub(crate) out_file: PathBuf,
}

#[derive(Parser, Debug)]
#[command(name = "did-from-github", about = "Create did:key DID document from a GitHub GPG public key")]
pub(crate) struct DidFromGitHubArgs {
    #[arg(long = "user", value_name = "USERNAME")]
    pub(crate) user: String,

    #[arg(long = "out", value_name = "FILE")]
    pub(crate) out_file: Option<PathBuf>,
}

#[derive(Parser, Debug)]
#[command(name = "get-secret", about = "Read a secret from the SHADI secret store")]
pub(crate) struct GetSecretArgs {
    #[arg(long = "key", value_name = "KEY")]
    pub(crate) key: String,
}

#[derive(Parser, Debug)]
#[command(name = "derive-agent-did", about = "Derive an agent DID from a human GPG key")]
pub(crate) struct DeriveAgentDidArgs {
    #[arg(
        short = 's',
        long = "secret",
        value_name = "SECRET",
        required_unless_present = "input",
        conflicts_with = "input"
    )]
    pub(crate) secret: Option<String>,

    #[arg(
        short = 'i',
        long = "in",
        value_name = "FILE",
        required_unless_present = "secret",
        conflicts_with = "secret"
    )]
    pub(crate) input: Option<PathBuf>,

    #[arg(short = 'n', long = "name", value_name = "NAME")]
    pub(crate) agent_name: String,

    #[arg(long = "prefix", value_name = "PATH", default_value = "agent_keys")]
    pub(crate) prefix: String,

    #[arg(short = 'o', long = "out", value_name = "FILE")]
    pub(crate) out_file: Option<PathBuf>,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
pub(crate) enum HumanIdentitySource {
    Gpg,
    Seed,
}

#[derive(Parser, Debug)]
#[command(name = "derive-agent-identity", about = "Derive one or more local agent identities from a human identity source")]
pub(crate) struct DeriveAgentIdentityArgs {
    #[arg(long = "source", value_enum, default_value = "gpg")]
    pub(crate) source: HumanIdentitySource,

    #[arg(
        short = 's',
        long = "human-secret",
        value_name = "SECRET",
        required_unless_present = "input",
        conflicts_with = "input"
    )]
    pub(crate) human_secret: Option<String>,

    #[arg(
        short = 'i',
        long = "in",
        value_name = "FILE",
        required_unless_present = "human_secret",
        conflicts_with = "human_secret"
    )]
    pub(crate) input: Option<PathBuf>,

    #[arg(short = 'n', long = "name", value_name = "NAME", action = ArgAction::Append, required = true)]
    pub(crate) agent_names: Vec<String>,

    #[arg(long = "prefix", value_name = "PATH", default_value = "agent_keys")]
    pub(crate) prefix: String,

    #[arg(long = "human-did-key", value_name = "SECRET")]
    pub(crate) human_did_key: Option<String>,

    #[arg(long = "out-dir", value_name = "DIR")]
    pub(crate) out_dir: Option<PathBuf>,
}

#[derive(Parser, Debug)]
#[command(name = "verify-agent-identity", about = "Verify an agent identity is derived from a human identity source")]
pub(crate) struct VerifyAgentIdentityArgs {
    #[arg(long = "source", value_enum, default_value = "gpg")]
    pub(crate) source: HumanIdentitySource,

    #[arg(
        short = 's',
        long = "human-secret",
        value_name = "SECRET",
        required_unless_present = "input",
        conflicts_with = "input"
    )]
    pub(crate) human_secret: Option<String>,

    #[arg(
        short = 'i',
        long = "in",
        value_name = "FILE",
        required_unless_present = "human_secret",
        conflicts_with = "human_secret"
    )]
    pub(crate) input: Option<PathBuf>,

    #[arg(short = 'n', long = "name", value_name = "NAME")]
    pub(crate) agent_name: String,

    #[arg(long = "prefix", value_name = "PATH", default_value = "agent_keys")]
    pub(crate) prefix: String,

    #[arg(long = "public-key-key", value_name = "SECRET")]
    pub(crate) public_key_key: Option<String>,

    #[arg(long = "did-key", value_name = "SECRET")]
    pub(crate) did_key: Option<String>,

    #[arg(long = "human-did-key", value_name = "SECRET")]
    pub(crate) human_did_key: Option<String>,

    #[arg(long = "require-human-binding", action = ArgAction::SetTrue)]
    pub(crate) require_human_binding: bool,
}

#[derive(Parser, Debug)]
#[command(name = "put-key", about = "Store an OpenPGP key in the SHADI secret store")]
pub(crate) struct PutKeyArgs {
    #[arg(short = 'k', long = "key", value_name = "SECRET")]
    pub(crate) key: String,

    #[arg(short = 'i', long = "in", value_name = "FILE")]
    pub(crate) input: PathBuf,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub(crate) struct PolicyFile {
    #[serde(default)]
    pub(crate) allow: Vec<String>,
    #[serde(default)]
    pub(crate) read: Vec<String>,
    #[serde(default)]
    pub(crate) write: Vec<String>,
    #[serde(default)]
    pub(crate) net_block: Option<bool>,
    #[serde(default)]
    pub(crate) net_allow: Vec<String>,
    #[serde(default)]
    pub(crate) allow_command: Vec<String>,
    #[serde(default)]
    pub(crate) block_command: Vec<String>,
    #[serde(default)]
    pub(crate) process_inject_keychain: Vec<ProcessInjectKeychainRule>,
    #[serde(default)]
    pub(crate) process_trusted_secret: Vec<ProcessTrustedSecretRule>,
    #[serde(default)]
    pub(crate) process_secret_policy: Vec<ProcessSecretPolicyRule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum SecretAction {
    Disclose,
    Use,
    DelegateToChild,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub(crate) struct ProcessSecretPolicyRule {
    pub(crate) program: String,
    pub(crate) secret: String,
    #[serde(default)]
    pub(crate) actions: Vec<SecretAction>,
    #[serde(default)]
    pub(crate) children: Vec<String>,
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) fd_env: Option<String>,
    #[serde(default)]
    pub(crate) child_sha256: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub(crate) struct ProcessInjectKeychainRule {
    pub(crate) program: String,
    pub(crate) key: String,
    pub(crate) env: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub(crate) struct ProcessTrustedSecretRule {
    pub(crate) program: String,
    pub(crate) key: String,
    pub(crate) name: String,
    pub(crate) fd_env: String,
    #[serde(default)]
    pub(crate) exec_sha256: Option<String>,
}

#[derive(Debug)]
pub(crate) struct ResolvedPolicy {
    pub(crate) policy: SandboxPolicy,
    pub(crate) blocked: HashSet<String>,
    pub(crate) allow: HashSet<String>,
}
