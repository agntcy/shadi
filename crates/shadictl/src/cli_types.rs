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

    #[arg(long = "slim-channel", value_name = "NAME")]
    pub(crate) slim_channel: Option<String>,

    #[arg(long = "slim-destination", value_name = "NAME")]
    pub(crate) slim_destination: Option<String>,

    #[arg(long = "slim-timeout", value_name = "SECONDS")]
    pub(crate) slim_timeout: Option<u64>,

    #[arg(long = "slim-payload-type", value_name = "TYPE")]
    pub(crate) slim_payload_type: Option<String>,

    #[arg(long = "slim-allow-empty", action = ArgAction::SetTrue)]
    pub(crate) slim_allow_empty: bool,

    /// Human-readable name for this sandbox session.
    /// When set, the control socket is created at
    /// `$TMPDIR/shadi-ctl-<name>.sock` instead of
    /// `$TMPDIR/shadi-ctl-<pid>.sock`, making it easy to
    /// attach by name: `/attach <name>`.
    /// Allowed characters: letters, digits, hyphens, underscores.
    #[arg(long = "name", value_name = "NAME")]
    pub(crate) session_name: Option<String>,

    /// OASF record reference for session provenance tracking.
    /// When set, the record reference is printed to stderr on session start
    /// to establish a verifiable link between this sandbox session and the
    /// agent's published record in the AGNTCY Agent Directory.
    /// Format: CID, name, name:version, or name:version@cid.
    /// Example: `cisco.com/agent:v1.0.0@bafyreib...`
    #[arg(long = "record", value_name = "REF")]
    pub(crate) record_ref: Option<String>,

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
    #[command(name = "did-from-ssh")]
    DidFromSsh(DidFromSshArgs),
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
    #[command(name = "slim")]
    Slim(SlimCli),
    /// Interactive terminal for managing SHADI sandbox sessions
    #[command(name = "shell")]
    Shell(ShellArgs),
    /// Interact with the AGNTCY Agent Directory via dirctl
    #[command(name = "dir")]
    Dir(DirCli),
}

#[derive(Parser, Debug)]
#[command(name = "dir", about = "Interact with the AGNTCY Agent Directory (requires dirctl)")]
pub(crate) struct DirCli {
    /// GitHub token (PAT or OAuth) for authenticating to the AGNTCY Agent Directory.
    /// For CI: pass a PAT or the GitHub Actions token.
    /// For interactive dev use, run `shadictl dir login` once (token cached by dirctl).
    /// Using the SHADI secret store (via --token-key) is preferred over passing this flag
    /// directly, because it keeps the token out of shell history and process listings.
    /// Also read from $DIRECTORY_CLIENT_GITHUB_TOKEN (the native dirctl env var).
    #[arg(long = "gh-token", value_name = "TOKEN", env = "DIRECTORY_CLIENT_GITHUB_TOKEN")]
    pub(crate) gh_token: Option<String>,

    /// SHADI secret store key that holds the directory auth token.
    /// Populate with: `shadictl dir login` or `shadictl put-secret --key dir/gh_token`
    /// Ignored when --gh-token / $DIRECTORY_CLIENT_GITHUB_TOKEN is set.
    #[arg(long = "token-key", value_name = "KEY", default_value = "dir/gh_token")]
    pub(crate) token_key: String,

    #[command(subcommand)]
    pub(crate) command: DirCommand,
}

#[derive(Parser, Debug)]
#[command(name = "slim", about = "Native SLIM operations managed by SHADI")]
pub(crate) struct SlimCli {
    #[command(subcommand)]
    pub(crate) command: SlimCommand,
}

#[derive(Subcommand, Debug)]
pub(crate) enum SlimCommand {
    #[command(name = "start-node", about = "Run the local native SLIM node until interrupted")]
    StartNode,
    #[command(
        name = "a2a-echo-peer",
        about = "Serve a task-backed A2A peer over SLIMRPC until one request or timeout"
    )]
    A2AEchoPeer(SlimA2AEchoPeerArgs),
    #[command(
        name = "a2a-send",
        about = "Send a unary or streaming A2A request over SLIMRPC"
    )]
    A2ASend(SlimA2ASendArgs),
    #[command(
        name = "a2a-collaborate",
        about = "Broadcast an A2A message to a SLIM group channel and listen for others' (Collaborate)"
    )]
    A2ACollaborate(SlimA2ACollaborateArgs),
    #[command(
        name = "controller",
        about = "Securely configure connections/routes on a SLIM node's controller endpoint"
    )]
    Controller {
        #[command(subcommand)]
        command: ControllerCommand,
    },
    #[command(
        name = "create-group",
        about = "Create a SLIM group with members resolved from Agent Directory discovery \
                 and/or named explicitly, then drop into the interactive shell as its moderator"
    )]
    CreateGroup(SlimCreateGroupArgs),
}

#[derive(Subcommand, Debug)]
pub(crate) enum ControllerCommand {
    #[command(
        about = "Push a ConfigurationCommand (connections/routes) to a controller endpoint"
    )]
    Connect(SlimControllerConnectArgs),
    #[command(name = "list-routes", about = "List routes known to a controller endpoint")]
    ListRoutes(SlimControllerListArgs),
    #[command(
        name = "list-connections",
        about = "List connections known to a controller endpoint"
    )]
    ListConnections(SlimControllerListArgs),
}

#[derive(clap::Args, Clone, Debug)]
pub(crate) struct SlimControllerConnectArgs {
    /// Controller endpoint to connect to (host:port) — the node's controller
    /// server, not its data-plane endpoint.
    #[arg(long, value_name = "ENDPOINT")]
    pub(crate) endpoint: String,

    /// Connection to create: <link_id>@<target-endpoint>. Repeatable.
    #[arg(long = "create-connection", value_name = "LINK_ID@ENDPOINT")]
    pub(crate) create_connection: Vec<String>,

    /// Link id of a connection to delete. Repeatable.
    #[arg(long = "delete-connection", value_name = "LINK_ID")]
    pub(crate) delete_connection: Vec<String>,

    /// Route (subscription) to set: <name>@<link_id>, name as org/ns/agent or
    /// org/ns/agent/id (id: an integer, a UUID, or NULL_COMPONENT). Repeatable.
    #[arg(long = "set-route", value_name = "NAME@LINK_ID")]
    pub(crate) set_route: Vec<String>,

    /// Route to delete: <name>@<link_id> (same name format as --set-route). Repeatable.
    #[arg(long = "delete-route", value_name = "NAME@LINK_ID")]
    pub(crate) delete_route: Vec<String>,

    #[arg(long, default_value_t = 10)]
    pub(crate) timeout_seconds: u64,
}

#[derive(clap::Args, Clone, Debug)]
pub(crate) struct SlimControllerListArgs {
    #[arg(long, value_name = "ENDPOINT")]
    pub(crate) endpoint: String,

    #[arg(long, default_value_t = 10)]
    pub(crate) timeout_seconds: u64,
}

#[derive(clap::Args, Clone, Debug)]
pub(crate) struct SlimA2AEchoPeerArgs {
    #[arg(long, env = "SLIM_ENDPOINT", value_name = "ENDPOINT")]
    pub(crate) endpoint: Option<String>,

    #[arg(long, env = "SHADI_AGENT_ID", default_value = "secops-a")]
    pub(crate) agent_id: String,

    #[arg(long, default_value_t = 20)]
    pub(crate) listen_timeout_seconds: u64,

    #[arg(long)]
    pub(crate) ready_file: Option<PathBuf>,

    #[arg(long, default_value_t = false)]
    pub(crate) start_local_node: bool,
}

#[derive(clap::Args, Clone, Debug)]
pub(crate) struct SlimA2ASendArgs {
    #[arg(long, env = "SLIM_ENDPOINT", value_name = "ENDPOINT")]
    pub(crate) endpoint: Option<String>,

    #[arg(long, env = "SHADI_AGENT_ID", default_value = "avatar")]
    pub(crate) agent_id: String,

    #[arg(long, default_value = "secops-a")]
    pub(crate) peer_agent_id: String,

    #[arg(long)]
    pub(crate) destination: Option<String>,

    #[arg(long, default_value = "hello from SHADI A2A")]
    pub(crate) message: String,

    #[arg(long, default_value_t = false)]
    pub(crate) stream: bool,

    #[arg(long, default_value_t = 20)]
    pub(crate) timeout_seconds: u64,

    #[arg(long, default_value = "shadictl-a2a-session")]
    pub(crate) session_id: String,
}

#[derive(clap::Args, Clone, Debug)]
pub(crate) struct SlimA2ACollaborateArgs {
    #[arg(long, env = "SLIM_ENDPOINT", value_name = "ENDPOINT")]
    pub(crate) endpoint: Option<String>,

    #[arg(long, env = "SHADI_AGENT_ID", default_value = "avatar")]
    pub(crate) agent_id: String,

    /// Comma-separated agent ids of the other group members.
    #[arg(long, value_name = "ID1,ID2,...")]
    pub(crate) peer_agent_ids: String,

    #[arg(long, default_value = "hello from SHADI A2A")]
    pub(crate) message: String,

    #[arg(long, default_value_t = 20)]
    pub(crate) timeout_seconds: u64,
}

#[derive(clap::Args, Clone, Debug)]
pub(crate) struct SlimCreateGroupArgs {
    /// Channel to create, e.g. agntcy/shadi/my-room.
    pub(crate) channel: String,

    /// Member source spec, repeatable: skill:<skill> | did:<did> |
    /// explicit:<name>=<did>[@<endpoint>]. Resolved candidates' DIDs are
    /// unioned into this group's trust set (SLIM_MEMBER_DIDS) — resolving a
    /// candidate does not by itself invite it into the live session; use
    /// `/slim invite <name>` or `/slim invite-from <spec>` for that.
    #[arg(long = "members", value_name = "SPEC")]
    pub(crate) members: Vec<String>,

    /// Agent Directory server address (used by skill:/did: member specs).
    #[arg(long, default_value = "prod.gateway.ads.outshift.io:443")]
    pub(crate) dir_server: String,

    /// GitHub token for DIR authentication (or set DIRECTORY_CLIENT_GITHUB_TOKEN).
    #[arg(long)]
    pub(crate) gh_token: Option<String>,

    /// Max results per resolved skill:/did: member source.
    #[arg(long, default_value_t = 20)]
    pub(crate) limit: usize,

    /// Write the resolved trust set as a slim_mas GroupConfig TOML file, so
    /// `shadictl slim-mas --config <path> list-members/validate` can audit it.
    #[arg(long, value_name = "PATH")]
    pub(crate) write_config: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub(crate) enum DirCommand {
    /// Authenticate with the Agent Directory and cache the token in the SHADI
    /// secret store.  Run once before using pull / info / search.
    #[command(name = "login")]
    Login(DirLoginArgs),
    /// Fetch an OASF agent record from the directory and cache it locally
    #[command(name = "pull")]
    Pull(DirPullArgs),
    /// Display metadata about an OASF agent record
    #[command(name = "info")]
    Info(DirInfoArgs),
    /// Search the directory for agent records by skill
    #[command(name = "search")]
    Search(DirSearchArgs),
    /// Verify the Sigstore signature of a record already in the directory
    #[command(name = "verify")]
    Verify(DirVerifyArgs),
}

#[derive(Parser, Debug)]
#[command(name = "login",
    about = "Authenticate with the Agent Directory via GitHub OAuth and ingest the token into the SHADI secret store",
    long_about = "Runs `dirctl auth login` (GitHub OAuth browser flow), then reads the resulting \
        access token from dirctl's local cache and writes it into the SHADI secret store at \
        --token-key (default: dir/gh_token). Subsequent `shadictl dir` commands pick it up \
        automatically.")]
pub(crate) struct DirLoginArgs {
    /// Show the authorization URL for manual opening instead of launching a browser.
    /// Use this in SSH/headless environments.
    #[arg(long = "no-browser", action = ArgAction::SetTrue)]
    pub(crate) no_browser: bool,

    /// Force re-authentication even if a valid cached token already exists.
    #[arg(long = "force", action = ArgAction::SetTrue)]
    pub(crate) force: bool,
}

#[derive(Parser, Debug)]
#[command(name = "pull", about = "Fetch an OASF record and cache it in ~/.shadi/records/")]
pub(crate) struct DirPullArgs {
    /// Record reference: CID, name, name:version, or name:version@cid
    pub(crate) reference: String,
    /// Directory server address (overrides $DIRECTORY_CLIENT_SERVER_ADDRESS)
    #[arg(long = "server-addr", value_name = "ADDR", env = "DIRECTORY_CLIENT_SERVER_ADDRESS",
          default_value = "prod.gateway.ads.outshift.io:443")]
    pub(crate) server_addr: String,
}

#[derive(Parser, Debug)]
#[command(
    name = "verify",
    about = "Verify the Sigstore signature of a record (delegates to dirctl verify)",
    long_about = "Calls `dirctl verify <CID>` to verify the Sigstore/cosign signature of an \n\
        OASF record already present in the directory.  Verification is performed locally \n\
        by default (sigstore TUF root + Rekor transparency log).  Use --oidc-issuer / \n\
        --oidc-subject to pin the signing identity, or --key to verify against a specific \n\
        public key.  Use --from-server to rely on the server's cached result instead.")]
pub(crate) struct DirVerifyArgs {
    /// Record CID to verify (e.g. bafkrei...).
    /// Obtain this from `dirctl pull <ref> --output json` or from the `dirctl search` output.
    pub(crate) cid: String,

    /// Public key to verify against (PEM file path, HTTPS URL, or KMS URI).
    /// When omitted, any valid Sigstore OIDC-based signature is accepted.
    #[arg(long = "key", value_name = "KEY")]
    pub(crate) key: Option<String>,

    /// OIDC issuer URL the signing identity must have been issued by.
    /// Accepts a literal URL or a regexp (cosign-compatible).
    /// Example: `https://token.actions.githubusercontent.com`
    #[arg(long = "oidc-issuer", value_name = "URL")]
    pub(crate) oidc_issuer: Option<String>,

    /// OIDC subject (identity) the signature must have been created with.
    /// Accepts a literal email/identity or a regexp.
    /// Example: `alice@example.com`
    #[arg(long = "oidc-subject", value_name = "IDENTITY")]
    pub(crate) oidc_subject: Option<String>,

    /// Use the server's cached verification result instead of performing local
    /// Sigstore verification.  Faster but trusts the directory server's judgement.
    #[arg(long = "from-server", action = ArgAction::SetTrue)]
    pub(crate) from_server: bool,

    /// Skip Rekor transparency log verification (useful in air-gapped environments).
    #[arg(long = "ignore-tlog", action = ArgAction::SetTrue)]
    pub(crate) ignore_tlog: bool,

    /// Path to a Sigstore TrustedRoot JSON file for fully offline verification.
    #[arg(long = "trusted-root-path", value_name = "FILE")]
    pub(crate) trusted_root_path: Option<PathBuf>,

    /// Directory server address (overrides $DIRECTORY_CLIENT_SERVER_ADDRESS).
    /// Needed to fetch the signature manifest from the directory.
    #[arg(long = "server-addr", value_name = "ADDR", env = "DIRECTORY_CLIENT_SERVER_ADDRESS",
          default_value = "prod.gateway.ads.outshift.io:443")]
    pub(crate) server_addr: String,
}

#[derive(Parser, Debug)]
#[command(name = "info", about = "Show metadata for an OASF record")]
pub(crate) struct DirInfoArgs {
    /// Record reference: CID, name, name:version, or name:version@cid
    pub(crate) reference: String,
    /// Directory server address (overrides $DIRECTORY_CLIENT_SERVER_ADDRESS)
    #[arg(long = "server-addr", value_name = "ADDR", env = "DIRECTORY_CLIENT_SERVER_ADDRESS",
          default_value = "prod.gateway.ads.outshift.io:443")]
    pub(crate) server_addr: String,
}

#[derive(Parser, Debug)]
#[command(name = "search", about = "Search the directory for agent records by skill")]
pub(crate) struct DirSearchArgs {
    /// OASF skill name to search for (repeatable, e.g. natural_language_processing)
    #[arg(long = "skill", value_name = "SKILL", action = ArgAction::Append)]
    pub(crate) skill: Vec<String>,
    /// Maximum number of results to return
    #[arg(long = "limit", value_name = "N", default_value = "10")]
    pub(crate) limit: usize,
    /// Directory server address (overrides $DIRECTORY_CLIENT_SERVER_ADDRESS)
    #[arg(long = "server-addr", value_name = "ADDR", env = "DIRECTORY_CLIENT_SERVER_ADDRESS",
          default_value = "prod.gateway.ads.outshift.io:443")]
    pub(crate) server_addr: String,
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

    /// Connect to a running sandbox session to include live patched policy state.
    #[arg(long = "socket", value_name = "PATH")]
    pub(crate) socket: Option<PathBuf>,

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

    /// Hostname or IP to add to the network allowlist (e.g. `httping.org` or `1.1.1.1`).
    /// A URL scheme and path are accepted for convenience and stripped automatically,
    /// so `http://httping.org/ping` and `httping.org` are equivalent.
    #[arg(long = "add-net-allow", value_name = "HOST|URL", action = ArgAction::Append)]
    pub(crate) add_net_allow: Vec<String>,

    /// Hostname or IP to remove from the network allowlist (same stripping as --add-net-allow).
    #[arg(long = "remove-net-allow", value_name = "HOST|URL", action = ArgAction::Append)]
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

    /// Connect to a running sandbox session by its human-readable name
    /// (as given by --name when launching shadictl).
    /// Equivalent to --socket $TMPDIR/shadi-ctl-<name>.sock.
    #[arg(long = "attach", value_name = "NAME", conflicts_with = "socket")]
    pub(crate) attach: Option<String>,
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

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GitHubKeyType {
    /// `/users/<u>/gpg_keys`; needs GH_TOKEN and an Ed25519 GPG key.
    Gpg,
    /// `github.com/<u>.keys`; unauthenticated, picks the first ssh-ed25519 key.
    Ssh,
}

#[derive(Parser, Debug)]
#[command(
    name = "did-from-github",
    about = "Create did:key DID document from a public key published on GitHub"
)]
pub(crate) struct DidFromGitHubArgs {
    #[arg(long = "user", value_name = "USERNAME")]
    pub(crate) user: String,

    /// Which published key to read. `ssh` needs no token and is the only option
    /// that works when the account's GPG key is not Ed25519.
    #[arg(long = "key-type", value_enum, default_value = "gpg")]
    pub(crate) key_type: GitHubKeyType,

    #[arg(long = "out", value_name = "FILE")]
    pub(crate) out_file: Option<PathBuf>,
}

#[derive(Parser, Debug)]
#[command(
    name = "did-from-ssh",
    about = "Create did:key DID document from an SSH Ed25519 key (public line or private key)"
)]
pub(crate) struct DidFromSshArgs {
    /// Secret-store reference holding the key.
    #[arg(
        short = 'k',
        long = "key",
        value_name = "SECRET",
        required_unless_present = "input",
        conflicts_with = "input"
    )]
    pub(crate) key_ref: Option<String>,

    /// File holding the key. An `ssh-ed25519 AAAA...` line or an OpenSSH private
    /// key; which one it is is detected from the content.
    #[arg(
        short = 'i',
        long = "in",
        value_name = "FILE",
        required_unless_present = "key_ref",
        conflicts_with = "key_ref"
    )]
    pub(crate) input: Option<PathBuf>,

    /// Secret-store reference holding the passphrase, when the key is an
    /// encrypted private key. Never passed as a literal: an argument would be
    /// visible to anyone running `ps`. `SHADI_SSH_PASSPHRASE` is also honoured.
    #[arg(long = "passphrase-secret", value_name = "SECRET")]
    pub(crate) passphrase_secret: Option<String>,

    #[arg(short = 'o', long = "out", value_name = "FILE", default_value = "did-document.json")]
    pub(crate) out_file: PathBuf,
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
    /// An OpenSSH Ed25519 private key; its 32-byte seed is the HKDF root
    /// (agntcy/shadi#140).
    Ssh,
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


    /// Secret-store reference holding the SSH key passphrase (`--source ssh`
    /// with an encrypted key). Never a literal argument — that would be visible
    /// via `ps`. `SHADI_SSH_PASSPHRASE` is also honoured.
    #[arg(long = "ssh-passphrase-secret", value_name = "SECRET")]
    pub(crate) ssh_passphrase_secret: Option<String>,
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

    /// Secret-store reference holding the SSH key passphrase (`--source ssh`
    /// with an encrypted key). Never a literal argument — that would be visible
    /// via `ps`. `SHADI_SSH_PASSPHRASE` is also honoured.
    #[arg(long = "ssh-passphrase-secret", value_name = "SECRET")]
    pub(crate) ssh_passphrase_secret: Option<String>,

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
    /// Environment variables to remove from the child process after all
    /// injections (proxy vars, secrets).  Useful for runtimes that crash on
    /// proxy schemes they don't support (e.g. Node.js SEA with
    /// `HTTPS_PROXY=socks5h://`).
    #[serde(default)]
    pub(crate) env_remove: Vec<String>,
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

pub(crate) use shadi_sandbox::ResolvedPolicy;
