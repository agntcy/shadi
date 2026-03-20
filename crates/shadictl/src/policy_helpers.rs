use super::*;
use shadi_sandbox::PlatformSandboxProfile;

pub(crate) fn format_policy(
    policy: &SandboxPolicy,
    blocked: &HashSet<String>,
    allow: &HashSet<String>,
) -> Result<String, String> {
    #[derive(serde::Serialize)]
    struct PolicyDump {
        allow: Vec<String>,
        read: Vec<String>,
        write: Vec<String>,
        net_block: bool,
        platform_profile: String,
        allow_command: Vec<String>,
        block_command: Vec<String>,
    }

    let allow_paths = policy
        .allow_read()
        .iter()
        .filter(|path| policy.allow_write().iter().any(|write| write == *path))
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>();
    let read_paths = policy
        .allow_read()
        .iter()
        .filter(|path| !policy.allow_write().iter().any(|write| write == *path))
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>();
    let write_paths = policy
        .allow_write()
        .iter()
        .filter(|path| !policy.allow_read().iter().any(|read| read == *path))
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>();
    let mut blocked_list = blocked.iter().cloned().collect::<Vec<_>>();
    blocked_list.sort();
    let mut allow_list = allow.iter().cloned().collect::<Vec<_>>();
    allow_list.sort();

    let dump = PolicyDump {
        allow: allow_paths,
        read: read_paths,
        write: write_paths,
        net_block: policy.net_blocked(),
        platform_profile: match policy.platform_profile() {
            PlatformSandboxProfile::Compatibility => "compatibility".to_string(),
            PlatformSandboxProfile::Minimal => "minimal".to_string(),
        },
        allow_command: allow_list,
        block_command: blocked_list,
    };

    serde_json::to_string_pretty(&dump).map_err(|err| err.to_string())
}

pub(crate) fn resolve_policy(cli: &Cli, file_policy: &PolicyFile) -> Result<ResolvedPolicy, String> {
    let mut blocked = default_blocked_commands()
        .into_iter()
        .map(|cmd| cmd.to_string())
        .collect::<HashSet<_>>();
    for cmd in file_policy.block_command.iter() {
        blocked.insert(cmd.to_string());
    }

    let mut allow = file_policy
        .allow_command
        .iter()
        .map(|cmd| cmd.to_string())
        .collect::<HashSet<_>>();
    for cmd in cli.allow_command.iter() {
        allow.insert(cmd.to_string());
    }

    let profile_name = match cli.profile.unwrap_or(LauncherProfile::Balanced) {
        LauncherProfile::Strict => "strict",
        LauncherProfile::Balanced => "balanced",
        LauncherProfile::Connected => "connected",
    };
    let span = info_span!(
        "shadi.policy.resolve",
        policy.allowed_paths = field::Empty,
        network.mode = field::Empty,
        policy.profile = %profile_name,
    );
    let _guard = span.enter();

    let profile = profile_defaults(cli.profile);
    let profile_net_block = profile.net_block.unwrap_or(false);
    let mut policy = SandboxPolicy::new()
        .block_network(cli.net_block || file_policy.net_block.unwrap_or(profile_net_block));

    #[cfg(target_os = "macos")]
    {
        policy = policy.use_minimal_platform_profile();
    }

    policy = apply_string_paths(policy, &profile.read, PathMode::Read)?;
    policy = apply_string_paths(policy, &profile.write, PathMode::Write)?;
    policy = apply_string_paths(policy, &profile.allow, PathMode::Allow)?;

    policy = apply_string_paths(policy, &file_policy.read, PathMode::Read)?;
    policy = apply_string_paths(policy, &file_policy.write, PathMode::Write)?;
    policy = apply_string_paths(policy, &file_policy.allow, PathMode::Allow)?;

    policy = apply_paths(policy, &cli.read, PathMode::Read)?;
    policy = apply_paths(policy, &cli.write, PathMode::Write)?;
    policy = apply_paths(policy, &cli.allow, PathMode::Allow)?;

    let mut allowed_paths = BTreeSet::new();
    allowed_paths.extend(policy.allow_read().iter().cloned());
    allowed_paths.extend(policy.allow_write().iter().cloned());
    span.record("policy.allowed_paths", &(allowed_paths.len() as i64));
    let network_mode = if policy.net_blocked() { "blocked" } else { "allowed" };
    span.record("network.mode", &field::display(network_mode));

    Ok(ResolvedPolicy {
        policy,
        blocked,
        allow,
    })
}

pub(crate) fn profile_defaults(profile: Option<LauncherProfile>) -> PolicyFile {
    match profile.unwrap_or(LauncherProfile::Balanced) {
        LauncherProfile::Strict => PolicyFile {
            allow: vec![".".to_string()],
            read: vec![".".to_string()],
            write: Vec::new(),
            net_block: Some(true),
            allow_command: Vec::new(),
            block_command: Vec::new(),
            process_inject_keychain: Vec::new(),
            process_trusted_secret: Vec::new(),
            process_secret_policy: Vec::new(),
        },
        LauncherProfile::Balanced => PolicyFile {
            allow: vec![".".to_string()],
            #[cfg(target_os = "macos")]
            read: Vec::new(),
            #[cfg(not(target_os = "macos"))]
            read: vec!["/".to_string()],
            write: Vec::new(),
            net_block: Some(true),
            allow_command: Vec::new(),
            block_command: Vec::new(),
            process_inject_keychain: Vec::new(),
            process_trusted_secret: Vec::new(),
            process_secret_policy: Vec::new(),
        },
        LauncherProfile::Connected => PolicyFile {
            allow: vec![".".to_string()],
            #[cfg(target_os = "macos")]
            read: Vec::new(),
            #[cfg(not(target_os = "macos"))]
            read: vec!["/".to_string()],
            write: Vec::new(),
            net_block: Some(false),
            allow_command: Vec::new(),
            block_command: Vec::new(),
            process_inject_keychain: Vec::new(),
            process_trusted_secret: Vec::new(),
            process_secret_policy: Vec::new(),
        },
    }
}

pub(crate) fn is_command_blocked(
    cmd: &str,
    blocked: &HashSet<String>,
    allow: &HashSet<String>,
) -> bool {
    blocked.contains(cmd) && !allow.contains(cmd)
}

enum PathMode {
    Read,
    Write,
    Allow,
}

fn apply_string_paths(
    mut policy: SandboxPolicy,
    paths: &[String],
    mode: PathMode,
) -> Result<SandboxPolicy, String> {
    for path in paths.iter() {
        let path = canonicalize_string_path(path)
            .map_err(|err| format!("invalid {} path {}: {}", mode.label(), path, err))?;
        policy = apply_path(policy, &path, &mode);
    }
    Ok(policy)
}

fn apply_paths(
    mut policy: SandboxPolicy,
    paths: &[PathBuf],
    mode: PathMode,
) -> Result<SandboxPolicy, String> {
    for path in paths.iter() {
        let path = canonicalize_path(path)
            .map_err(|err| format!("invalid {} path {}: {}", mode.label(), path.display(), err))?;
        policy = apply_path(policy, &path, &mode);
    }
    Ok(policy)
}

fn apply_path(mut policy: SandboxPolicy, path: &PathBuf, mode: &PathMode) -> SandboxPolicy {
    match mode {
        PathMode::Read => policy = policy.allow_read_path(path),
        PathMode::Write => policy = policy.allow_write_path(path),
        PathMode::Allow => policy = policy.allow_read_path(path).allow_write_path(path),
    }
    policy
}

impl PathMode {
    fn label(&self) -> &'static str {
        match self {
            PathMode::Read => "read",
            PathMode::Write => "write",
            PathMode::Allow => "allow",
        }
    }
}

pub(crate) fn list_keychain(prefix: Option<&str>) -> Result<(), String> {
    let store = default_secret_store();
    let keys = list_keychain_with_store(store.as_ref(), prefix)?;
    for key in keys {
        println!("{}", key);
    }
    Ok(())
}

pub(crate) fn list_keychain_with_store(
    store: &dyn SecretStore,
    prefix: Option<&str>,
) -> Result<Vec<String>, String> {
    let mut keys = store.list_keys().map_err(|err| err.to_string())?;
    if let Some(prefix) = prefix {
        keys.retain(|key| key.starts_with(prefix));
    }
    keys.sort();
    Ok(keys)
}

pub(crate) fn canonicalize_path(path: &PathBuf) -> std::io::Result<PathBuf> {
    std::fs::canonicalize(path)
}

pub(crate) fn canonicalize_string_path(path: &str) -> std::io::Result<PathBuf> {
    std::fs::canonicalize(Path::new(path))
}

pub(crate) fn load_policy_file(path: &Path) -> std::io::Result<PolicyFile> {
    let span = info_span!("shadi.policy.load", policy.source = %path.display());
    let _guard = span.enter();
    let data = std::fs::read_to_string(path)?;
    serde_json::from_str(&data)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
}

pub(crate) fn inject_keychain_secrets(command: &mut Command, mappings: &[String]) -> Result<(), String> {
    if mappings.is_empty() {
        return Ok(());
    }

    let span = info_span!("shadi.secrets.inject", secret.count = mappings.len() as i64);
    let _guard = span.enter();
    let store = default_secret_store();
    inject_keychain_with_store(store.as_ref(), command, mappings)
}

pub(crate) fn inject_keychain_with_store(
    store: &dyn SecretStore,
    command: &mut Command,
    mappings: &[String],
) -> Result<(), String> {
    for mapping in mappings {
        let (key, env) = parse_key_env(mapping)?;
        let secret = store
            .get(key)
            .map_err(|_| format!("keychain lookup failed for {}", key))?;
        let value = secret.expose(|bytes| bytes.to_vec());
        let value = secret_bytes_to_utf8(&value)?;
        command.env(env, value);
    }

    Ok(())
}

pub(crate) fn secret_bytes_to_utf8(value: &[u8]) -> Result<String, String> {
    String::from_utf8(value.to_vec()).map_err(|_| "secret is not utf-8".to_string())
}

pub(crate) fn parse_key_env(value: &str) -> Result<(&str, &str), String> {
    let mut parts = value.splitn(2, '=');
    let key = parts.next().unwrap_or("");
    let env = parts.next().unwrap_or("");
    if key.is_empty() || env.is_empty() {
        return Err("inject-keychain must be in KEY=ENV format".to_string());
    }
    Ok((key, env))
}

pub(crate) fn default_blocked_commands() -> HashSet<&'static str> {
    [
        "rm",
        "rmdir",
        "shred",
        "srm",
        "dd",
        "mkfs",
        "fdisk",
        "parted",
        "wipefs",
        "chmod",
        "chown",
        "chgrp",
        "chattr",
        "shutdown",
        "reboot",
        "halt",
        "systemctl",
        "apt",
        "brew",
        "pip",
        "yum",
        "pacman",
        "mv",
        "cp",
        "truncate",
        "sudo",
        "su",
        "doas",
        "pkexec",
        "scp",
        "rsync",
        "sftp",
        "ftp",
    ]
    .into_iter()
    .collect()
}
