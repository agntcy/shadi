use super::*;
use shadi_sandbox::{PolicyFileValues, PolicyOverrides, SandboxProfile};

pub(crate) fn format_policy(
    policy: &SandboxPolicy,
    blocked: &HashSet<String>,
    allow: &HashSet<String>,
) -> Result<String, String> {
    let described = shadi_sandbox::describe_policy(policy, blocked, allow);
    serde_json::to_string_pretty(&described).map_err(|err| err.to_string())
}

/// Map this binary's `Cli` and `PolicyFile` onto the layering rules in
/// `shadi_sandbox::resolve`, which the desktop app resolves policy with too.
pub(crate) fn resolve_policy(cli: &Cli, file_policy: &PolicyFile) -> Result<ResolvedPolicy, String> {
    let overrides = PolicyOverrides {
        profile: cli.profile.map(|profile| match profile {
            LauncherProfile::Strict => SandboxProfile::Strict,
            LauncherProfile::Balanced => SandboxProfile::Balanced,
            LauncherProfile::Connected => SandboxProfile::Connected,
        }),
        allow: cli.allow.clone(),
        read: cli.read.clone(),
        write: cli.write.clone(),
        net_block: cli.net_block,
        net_allow: cli.net_allow.clone(),
        allow_command: cli.allow_command.clone(),
    };

    let file_values = PolicyFileValues {
        allow: file_policy.allow.clone(),
        read: file_policy.read.clone(),
        write: file_policy.write.clone(),
        net_block: file_policy.net_block,
        net_allow: file_policy.net_allow.clone(),
        allow_command: file_policy.allow_command.clone(),
        block_command: file_policy.block_command.clone(),
    };

    shadi_sandbox::resolve_policy(&overrides, &file_values)
}

pub(crate) fn profile_defaults(profile: Option<LauncherProfile>) -> PolicyFile {
    // The sandbox axes live in shadi_sandbox so the desktop panel gets the same
    // profiles without restating them; everything below them is empty in every
    // profile and stays here with the rest of the policy-file schema.
    let defaults = match profile.unwrap_or(LauncherProfile::Balanced) {
        LauncherProfile::Strict => SandboxProfile::Strict,
        LauncherProfile::Balanced => SandboxProfile::Balanced,
        LauncherProfile::Connected => SandboxProfile::Connected,
    }
    .defaults();

    PolicyFile {
        allow: defaults.allow,
        read: defaults.read,
        write: defaults.write,
        net_block: Some(defaults.net_block),
        net_allow: Vec::new(),
        allow_command: Vec::new(),
        block_command: Vec::new(),
        env_remove: Vec::new(),
        process_inject_keychain: Vec::new(),
        process_trusted_secret: Vec::new(),
        process_secret_policy: Vec::new(),
    }
}

pub(crate) use shadi_sandbox::is_command_blocked;

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

