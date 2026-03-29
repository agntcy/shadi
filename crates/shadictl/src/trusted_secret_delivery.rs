use super::*;

use agent_secrets::memory::SecretBytes;
use std::collections::{HashMap, HashSet};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(windows)]
use std::ffi::OsString;
use std::path::{Path, PathBuf};
#[cfg(all(test, unix))]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(unix)]
use std::thread;
#[cfg(unix)]
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};

#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    CloseHandle, SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
};
#[cfg(windows)]
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::WriteFile;
#[cfg(windows)]
use windows_sys::Win32::System::Pipes::CreatePipe;

const TRUSTED_SECRET_PROTOCOL_ENV: &str = "SHADI_TRUSTED_SECRET_PROTOCOL";
#[cfg(unix)]
const TRUSTED_SECRET_PROTOCOL_VALUE: &str = "pid-path-fetch-v3";
#[cfg(windows)]
const TRUSTED_SECRET_PROTOCOL_VALUE: &str = "consume-close-v1";

#[cfg(unix)]
const TRUSTED_SECRET_ENDPOINT_DIR_PREFIX: &str = ".shadi-trusted-secret";
#[cfg(unix)]
const TRUSTED_SECRET_ENDPOINT_FILE_NAME: &str = "secret.sock";
#[cfg(target_os = "macos")]
const TRUSTED_SECRET_ENDPOINT_ROOT: &str = "/private/tmp";
#[cfg(all(unix, not(target_os = "macos")))]
const TRUSTED_SECRET_ENDPOINT_ROOT: &str = "/tmp";
#[cfg(unix)]
const TRUSTED_SECRET_DELIVERY_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(unix)]
const TRUSTED_SECRET_DELIVERY_POLL_INTERVAL: Duration = Duration::from_millis(10);
#[cfg(unix)]
const TRUSTED_SECRET_NONCE_LEN: usize = 32;
#[cfg(unix)]
const TRUSTED_SECRET_NONCE_READ_TIMEOUT: Duration = Duration::from_millis(250);

#[cfg(all(test, unix))]
static TRUSTED_SECRET_TEST_COUNTER: AtomicU64 = AtomicU64::new(1);

#[cfg(windows)]
pub(crate) const TRUSTED_SECRET_WINDOWS_HANDLE_LIST_ENV: &str =
    "SHADI_INTERNAL_TRUSTED_SECRET_HANDLES";

#[derive(Debug)]
enum PreparedTrustedSecret {
    #[cfg(unix)]
    UnixBroker(UnixTrustedSecretBroker),
    #[cfg(windows)]
    Windows { read_handle: HANDLE },
}

#[cfg(unix)]
#[derive(Debug)]
struct UnixTrustedSecretBroker {
    name: String,
    kind: UnixTrustedSecretBrokerKind,
    socket_path: PathBuf,
    listener: Option<UnixListener>,
    nonce: String,
    payload: Option<SecretBytes>,
    temp_dir: PathBuf,
}

#[cfg(unix)]
#[derive(Debug)]
enum UnixTrustedSecretBrokerKind {
    Direct { expected_program: PathBuf },
    Delegated {
        allowed_children: Vec<DelegatedChildConstraint>,
        worker: Option<thread::JoinHandle<Result<(), String>>>,
    },
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct DelegatedChildConstraint {
    program: PathBuf,
    sha256: Option<[u8; 32]>,
}

#[derive(Debug, Default)]
pub(crate) struct PendingTrustedSecretDelivery {
    secrets: Vec<PreparedTrustedSecret>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct LaunchSecretConfig {
    pub(crate) inject_keychain: Vec<String>,
    pub(crate) trusted_secret: Vec<String>,
    pub(crate) trusted_secret_exec: Vec<String>,
    pub(crate) trusted_secret_fd_env: Vec<String>,
    pub(crate) process_secret_policy: Vec<ResolvedProcessSecretPolicyRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedProcessSecretPolicyRule {
    pub(crate) secret: String,
    pub(crate) actions: Vec<SecretAction>,
    pub(crate) children: Vec<PathBuf>,
    pub(crate) child_sha256: Vec<[u8; 32]>,
    pub(crate) name: Option<String>,
    pub(crate) fd_env: Option<String>,
}

impl PendingTrustedSecretDelivery {
    pub(crate) fn new(
        command: &mut Command,
        mappings: &[String],
        exec_mappings: &[String],
        fd_env_mappings: &[String],
        process_secret_policy: &[ResolvedProcessSecretPolicyRule],
    ) -> Result<Option<Self>, String> {
        let delegated_rules = process_secret_policy
            .iter()
            .filter(|rule| rule.actions.contains(&SecretAction::DelegateToChild))
            .collect::<Vec<_>>();

        if mappings.is_empty() && delegated_rules.is_empty() {
            return Ok(None);
        }

        #[cfg(unix)]
        {
            let command_path = resolve_command_path(command)?;
            reject_relay_executable(&command_path)?;
            let exec_map = parse_exec_mappings(exec_mappings)?;
            let fd_env_map = parse_name_mappings(
                fd_env_mappings,
                "trusted-secret-fd-env must be in NAME=ENV format",
            )?;

            let store = default_secret_store();
            let mut pending = Self::default();
            let mut seen_names = HashSet::new();
            command.env(TRUSTED_SECRET_PROTOCOL_ENV, TRUSTED_SECRET_PROTOCOL_VALUE);

            for mapping in mappings.iter() {
                let (key, name) = parse_key_name(mapping, "trusted-secret must be in KEY=NAME format")?;
                if !seen_names.insert(name.to_string()) {
                    return Err(format!(
                        "trusted secret '{}' is configured more than once",
                        name
                    ));
                }
                let exec_path = exec_map.get(name).ok_or_else(|| {
                    format!(
                        "trusted secret '{}' is missing a trusted-secret-exec mapping",
                        name
                    )
                })?;
                if *exec_path != command_path {
                    return Err(format!(
                        "trusted secret '{}' targets {}, but launched command resolves to {}",
                        name,
                        exec_path.display(),
                        command_path.display()
                    ));
                }

                let fd_env = fd_env_map.get(name).ok_or_else(|| {
                    format!(
                        "trusted secret '{}' is missing a trusted-secret-fd-env mapping",
                        name
                    )
                })?;

                let secret = store
                    .get(key)
                    .map_err(|_| format!("keychain lookup failed for {}", key))?;
                let broker = prepare_secret_broker(
                    command,
                    name,
                    fd_env,
                    secret,
                    UnixTrustedSecretBrokerKind::Direct {
                        expected_program: exec_path.to_path_buf(),
                    },
                )?;
                pending
                    .secrets
                    .push(PreparedTrustedSecret::UnixBroker(broker));
            }

            for rule in delegated_rules {
                let name = rule.name.as_ref().ok_or_else(|| {
                    format!(
                        "process secret policy for '{}' uses delegate-to-child but does not declare a name",
                        rule.secret
                    )
                })?;
                if !seen_names.insert(name.clone()) {
                    return Err(format!(
                        "trusted secret '{}' is configured more than once",
                        name
                    ));
                }

                let fd_env = rule.fd_env.as_ref().ok_or_else(|| {
                    format!(
                        "process secret policy for '{}' uses delegate-to-child but does not declare fd_env",
                        rule.secret
                    )
                })?;

                for child in &rule.children {
                    reject_relay_executable(child)?;
                }

                let secret = store
                    .get(&rule.secret)
                    .map_err(|_| format!("keychain lookup failed for {}", rule.secret))?;
                let allowed_children = rule
                    .children
                    .iter()
                    .enumerate()
                    .map(|(index, child)| DelegatedChildConstraint {
                        program: child.clone(),
                        sha256: if rule.child_sha256.is_empty() {
                            None
                        } else {
                            Some(rule.child_sha256[index])
                        },
                    })
                    .collect();
                let broker = prepare_secret_broker(
                    command,
                    name,
                    fd_env,
                    secret,
                    UnixTrustedSecretBrokerKind::Delegated {
                        allowed_children,
                        worker: None,
                    },
                )?;
                pending
                    .secrets
                    .push(PreparedTrustedSecret::UnixBroker(broker));
            }

            Ok(Some(pending))
        }

        #[cfg(windows)]
        {
            let command_path = resolve_command_path(command)?;
            reject_relay_executable(&command_path)?;
            let exec_map = parse_exec_mappings(exec_mappings)?;
            let fd_env_map = parse_name_mappings(
                fd_env_mappings,
                "trusted-secret-fd-env must be in NAME=ENV format",
            )?;

            let store = default_secret_store();
            let mut pending = Self::default();
            let mut inherited_handles = Vec::new();
            let mut seen_names = HashSet::new();
            command.env(TRUSTED_SECRET_PROTOCOL_ENV, TRUSTED_SECRET_PROTOCOL_VALUE);

            for mapping in mappings {
                let (key, name) = parse_key_name(mapping, "trusted-secret must be in KEY=NAME format")?;
                if !seen_names.insert(name.to_string()) {
                    return Err(format!(
                        "trusted secret '{}' is configured more than once",
                        name
                    ));
                }
                let exec_path = exec_map.get(name).ok_or_else(|| {
                    format!(
                        "trusted secret '{}' is missing a trusted-secret-exec mapping",
                        name
                    )
                })?;
                if *exec_path != command_path {
                    return Err(format!(
                        "trusted secret '{}' targets {}, but launched command resolves to {}",
                        name,
                        exec_path.display(),
                        command_path.display()
                    ));
                }

                let fd_env = fd_env_map.get(name).ok_or_else(|| {
                    format!(
                        "trusted secret '{}' is missing a trusted-secret-fd-env mapping",
                        name
                    )
                })?;

                let secret = store
                    .get(key)
                    .map_err(|_| format!("keychain lookup failed for {}", key))?;
                let read_handle = prepare_secret_handle(secret)?;
                command.env(fd_env, (read_handle as usize).to_string());
                inherited_handles.push((read_handle as usize).to_string());
                pending
                    .secrets
                    .push(PreparedTrustedSecret::Windows { read_handle });
            }

            if !inherited_handles.is_empty() {
                command.env(
                    TRUSTED_SECRET_WINDOWS_HANDLE_LIST_ENV,
                    inherited_handles.join(","),
                );
            }

            Ok(Some(pending))
        }
    }

    pub(crate) fn close_parent_fds(&mut self) {
        for prepared in &mut self.secrets {
            #[cfg(unix)]
            {
                let PreparedTrustedSecret::UnixBroker(broker) = prepared;
                if let UnixTrustedSecretBrokerKind::Delegated { worker, .. } = &mut broker.kind {
                    if let Some(handle) = worker.take() {
                        let _ = handle.join();
                    }
                }
                let _ = std::fs::remove_file(&broker.socket_path);
                if broker.temp_dir.exists() {
                    let _ = std::fs::remove_dir_all(&broker.temp_dir);
                }
            }

            #[cfg(windows)]
            {
                let PreparedTrustedSecret::Windows { read_handle } = prepared;
                if !read_handle.is_null() && *read_handle != INVALID_HANDLE_VALUE {
                    unsafe {
                        CloseHandle(*read_handle);
                    }
                    *read_handle = std::ptr::null_mut();
                }
            }
        }
    }

    #[cfg_attr(not(unix), allow(unused_variables))]
    pub(crate) fn deliver_after_spawn(&mut self, child_pid: u32) -> Result<(), String> {
        #[cfg(unix)]
        {
            for prepared in &mut self.secrets {
                let PreparedTrustedSecret::UnixBroker(broker) = prepared;
                let direct_expected_program = match &broker.kind {
                    UnixTrustedSecretBrokerKind::Direct { expected_program } => {
                        Some(expected_program.clone())
                    }
                    UnixTrustedSecretBrokerKind::Delegated { .. } => None,
                };

                if let Some(expected_program) = direct_expected_program {
                    deliver_secret_to_process(broker, child_pid, &expected_program)?;
                    continue;
                }

                let delegated_allowed_children = match &broker.kind {
                    UnixTrustedSecretBrokerKind::Delegated { allowed_children, .. } => {
                        Some(allowed_children.clone())
                    }
                    UnixTrustedSecretBrokerKind::Direct { .. } => None,
                };

                if let Some(allowed_children) = delegated_allowed_children {
                    let thread = start_delegated_secret_delivery(broker, child_pid, allowed_children)?;
                    if let UnixTrustedSecretBrokerKind::Delegated { worker, .. } = &mut broker.kind {
                        *worker = Some(thread);
                    }
                }
            }
        }

        Ok(())
    }

    pub(crate) fn wait_for_background_delivery(&mut self) -> Result<(), String> {
        #[cfg(unix)]
        {
            for prepared in &mut self.secrets {
                let PreparedTrustedSecret::UnixBroker(broker) = prepared;
                if let UnixTrustedSecretBrokerKind::Delegated { worker, .. } = &mut broker.kind {
                    if let Some(handle) = worker.take() {
                        match handle.join() {
                            Ok(result) => result?,
                            Err(_) => return Err("trusted secret delivery worker panicked".to_string()),
                        }
                    }
                }
            }
        }

        Ok(())
    }

    pub(crate) fn endpoint_paths(&self) -> Vec<PathBuf> {
        let paths = Vec::new();
        #[cfg(unix)]
        let mut paths = paths;
        #[cfg(unix)]
        {
            for prepared in &self.secrets {
                let PreparedTrustedSecret::UnixBroker(broker) = prepared;
                paths.push(broker.temp_dir.clone());
            }
        }
        paths
    }
}

impl Drop for PendingTrustedSecretDelivery {
    fn drop(&mut self) {
        self.close_parent_fds();
    }
}

pub(crate) fn resolve_launch_secret_config(
    command: &Command,
    cli: &Cli,
    file_policy: &PolicyFile,
) -> Result<LaunchSecretConfig, String> {
    let command_path = resolve_command_path(command)?;
    let mut resolved = LaunchSecretConfig {
        inject_keychain: cli.inject_keychain.clone(),
        trusted_secret: cli.trusted_secret.clone(),
        trusted_secret_exec: cli.trusted_secret_exec.clone(),
        trusted_secret_fd_env: cli.trusted_secret_fd_env.clone(),
        process_secret_policy: Vec::new(),
    };

    for rule in &file_policy.process_inject_keychain {
        let rule_program = canonicalize_policy_program(&rule.program, command)?;
        if rule_program == command_path {
            resolved
                .inject_keychain
                .push(format!("{}={}", rule.key, rule.env));
        }
    }

    for rule in &file_policy.process_trusted_secret {
        let rule_program = canonicalize_policy_program(&rule.program, command)?;
        if rule_program == command_path {
            if let Some(expected_hex) = &rule.exec_sha256 {
                let expected = parse_sha256_hex(expected_hex).map_err(|err| {
                    format!(
                        "process trusted secret '{}' has invalid exec_sha256: {}",
                        rule.name, err
                    )
                })?;
                let actual = compute_file_sha256(&rule_program).map_err(|err| {
                    format!(
                        "process trusted secret '{}' executable could not be hashed: {}",
                        rule.name, err
                    )
                })?;
                if actual != expected {
                    return Err(format!(
                        "process trusted secret '{}' exec_sha256 does not match current executable",
                        rule.name
                    ));
                }
            }

            resolved
                .trusted_secret
                .push(format!("{}={}", rule.key, rule.name));
            resolved
                .trusted_secret_exec
                .push(format!("{}={}", rule.name, rule_program.display()));
            resolved
                .trusted_secret_fd_env
                .push(format!("{}={}", rule.name, rule.fd_env));
        }
    }

    for rule in &file_policy.process_secret_policy {
        let rule_program = canonicalize_policy_program(&rule.program, command)?;
        if rule_program != command_path {
            continue;
        }

        if rule.actions.is_empty() {
            return Err(format!(
                "process secret policy for '{}' must declare at least one action",
                rule.secret
            ));
        }

        if rule.actions.contains(&SecretAction::DelegateToChild) && rule.children.is_empty() {
            return Err(format!(
                "process secret policy for '{}' uses delegate-to-child but does not declare any children",
                rule.secret
            ));
        }

        if !rule.child_sha256.is_empty() && rule.child_sha256.len() != rule.children.len() {
            return Err(format!(
                "process secret policy for '{}' declares {} child sha256 values for {} children",
                rule.secret,
                rule.child_sha256.len(),
                rule.children.len()
            ));
        }

        if rule.actions.contains(&SecretAction::DelegateToChild)
            && rule.name.as_deref().unwrap_or("").is_empty()
        {
            return Err(format!(
                "process secret policy for '{}' uses delegate-to-child but does not declare a name",
                rule.secret
            ));
        }

        if rule.actions.contains(&SecretAction::DelegateToChild)
            && rule.fd_env.as_deref().unwrap_or("").is_empty()
        {
            return Err(format!(
                "process secret policy for '{}' uses delegate-to-child but does not declare fd_env",
                rule.secret
            ));
        }

        if !rule.actions.contains(&SecretAction::DelegateToChild) && !rule.children.is_empty() {
            return Err(format!(
                "process secret policy for '{}' declares children without delegate-to-child",
                rule.secret
            ));
        }

        #[cfg(windows)]
        if rule.actions.contains(&SecretAction::DelegateToChild) {
            return Err(format!(
                "process secret policy for '{}' uses delegate-to-child, which is not supported on Windows",
                rule.secret
            ));
        }

        let mut children = Vec::new();
        let mut child_sha256 = Vec::new();
        for child in &rule.children {
            children.push(canonicalize_policy_program(child, command)?);
        }

        for (index, child) in children.iter().enumerate() {
            if rule.child_sha256.is_empty() {
                break;
            }

            let expected = parse_sha256_hex(&rule.child_sha256[index]).map_err(|err| {
                format!(
                    "process secret policy for '{}' child '{}' has invalid sha256: {}",
                    rule.secret,
                    child.display(),
                    err
                )
            })?;
            let actual = compute_file_sha256(child).map_err(|err| {
                format!(
                    "process secret policy for '{}' child '{}' could not be hashed: {}",
                    rule.secret,
                    child.display(),
                    err
                )
            })?;
            if actual != expected {
                return Err(format!(
                    "process secret policy for '{}' child '{}' sha256 does not match current executable",
                    rule.secret,
                    child.display()
                ));
            }
            child_sha256.push(expected);
        }

        resolved.process_secret_policy.push(ResolvedProcessSecretPolicyRule {
            secret: rule.secret.clone(),
            actions: rule.actions.clone(),
            children,
            child_sha256,
            name: rule.name.clone(),
            fd_env: rule.fd_env.clone(),
        });
    }

    Ok(resolved)
}

fn parse_key_name<'a>(value: &'a str, error: &str) -> Result<(&'a str, &'a str), String> {
    let mut parts = value.splitn(2, '=');
    let key = parts.next().unwrap_or("");
    let name = parts.next().unwrap_or("");
    if key.is_empty() || name.is_empty() {
        return Err(error.to_string());
    }
    Ok((key, name))
}

fn canonicalize_policy_program(value: &str, command: &Command) -> Result<PathBuf, String> {
    let cwd = match command.get_current_dir() {
        Some(path) => path.to_path_buf(),
        None => std::env::current_dir().map_err(|err| err.to_string())?,
    };
    canonicalize_executable(Path::new(value), &cwd)
        .map_err(|err| format!("failed to resolve policy program {}: {}", value, err))
}

fn parse_name_mappings(values: &[String], error: &str) -> Result<HashMap<String, String>, String> {
    let mut mappings = HashMap::new();
    for value in values {
        let (name, mapped) = parse_key_name(value, error)?;
        if mappings
            .insert(name.to_string(), mapped.to_string())
            .is_some()
        {
            return Err(format!("{}: duplicate mapping for '{}'", error, name));
        }
    }
    Ok(mappings)
}

fn parse_sha256_hex(value: &str) -> Result<[u8; 32], String> {
    let trimmed = value.trim();
    if trimmed.len() != 64 {
        return Err("expected 64 hex characters".to_string());
    }

    let mut output = [0_u8; 32];
    for (index, chunk) in trimmed.as_bytes().chunks_exact(2).enumerate() {
        let hex = std::str::from_utf8(chunk).map_err(|err| err.to_string())?;
        output[index] = u8::from_str_radix(hex, 16)
            .map_err(|_| format!("invalid hex byte '{}'", hex))?;
    }
    Ok(output)
}

fn compute_file_sha256(path: &Path) -> Result<[u8; 32], String> {
    let mut file = std::fs::File::open(path).map_err(|err| err.to_string())?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];

    loop {
        let read = std::io::Read::read(&mut file, &mut buffer).map_err(|err| err.to_string())?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    let digest = hasher.finalize();
    let mut output = [0_u8; 32];
    output.copy_from_slice(&digest);
    Ok(output)
}

fn parse_exec_mappings(values: &[String]) -> Result<HashMap<String, PathBuf>, String> {
    let mut mappings = HashMap::new();
    for value in values {
        let (name, program) = parse_key_name(value, "trusted-secret-exec must be in NAME=PROGRAM format")?;
        let path = canonicalize_executable(Path::new(program), &std::env::current_dir().map_err(|err| err.to_string())?)
            .map_err(|err| format!("invalid trusted executable {}: {}", program, err))?;
        if mappings.insert(name.to_string(), path).is_some() {
            return Err(format!(
                "trusted-secret-exec has duplicate mapping for '{}'",
                name
            ));
        }
    }
    Ok(mappings)
}

fn resolve_command_path(command: &Command) -> Result<PathBuf, String> {
    let cwd = match command.get_current_dir() {
        Some(path) => path.to_path_buf(),
        None => std::env::current_dir().map_err(|err| err.to_string())?,
    };
    canonicalize_executable(Path::new(command.get_program()), &cwd)
        .map_err(|err| format!("failed to resolve launched command: {}", err))
}

fn canonicalize_executable(program: &Path, cwd: &Path) -> Result<PathBuf, String> {
    if program.is_absolute() {
        return std::fs::canonicalize(program).map_err(|err| err.to_string());
    }

    if program.components().count() > 1 {
        return std::fs::canonicalize(cwd.join(program)).map_err(|err| err.to_string());
    }

    let path_env = std::env::var_os("PATH").ok_or_else(|| "PATH is not set".to_string())?;
    for entry in std::env::split_paths(&path_env) {
        for candidate in executable_candidates(&entry, program) {
            if candidate.exists() {
                return std::fs::canonicalize(candidate).map_err(|err| err.to_string());
            }
        }
    }

    Err(format!("{} was not found on PATH", program.display()))
}

fn reject_relay_executable(program: &Path) -> Result<(), String> {
    let Some(name) = program.file_name().and_then(|value| value.to_str()) else {
        return Ok(());
    };

    if is_relay_executable_name(name) {
        return Err(format!(
            "trusted secret target '{}' is a relay binary; use a direct trusted consumer",
            program.display()
        ));
    }

    Ok(())
}

fn is_relay_executable_name(name: &str) -> bool {
    let normalized = name.to_ascii_lowercase();
    let stem = Path::new(&normalized)
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or(&normalized);

    matches!(stem, "sh" | "bash" | "zsh" | "dash" | "fish" | "ksh" | "env" | "osascript")
        || stem.starts_with("python")
        || stem.starts_with("node")
        || stem.starts_with("ruby")
        || stem.starts_with("perl")
        || stem.starts_with("php")
        || stem.starts_with("lua")
}

fn executable_candidates(base: &Path, program: &Path) -> Vec<PathBuf> {
    let joined = base.join(program);

    #[cfg(not(windows))]
    {
        vec![joined]
    }

    #[cfg(windows)]
    {
        let mut candidates = vec![joined.clone()];
        if joined.extension().is_some() {
            return candidates;
        }

        let pathext = std::env::var_os("PATHEXT").unwrap_or_else(|| OsString::from(".COM;.EXE;.BAT;.CMD"));
        for extension in pathext.to_string_lossy().split(';').filter(|value| !value.is_empty()) {
            let trimmed = extension.trim();
            let ext = if trimmed.starts_with('.') {
                trimmed.to_lowercase()
            } else {
                format!(".{}", trimmed).to_lowercase()
            };
            candidates.push(base.join(format!("{}{}", program.display(), ext)));
        }

        candidates
    }
}

#[cfg(unix)]
fn prepare_secret_broker(
    command: &mut Command,
    name: &str,
    endpoint_env: &str,
    payload: SecretBytes,
    kind: UnixTrustedSecretBrokerKind,
) -> Result<UnixTrustedSecretBroker, String> {
    let temp_dir = create_secret_endpoint_dir()?;
    let socket_path = temp_dir.join(TRUSTED_SECRET_ENDPOINT_FILE_NAME);
    let listener = UnixListener::bind(&socket_path).map_err(|err| err.to_string())?;
    let nonce = generate_secret_nonce()?;
    listener
        .set_nonblocking(true)
        .map_err(|err| err.to_string())?;
    command.env(endpoint_env, socket_path.display().to_string());
    command.env(trusted_secret_nonce_env(endpoint_env), &nonce);

    Ok(UnixTrustedSecretBroker {
        name: name.to_string(),
        kind,
        socket_path,
        listener: Some(listener),
        nonce,
        payload: Some(payload),
        temp_dir,
    })
}

#[cfg(unix)]
fn trusted_secret_nonce_env(endpoint_env: &str) -> String {
    format!("{}_NONCE", endpoint_env)
}

#[cfg(unix)]
fn generate_secret_nonce() -> Result<String, String> {
    let mut file = std::fs::File::open("/dev/urandom").map_err(|err| err.to_string())?;
    let mut bytes = [0_u8; TRUSTED_SECRET_NONCE_LEN / 2];
    file.read_exact(&mut bytes).map_err(|err| err.to_string())?;
    Ok(bytes_to_lower_hex(&bytes))
}

#[cfg(unix)]
fn bytes_to_lower_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{:02x}", byte));
    }
    output
}

#[cfg(unix)]
fn read_secret_nonce(stream: &mut UnixStream) -> Result<String, String> {
    stream
        .set_read_timeout(Some(TRUSTED_SECRET_NONCE_READ_TIMEOUT))
        .map_err(|err| err.to_string())?;
    let mut buffer = [0_u8; TRUSTED_SECRET_NONCE_LEN];
    stream.read_exact(&mut buffer).map_err(|err| err.to_string())?;
    stream.set_read_timeout(None).map_err(|err| err.to_string())?;
    String::from_utf8(buffer.to_vec()).map_err(|err| err.to_string())
}

#[cfg(unix)]
fn create_secret_endpoint_dir() -> Result<PathBuf, String> {
    let root = Path::new(TRUSTED_SECRET_ENDPOINT_ROOT);
    for attempt in 0..32_u32 {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| err.to_string())?
            .as_nanos();
        let dir = root.join(format!(
            "{}-{}-{}-{}",
            TRUSTED_SECRET_ENDPOINT_DIR_PREFIX,
            std::process::id(),
            stamp,
            attempt
        ));
        match std::fs::create_dir(&dir) {
            Ok(()) => return Ok(dir),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err.to_string()),
        }
    }

    Err("failed to create trusted secret endpoint directory".to_string())
}

#[cfg(unix)]
fn deliver_secret_to_process(
    broker: &mut UnixTrustedSecretBroker,
    child_pid: u32,
    expected_program: &Path,
) -> Result<(), String> {
    let payload = broker
        .payload
        .as_ref()
        .ok_or_else(|| format!("trusted secret '{}' payload is unavailable", broker.name))?;
    let listener = broker
        .listener
        .as_ref()
        .ok_or_else(|| format!("trusted secret '{}' broker listener is unavailable", broker.name))?;
    let deadline = Instant::now() + TRUSTED_SECRET_DELIVERY_TIMEOUT;
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let peer_pid = get_peer_pid(&stream)?;
                if peer_pid != child_pid {
                    return Err(format!(
                        "trusted secret '{}' fetch came from unexpected pid {}",
                        broker.name, peer_pid
                    ));
                }

                let peer_program = get_process_executable(peer_pid)?;
                if peer_program != expected_program {
                    return Err(format!(
                        "trusted secret '{}' fetch came from unexpected executable {}",
                        broker.name,
                        peer_program.display()
                    ));
                }

                let presented_nonce = read_secret_nonce(&mut stream)?;
                if presented_nonce != broker.nonce {
                    return Err(format!(
                        "trusted secret '{}' fetch presented an invalid nonce",
                        broker.name
                    ));
                }

                payload
                    .expose(|bytes| stream.write_all(bytes))
                    .map_err(|err| err.to_string())?;
                return Ok(());
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                if !process_is_alive(child_pid) {
                    return Err(format!(
                        "trusted secret '{}' was not fetched before child exit",
                        broker.name
                    ));
                }
                thread::sleep(TRUSTED_SECRET_DELIVERY_POLL_INTERVAL);
            }
            Err(err) => return Err(err.to_string()),
        }
    }

    Err(format!(
        "timed out delivering trusted secret '{}' to child {}",
        broker.name, child_pid
    ))
}

#[cfg(unix)]
fn start_delegated_secret_delivery(
    broker: &mut UnixTrustedSecretBroker,
    parent_pid: u32,
    allowed_children: Vec<DelegatedChildConstraint>,
) -> Result<thread::JoinHandle<Result<(), String>>, String> {
    let listener = broker
        .listener
        .take()
        .ok_or_else(|| format!("trusted secret '{}' broker listener is unavailable", broker.name))?;
    let name = broker.name.clone();
    let nonce = broker.nonce.clone();
    let payload = broker
        .payload
        .take()
        .ok_or_else(|| format!("trusted secret '{}' payload is unavailable", broker.name))?;

    Ok(thread::spawn(move || {
        let mut last_rejection = None;
        while process_is_alive(parent_pid) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let peer_pid = get_peer_pid(&stream)?;
                    let peer_program = match get_process_executable(peer_pid) {
                        Ok(program) => program,
                        Err(err) => {
                            last_rejection = Some(format!(
                                "trusted secret '{}' delegated fetch could not resolve executable for pid {}: {}",
                                name, peer_pid, err
                            ));
                            continue;
                        }
                    };
                    let Some(allowed_child) = allowed_children
                        .iter()
                        .find(|child| child.program == peer_program)
                    else {
                        last_rejection = Some(format!(
                            "trusted secret '{}' delegated fetch came from unauthorized executable {}",
                            name,
                            peer_program.display()
                        ));
                        continue;
                    };

                    if let Some(expected_sha256) = allowed_child.sha256 {
                        let Ok(actual_sha256) = compute_file_sha256(&peer_program) else {
                            last_rejection = Some(format!(
                                "trusted secret '{}' delegated fetch could not hash authorized child {}",
                                name,
                                peer_program.display()
                            ));
                            continue;
                        };
                        if actual_sha256 != expected_sha256 {
                            last_rejection = Some(format!(
                                "trusted secret '{}' delegated fetch hash mismatch for {}",
                                name,
                                peer_program.display()
                            ));
                            continue;
                        }
                    }

                    let Ok(peer_parent_pid) = get_process_parent_pid(peer_pid) else {
                        last_rejection = Some(format!(
                            "trusted secret '{}' delegated fetch could not resolve parent pid for {}",
                            name, peer_pid
                        ));
                        continue;
                    };
                    if peer_parent_pid != parent_pid {
                        last_rejection = Some(format!(
                            "trusted secret '{}' delegated fetch came from child {} with unexpected parent {}",
                            name, peer_pid, peer_parent_pid
                        ));
                        continue;
                    }

                    let Ok(presented_nonce) = read_secret_nonce(&mut stream) else {
                        last_rejection = Some(format!(
                            "trusted secret '{}' delegated fetch from {} did not present a valid nonce",
                            name, peer_pid
                        ));
                        continue;
                    };
                    if presented_nonce != nonce {
                        last_rejection = Some(format!(
                            "trusted secret '{}' delegated fetch from {} presented the wrong nonce",
                            name, peer_pid
                        ));
                        continue;
                    }

                    payload
                        .expose(|bytes| stream.write_all(bytes))
                        .map_err(|err| err.to_string())?;
                    return Ok(());
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(TRUSTED_SECRET_DELIVERY_POLL_INTERVAL);
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::NotConnected
                    ) =>
                {
                    thread::sleep(TRUSTED_SECRET_DELIVERY_POLL_INTERVAL);
                }
                Err(err) => {
                    return Err(format!(
                        "trusted secret '{}' delegated delivery failed: {}",
                        name, err
                    ));
                }
            }
        }

        Err(last_rejection.unwrap_or_else(|| {
            format!(
                "trusted secret '{}' delegated delivery ended before an authorized child fetched the secret",
                name
            )
        }))
    }))
}

#[cfg(unix)]
fn process_is_alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as i32, 0) == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM) }
}

#[cfg(target_os = "macos")]
fn get_peer_pid(stream: &UnixStream) -> Result<u32, String> {
    use std::mem::size_of_val;
    use std::os::fd::AsRawFd;

    let mut peer_pid: libc::pid_t = 0;
    let mut len = size_of_val(&peer_pid) as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            0,
            libc::LOCAL_PEERPID,
            (&mut peer_pid as *mut libc::pid_t).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(peer_pid as u32)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn get_peer_pid(stream: &UnixStream) -> Result<u32, String> {
    use std::mem::size_of;
    use std::os::fd::AsRawFd;

    let mut peer_cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut peer_cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(peer_cred.pid as u32)
}

#[cfg(target_os = "macos")]
fn get_process_executable(pid: u32) -> Result<PathBuf, String> {
    const PROC_PIDPATHINFO_MAXSIZE: usize = 4096;

    #[link(name = "proc")]
    unsafe extern "C" {
        fn proc_pidpath(pid: i32, buffer: *mut libc::c_void, buffersize: u32) -> i32;
    }

    let mut buffer = vec![0_u8; PROC_PIDPATHINFO_MAXSIZE];
    let rc = unsafe {
        proc_pidpath(
            pid as i32,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
        )
    };
    if rc <= 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let path = std::ffi::CStr::from_bytes_until_nul(&buffer)
        .map_err(|err| err.to_string())?
        .to_string_lossy()
        .into_owned();
    std::fs::canonicalize(path).map_err(|err| err.to_string())
}

#[cfg(target_os = "macos")]
fn get_process_parent_pid(pid: u32) -> Result<u32, String> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let expected_size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
    let rc = unsafe {
        libc::proc_pidinfo(
            pid as i32,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            expected_size,
        )
    };
    if rc != expected_size {
        if rc <= 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        return Err(format!(
            "proc_pidinfo returned unexpected size {} for pid {}",
            rc, pid
        ));
    }

    Ok(info.pbi_ppid)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn get_process_executable(pid: u32) -> Result<PathBuf, String> {
    std::fs::canonicalize(format!("/proc/{}/exe", pid)).map_err(|err| err.to_string())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn get_process_parent_pid(pid: u32) -> Result<u32, String> {
    let status = std::fs::read_to_string(format!("/proc/{}/status", pid))
        .map_err(|err| err.to_string())?;
    let parent_line = status
        .lines()
        .find(|line| line.starts_with("PPid:"))
        .ok_or_else(|| format!("missing PPid entry for pid {}", pid))?;
    let parent_pid = parent_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| format!("missing PPid value for pid {}", pid))?
        .parse::<u32>()
        .map_err(|err| err.to_string())?;
    Ok(parent_pid)
}

#[cfg(windows)]
fn prepare_secret_handle(payload: SecretBytes) -> Result<HANDLE, String> {
    let mut security_attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    let mut read_handle: HANDLE = std::ptr::null_mut();
    let mut write_handle: HANDLE = std::ptr::null_mut();
    let ok = unsafe { CreatePipe(&mut read_handle, &mut write_handle, &mut security_attributes, 0) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }

    let result = (|| {
        let ok = unsafe { SetHandleInformation(write_handle, HANDLE_FLAG_INHERIT, 0) };
        if ok == 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }

        payload.expose(|bytes| write_all_handle(write_handle, bytes))?;
        unsafe {
            CloseHandle(write_handle);
        }
        Ok(read_handle)
    })();

    if result.is_err() {
        unsafe {
            if !write_handle.is_null() && write_handle != INVALID_HANDLE_VALUE {
                CloseHandle(write_handle);
            }
            if !read_handle.is_null() && read_handle != INVALID_HANDLE_VALUE {
                CloseHandle(read_handle);
            }
        }
    }

    result
}

#[cfg(windows)]
fn write_all_handle(handle: HANDLE, payload: &[u8]) -> Result<(), String> {
    let mut written = 0;
    while written < payload.len() {
        let mut chunk = 0_u32;
        let ok = unsafe {
            WriteFile(
                handle,
                payload[written..].as_ptr().cast(),
                (payload.len() - written) as u32,
                &mut chunk,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        written += chunk as usize;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    use std::process::Stdio;

    #[cfg(unix)]
    fn unique_test_key(prefix: &str) -> String {
        let stamp = TRUSTED_SECRET_TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("{prefix}-{}-{}", std::process::id(), stamp)
    }

    #[cfg(unix)]
    fn compile_trusted_secret_test_helper(dir: &Path) -> PathBuf {
        compile_trusted_secret_test_helper_named(dir, "trusted-secret-helper")
    }

    #[cfg(unix)]
    fn compile_trusted_secret_test_helper_named(dir: &Path, name: &str) -> PathBuf {
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/test_binaries/shadictl-test-trusted-secret-helper.rs");
        let binary = dir.join(name);
        let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
        let mut command = Command::new(rustc);
        crate::scrub_test_secret_backend_env(&mut command);
        let output = command
            .arg("--edition=2021")
            .arg(&source)
            .arg("-o")
            .arg(&binary)
            .stderr(Stdio::piped())
            .output()
            .expect("compile checked-in trusted secret helper");
        assert!(
            output.status.success(),
            "failed to compile helper {}: {}",
            source.display(),
            String::from_utf8_lossy(&output.stderr)
        );

        binary
    }

    #[cfg(unix)]
    fn build_test_cli(program: &Path) -> Cli {
        Cli {
            profile: None,
            policy_file: None,
            allow: Vec::new(),
            read: Vec::new(),
            write: Vec::new(),
            net_block: false,
            net_allow: Vec::new(),
            allow_command: Vec::new(),
            inject_keychain: Vec::new(),
            trusted_secret: Vec::new(),
            trusted_secret_exec: Vec::new(),
            trusted_secret_fd_env: Vec::new(),
            list_keychain: false,
            list_prefix: None,
            print_policy: false,
            git_snapshot: false,
            git_snapshot_dir: None,
            git_snapshot_untracked: false,
            watch_policy: false,
            session_name: None,
            record_ref: None,
            subcommand: None,
            run_command: vec![program.display().to_string()],
        }
    }

    #[cfg(unix)]
    fn build_test_helper_command(temp: &tempfile::TempDir) -> (PathBuf, Command) {
        let helper = compile_trusted_secret_test_helper(temp.path());
        let mut command = Command::new(&helper);
        crate::scrub_test_secret_backend_env(&mut command);
        command.current_dir(temp.path());
        (helper, command)
    }

    #[cfg(unix)]
    fn resolve_config_error(
        command: &Command,
        program: &Path,
        policy: &PolicyFile,
    ) -> String {
        let cli = build_test_cli(program);
        resolve_launch_secret_config(command, &cli, policy).unwrap_err()
    }

    #[test]
    fn parse_name_mappings_requires_name_and_value() {
        let err = parse_name_mappings(&["broken".to_string()], "bad mapping").unwrap_err();
        assert!(err.contains("bad mapping"));
    }

    #[cfg(unix)]
    #[test]
    fn resolve_launch_secret_config_selects_only_matching_policy_rules() {
        let temp = tempfile::tempdir().expect("tempdir");
        let helper = compile_trusted_secret_test_helper(temp.path());
        let child = std::fs::canonicalize("/usr/bin/curl").expect("canonicalize curl");
        let child_sha256 = compute_file_sha256(&child)
            .expect("hash child")
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<String>();
        let mut command = Command::new(&helper);
        crate::scrub_test_secret_backend_env(&mut command);
        command.current_dir(temp.path());

        let policy = PolicyFile {
            process_inject_keychain: vec![
                ProcessInjectKeychainRule {
                    program: helper.display().to_string(),
                    key: "secops/token".to_string(),
                    env: "TOKEN".to_string(),
                },
                ProcessInjectKeychainRule {
                    program: "/bin/sh".to_string(),
                    key: "other/token".to_string(),
                    env: "OTHER".to_string(),
                },
            ],
            process_trusted_secret: vec![
                ProcessTrustedSecretRule {
                    program: helper.display().to_string(),
                    key: "secops/token".to_string(),
                    name: "token".to_string(),
                    fd_env: "TOKEN_FD".to_string(),
                    exec_sha256: None,
                },
                ProcessTrustedSecretRule {
                    program: "/bin/sh".to_string(),
                    key: "other/token".to_string(),
                    name: "other".to_string(),
                    fd_env: "OTHER_FD".to_string(),
                    exec_sha256: None,
                },
            ],
            process_secret_policy: vec![
                ProcessSecretPolicyRule {
                    program: helper.display().to_string(),
                    secret: "secops/github_token".to_string(),
                    actions: vec![SecretAction::DelegateToChild],
                    children: vec![child.display().to_string()],
                    child_sha256: vec![child_sha256.clone()],
                    name: Some("github-token".to_string()),
                    fd_env: Some("TOKEN_FD".to_string()),
                },
                ProcessSecretPolicyRule {
                    program: "/bin/sh".to_string(),
                    secret: "other/token".to_string(),
                    actions: vec![SecretAction::Disclose],
                    children: Vec::new(),
                    child_sha256: Vec::new(),
                    name: None,
                    fd_env: None,
                },
            ],
            ..PolicyFile::default()
        };

        let cli = build_test_cli(&helper);

        let resolved = resolve_launch_secret_config(&command, &cli, &policy).expect("resolve config");
        let helper_canonical = std::fs::canonicalize(&helper).expect("canonical helper");
        assert_eq!(resolved.inject_keychain, vec!["secops/token=TOKEN".to_string()]);
        assert_eq!(resolved.trusted_secret, vec!["secops/token=token".to_string()]);
        assert_eq!(resolved.trusted_secret_fd_env, vec!["token=TOKEN_FD".to_string()]);
        assert_eq!(
            resolved.trusted_secret_exec,
            vec![format!("token={}", helper_canonical.display())]
        );
        assert_eq!(resolved.process_secret_policy.len(), 1);
        assert_eq!(resolved.process_secret_policy[0].secret, "secops/github_token");
        assert_eq!(
            resolved.process_secret_policy[0].actions,
            vec![SecretAction::DelegateToChild]
        );
        assert_eq!(resolved.process_secret_policy[0].children, vec![child]);
        assert_eq!(resolved.process_secret_policy[0].child_sha256.len(), 1);
        assert_eq!(resolved.process_secret_policy[0].name.as_deref(), Some("github-token"));
        assert_eq!(resolved.process_secret_policy[0].fd_env.as_deref(), Some("TOKEN_FD"));
    }

    #[cfg(unix)]
    #[test]
    fn resolve_launch_secret_config_rejects_delegate_to_child_without_children() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (helper, command) = build_test_helper_command(&temp);

        let policy = PolicyFile {
            process_secret_policy: vec![ProcessSecretPolicyRule {
                program: helper.display().to_string(),
                secret: "secops/github_token".to_string(),
                actions: vec![SecretAction::DelegateToChild],
                children: Vec::new(),
                child_sha256: Vec::new(),
                name: Some("github-token".to_string()),
                fd_env: Some("TOKEN_FD".to_string()),
            }],
            ..PolicyFile::default()
        };

        let err = resolve_config_error(&command, &helper, &policy);
        assert!(err.contains("delegate-to-child"));
        assert!(err.contains("does not declare any children"));
    }

    #[cfg(unix)]
    #[test]
    fn resolve_launch_secret_config_rejects_delegate_to_child_without_name() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (helper, command) = build_test_helper_command(&temp);

        let policy = PolicyFile {
            process_secret_policy: vec![ProcessSecretPolicyRule {
                program: helper.display().to_string(),
                secret: "secops/github_token".to_string(),
                actions: vec![SecretAction::DelegateToChild],
                children: vec!["/usr/bin/curl".to_string()],
                child_sha256: Vec::new(),
                name: None,
                fd_env: Some("TOKEN_FD".to_string()),
            }],
            ..PolicyFile::default()
        };

        let err = resolve_config_error(&command, &helper, &policy);
        assert!(err.contains("does not declare a name"));
    }

    #[cfg(unix)]
    #[test]
    fn resolve_launch_secret_config_rejects_delegate_to_child_without_fd_env() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (helper, command) = build_test_helper_command(&temp);

        let policy = PolicyFile {
            process_secret_policy: vec![ProcessSecretPolicyRule {
                program: helper.display().to_string(),
                secret: "secops/github_token".to_string(),
                actions: vec![SecretAction::DelegateToChild],
                children: vec!["/usr/bin/curl".to_string()],
                child_sha256: Vec::new(),
                name: Some("github-token".to_string()),
                fd_env: None,
            }],
            ..PolicyFile::default()
        };

        let err = resolve_config_error(&command, &helper, &policy);
        assert!(err.contains("does not declare fd_env"));
    }

    #[cfg(unix)]
    #[test]
    fn resolve_launch_secret_config_rejects_children_without_delegate_to_child() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (helper, command) = build_test_helper_command(&temp);

        let policy = PolicyFile {
            process_secret_policy: vec![ProcessSecretPolicyRule {
                program: helper.display().to_string(),
                secret: "secops/github_token".to_string(),
                actions: vec![SecretAction::Disclose],
                children: vec!["/usr/bin/curl".to_string()],
                child_sha256: Vec::new(),
                name: None,
                fd_env: None,
            }],
            ..PolicyFile::default()
        };

        let err = resolve_config_error(&command, &helper, &policy);
        assert!(err.contains("declares children without delegate-to-child"));
    }

    #[cfg(unix)]
    #[test]
    fn resolve_launch_secret_config_rejects_child_sha256_count_mismatch() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (helper, command) = build_test_helper_command(&temp);

        let policy = PolicyFile {
            process_secret_policy: vec![ProcessSecretPolicyRule {
                program: helper.display().to_string(),
                secret: "secops/github_token".to_string(),
                actions: vec![SecretAction::DelegateToChild],
                children: vec!["/usr/bin/curl".to_string()],
                child_sha256: vec!["00".repeat(32), "11".repeat(32)],
                name: Some("github-token".to_string()),
                fd_env: Some("TOKEN_FD".to_string()),
            }],
            ..PolicyFile::default()
        };

        let err = resolve_config_error(&command, &helper, &policy);
        assert!(err.contains("declares 2 child sha256 values for 1 children"));
    }

    #[cfg(unix)]
    #[test]
    fn resolve_launch_secret_config_rejects_mismatched_child_sha256() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (helper, command) = build_test_helper_command(&temp);

        let policy = PolicyFile {
            process_secret_policy: vec![ProcessSecretPolicyRule {
                program: helper.display().to_string(),
                secret: "secops/github_token".to_string(),
                actions: vec![SecretAction::DelegateToChild],
                children: vec!["/usr/bin/curl".to_string()],
                child_sha256: vec!["00".repeat(32)],
                name: Some("github-token".to_string()),
                fd_env: Some("TOKEN_FD".to_string()),
            }],
            ..PolicyFile::default()
        };

        let err = resolve_config_error(&command, &helper, &policy);
        assert!(err.contains("sha256 does not match current executable"));
    }

    #[cfg(unix)]
    #[test]
    fn resolve_launch_secret_config_accepts_matching_process_trusted_secret_exec_sha256() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (helper, mut command) = build_test_helper_command(&temp);
        crate::scrub_test_secret_backend_env(&mut command);

        let digest = compute_file_sha256(&helper)
            .expect("hash helper")
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<String>();

        let policy = PolicyFile {
            process_trusted_secret: vec![ProcessTrustedSecretRule {
                program: helper.display().to_string(),
                key: "secops/token".to_string(),
                name: "token".to_string(),
                fd_env: "TOKEN_FD".to_string(),
                exec_sha256: Some(digest),
            }],
            ..PolicyFile::default()
        };

        let cli = build_test_cli(&helper);
        let resolved = resolve_launch_secret_config(&command, &cli, &policy).expect("resolve");
        assert_eq!(resolved.trusted_secret, vec!["secops/token=token".to_string()]);
    }

    #[cfg(unix)]
    #[test]
    fn resolve_launch_secret_config_rejects_mismatched_process_trusted_secret_exec_sha256() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (helper, command) = build_test_helper_command(&temp);

        let policy = PolicyFile {
            process_trusted_secret: vec![ProcessTrustedSecretRule {
                program: helper.display().to_string(),
                key: "secops/token".to_string(),
                name: "token".to_string(),
                fd_env: "TOKEN_FD".to_string(),
                exec_sha256: Some("00".repeat(32)),
            }],
            ..PolicyFile::default()
        };

        let err = resolve_config_error(&command, &helper, &policy);
        assert!(err.contains("exec_sha256 does not match current executable"));
    }

    #[cfg(unix)]
    #[test]
    fn trusted_secret_delivery_feeds_authorized_child_without_disclosing_to_parent() {
        let key = unique_test_key("secops/token");
        test_store_put(&key, b"trusted-value");
        let temp = tempfile::tempdir().expect("tempdir");
        let parent = compile_trusted_secret_test_helper_named(temp.path(), "trusted-secret-parent");
        let child = compile_trusted_secret_test_helper_named(temp.path(), "trusted-secret-child");
        let output_path = temp.path().join("delegated-secret.txt");

        let mut command = Command::new(&parent);
        crate::scrub_test_secret_backend_env(&mut command);
        command
            .arg("spawn-child")
            .arg(&child)
            .arg(&output_path);
        command.current_dir(temp.path());

        let delegated_rule = ResolvedProcessSecretPolicyRule {
            secret: key.clone(),
            actions: vec![SecretAction::DelegateToChild],
            children: vec![std::fs::canonicalize(&child).expect("canonical child")],
            child_sha256: Vec::new(),
            name: Some("token".to_string()),
            fd_env: Some("TOKEN_FD".to_string()),
        };

        let mut pending = PendingTrustedSecretDelivery::new(
            &mut command,
            &[],
            &[],
            &[],
            &[delegated_rule],
        )
        .expect("prepare")
        .expect("delivery");

        let envs = command.get_envs().collect::<Vec<_>>();
        assert!(!envs.iter().any(|(key, value)| {
            *key == std::ffi::OsStr::new("TOKEN")
                && *value == Some(std::ffi::OsStr::new("trusted-value"))
        }));

        let status = command.spawn().expect("spawn parent helper");
        pending
            .deliver_after_spawn(status.id())
            .expect("start delegated delivery");
        let output = status.wait_with_output().expect("wait parent helper");
        assert!(output.status.success());
        pending
            .wait_for_background_delivery()
            .expect("wait delegated delivery");
        pending.close_parent_fds();
        assert_eq!(std::fs::read(&output_path).expect("read delegated output"), b"trusted-value");
    }

    #[cfg(unix)]
    #[test]
    fn trusted_secret_delivery_rejects_same_binary_outsider_before_authorized_child() {
        let key = unique_test_key("secops/token");
        test_store_put(&key, b"trusted-value");
        let temp = tempfile::tempdir().expect("tempdir");
        let parent = compile_trusted_secret_test_helper_named(temp.path(), "trusted-secret-parent");
        let child = compile_trusted_secret_test_helper_named(temp.path(), "trusted-secret-child");
        let authorized_output = temp.path().join("authorized-secret.txt");
        let outsider_status = temp.path().join("outsider-status.txt");

        let mut command = Command::new(&parent);
        crate::scrub_test_secret_backend_env(&mut command);
        command
            .arg("spawn-child-after-delay")
            .arg(&child)
            .arg(&authorized_output)
            .arg("200");
        command.current_dir(temp.path());

        let delegated_rule = ResolvedProcessSecretPolicyRule {
            secret: key.clone(),
            actions: vec![SecretAction::DelegateToChild],
            children: vec![std::fs::canonicalize(&child).expect("canonical child")],
            child_sha256: Vec::new(),
            name: Some("token".to_string()),
            fd_env: Some("TOKEN_FD".to_string()),
        };

        let mut pending = PendingTrustedSecretDelivery::new(
            &mut command,
            &[],
            &[],
            &[],
            &[delegated_rule],
        )
        .expect("prepare")
        .expect("delivery");

        let token_endpoint = command
            .get_envs()
            .find_map(|(key, value)| {
                if key == std::ffi::OsStr::new("TOKEN_FD") {
                    value.map(|value| value.to_os_string())
                } else {
                    None
                }
            })
            .expect("token endpoint env");
        let token_nonce = command
            .get_envs()
            .find_map(|(key, value)| {
                if key == std::ffi::OsStr::new("TOKEN_FD_NONCE") {
                    value.map(|value| value.to_os_string())
                } else {
                    None
                }
            })
            .expect("token nonce env");

        let parent_process = command.spawn().expect("spawn parent helper");
        pending
            .deliver_after_spawn(parent_process.id())
            .expect("start delegated delivery");

        std::thread::sleep(Duration::from_millis(50));
        let outsider = {
            let mut outsider = Command::new(&child);
            crate::scrub_test_secret_backend_env(&mut outsider);
            outsider
                .arg("probe-secret")
                .arg(&outsider_status)
                .current_dir(temp.path())
                .env(TRUSTED_SECRET_PROTOCOL_ENV, TRUSTED_SECRET_PROTOCOL_VALUE)
                .env("TOKEN_FD", &token_endpoint)
                .env("TOKEN_FD_NONCE", &token_nonce)
                .output()
                .expect("spawn outsider")
        };
        assert!(!outsider.status.success());
        assert_unix_secret_probe_rejected(&outsider_status);

        let output = parent_process.wait_with_output().expect("wait parent helper");
        assert!(output.status.success());
        pending
            .wait_for_background_delivery()
            .expect("wait delegated delivery");
        pending.close_parent_fds();
        assert_eq!(std::fs::read(&authorized_output).expect("read delegated output"), b"trusted-value");
    }

    #[cfg(unix)]
    #[test]
    fn trusted_secret_delivery_requires_matching_child_sha256() {
        let key = unique_test_key("secops/token");
        test_store_put(&key, b"trusted-value");
        let temp = tempfile::tempdir().expect("tempdir");
        let parent = compile_trusted_secret_test_helper_named(temp.path(), "trusted-secret-parent");
        let child = compile_trusted_secret_test_helper_named(temp.path(), "trusted-secret-child");
        let child_status = temp.path().join("child-status.txt");

        let mut command = Command::new(&parent);
        crate::scrub_test_secret_backend_env(&mut command);
        command
            .arg("spawn-child-probe-after-delay")
            .arg(&child)
            .arg(&child_status)
            .arg("50");
        command.current_dir(temp.path());

        let delegated_rule = ResolvedProcessSecretPolicyRule {
            secret: key.clone(),
            actions: vec![SecretAction::DelegateToChild],
            children: vec![std::fs::canonicalize(&child).expect("canonical child")],
            child_sha256: vec![[0_u8; 32]],
            name: Some("token".to_string()),
            fd_env: Some("TOKEN_FD".to_string()),
        };

        let mut pending = PendingTrustedSecretDelivery::new(
            &mut command,
            &[],
            &[],
            &[],
            &[delegated_rule],
        )
        .expect("prepare")
        .expect("delivery");

        let parent_process = command.spawn().expect("spawn parent helper");
        pending
            .deliver_after_spawn(parent_process.id())
            .expect("start delegated delivery");
        let output = parent_process.wait_with_output().expect("wait parent helper");
        assert!(!output.status.success());
        let err = pending
            .wait_for_background_delivery()
            .expect_err("delegated delivery should fail on child sha mismatch");
        assert!(err.contains("hash mismatch"));
        pending.close_parent_fds();
        assert_unix_secret_probe_rejected(&child_status);
    }

    #[cfg(unix)]
    #[test]
    fn trusted_secret_delivery_rejects_authorized_child_without_nonce() {
        let key = unique_test_key("secops/token");
        test_store_put(&key, b"trusted-value");
        let temp = tempfile::tempdir().expect("tempdir");
        let parent = compile_trusted_secret_test_helper_named(temp.path(), "trusted-secret-parent");
        let child = compile_trusted_secret_test_helper_named(temp.path(), "trusted-secret-child");
        let output_path = temp.path().join("missing-nonce.txt");

        let mut command = Command::new(&parent);
        crate::scrub_test_secret_backend_env(&mut command);
        command
            .arg("spawn-child-without-nonce")
            .arg(&child)
            .arg(&output_path);
        command.current_dir(temp.path());

        let delegated_rule = ResolvedProcessSecretPolicyRule {
            secret: key.clone(),
            actions: vec![SecretAction::DelegateToChild],
            children: vec![std::fs::canonicalize(&child).expect("canonical child")],
            child_sha256: Vec::new(),
            name: Some("token".to_string()),
            fd_env: Some("TOKEN_FD".to_string()),
        };

        let mut pending = PendingTrustedSecretDelivery::new(
            &mut command,
            &[],
            &[],
            &[],
            &[delegated_rule],
        )
        .expect("prepare")
        .expect("delivery");

        let parent_process = command.spawn().expect("spawn parent helper");
        pending
            .deliver_after_spawn(parent_process.id())
            .expect("start delegated delivery");
        let output = parent_process.wait_with_output().expect("wait parent helper");
        assert!(!output.status.success());
        let err = pending
            .wait_for_background_delivery()
            .expect_err("delegated delivery should fail when the nonce is missing");
        assert!(err.contains("trusted secret 'token'"), "unexpected error: {err}");
        pending.close_parent_fds();
        assert!(std::fs::read(&output_path).is_err());
    }

    #[test]
    fn parse_name_mappings_rejects_duplicates() {
        let err = parse_name_mappings(
            &["token=TOKEN_FD".to_string(), "token=OTHER_FD".to_string()],
            "bad mapping",
        )
        .unwrap_err();
        assert!(err.contains("duplicate mapping"));
        assert!(err.contains("token"));
    }

    #[test]
    fn parse_exec_mappings_requires_program() {
        let err = parse_exec_mappings(&["broken".to_string()]).unwrap_err();
        assert!(err.contains("NAME=PROGRAM"));
    }

    #[cfg(unix)]
    #[test]
    fn parse_exec_mappings_rejects_duplicates() {
        let err = parse_exec_mappings(&[
            "token=/bin/sh".to_string(),
            "token=/bin/bash".to_string(),
        ])
        .unwrap_err();
        assert!(err.contains("duplicate mapping"));
        assert!(err.contains("token"));
    }

    #[cfg(windows)]
    #[test]
    fn executable_candidates_include_pathext_variants() {
        let candidates = executable_candidates(Path::new("C:\\Tools"), Path::new("copilot"));
        assert!(candidates.iter().any(|path| {
            path.file_name()
                .and_then(|value| value.to_str())
                .map(|value| value.eq_ignore_ascii_case("copilot.exe"))
                .unwrap_or(false)
        }));
    }

    #[cfg(unix)]
    #[test]
    fn trusted_secret_delivery_rejects_mismatched_executable() {
        let key = unique_test_key("secops/token");
        test_store_put(&key, b"value");
        let mut command = Command::new("/usr/bin/true");
        let err = PendingTrustedSecretDelivery::new(
            &mut command,
            &[format!("{}=token", key)],
            &["token=/bin/sh".to_string()],
            &["token=TOKEN_FD".to_string()],
            &[],
        )
        .unwrap_err();
        assert!(err.contains("targets"));
    }

    #[cfg(unix)]
    #[test]
    fn trusted_secret_delivery_rejects_shell_relay_binary() {
        let key = unique_test_key("secops/token");
        test_store_put(&key, b"value");
        let mut command = Command::new("sh");
        let command_path = resolve_command_path(&command).expect("resolve shell");
        let err = PendingTrustedSecretDelivery::new(
            &mut command,
            &[format!("{}=token", key)],
            &[format!("token={}", command_path.display())],
            &["token=TOKEN_FD".to_string()],
            &[],
        )
        .unwrap_err();
        assert!(err.contains("relay binary"));
    }

    #[cfg(unix)]
    #[test]
    fn trusted_secret_delivery_rejects_interpreter_relay_binary() {
        let key = unique_test_key("secops/token");
        test_store_put(&key, b"value");
        let mut command = Command::new("python3");
        let command_path = resolve_command_path(&command).expect("resolve interpreter");
        let err = PendingTrustedSecretDelivery::new(
            &mut command,
            &[format!("{}=token", key)],
            &[format!("token={}", command_path.display())],
            &["token=TOKEN_FD".to_string()],
            &[],
        )
        .unwrap_err();
        assert!(err.contains("relay binary"));
    }

    #[cfg(unix)]
    #[test]
    fn trusted_secret_delivery_rejects_duplicate_secret_names() {
        let first_key = unique_test_key("secops/token");
        let second_key = unique_test_key("secops/token");
        test_store_put(&first_key, b"first");
        test_store_put(&second_key, b"second");
        let temp = tempfile::tempdir().expect("tempdir");
        let helper = compile_trusted_secret_test_helper(temp.path());

        let mut command = Command::new(&helper);
        crate::scrub_test_secret_backend_env(&mut command);
        let err = PendingTrustedSecretDelivery::new(
            &mut command,
            &[
                format!("{}=token", first_key),
                format!("{}=token", second_key),
            ],
            &[format!("token={}", helper.display())],
            &["token=TOKEN_FD".to_string()],
            &[],
        )
        .unwrap_err();
        assert!(err.contains("configured more than once"));
    }

    #[cfg(unix)]
    fn assert_unix_secret_probe_rejected(path: &Path) {
        let status = std::fs::read(path).expect("read probe status");
        assert!(
            status == b"closed"
                || status.starts_with(b"Connection reset by peer")
                || status.starts_with(b"Broken pipe"),
            "unexpected probe rejection payload: {:?}",
            String::from_utf8_lossy(&status)
        );
    }

    #[cfg(unix)]
    #[test]
    fn trusted_secret_delivery_feeds_direct_child_over_fd() {
        let key = unique_test_key("secops/token");
        test_store_put(&key, b"trusted-value");
        let temp = tempfile::tempdir().expect("tempdir");
        let helper = compile_trusted_secret_test_helper(temp.path());
        let output_path = temp.path().join("secret.txt");

        let mut command = Command::new(&helper);
        crate::scrub_test_secret_backend_env(&mut command);
        command.arg("read-secret").arg(&output_path);
        command.current_dir(temp.path());
        let mut pending = PendingTrustedSecretDelivery::new(
            &mut command,
            &[format!("{}=token", key)],
            &[format!("token={}", helper.display())],
            &["token=TOKEN_FD".to_string()],
            &[],
        )
        .expect("prepare")
        .expect("delivery");

        let status = command.spawn().expect("spawn");
        pending
            .deliver_after_spawn(status.id())
            .expect("deliver secret");
        pending.close_parent_fds();
        let output = status.wait_with_output().expect("wait output");
        assert!(output.status.success());
        assert_eq!(std::fs::read(&output_path).expect("read output"), b"trusted-value");
    }

    #[cfg(unix)]
    #[test]
    fn trusted_secret_consumer_exec_does_not_retain_secret_capability() {
        let key = unique_test_key("secops/token");
        test_store_put(&key, b"trusted-value");
        let temp = tempfile::tempdir().expect("tempdir");
        let helper = compile_trusted_secret_test_helper(temp.path());
        let checker = compile_trusted_secret_test_helper_named(temp.path(), "trusted-secret-checker");
        let secret_output = temp.path().join("secret.txt");
        let status_output = temp.path().join("status.txt");

        let mut command = Command::new(&helper);
        crate::scrub_test_secret_backend_env(&mut command);
        command
            .arg("consume-and-exec")
            .arg(&secret_output)
            .arg(&status_output)
            .arg(&checker);
        command.current_dir(temp.path());
        let mut pending = PendingTrustedSecretDelivery::new(
            &mut command,
            &[format!("{}=token", key)],
            &[format!("token={}", helper.display())],
            &["token=TOKEN_FD".to_string()],
            &[],
        )
        .expect("prepare")
        .expect("delivery");

        let status = command.spawn().expect("spawn");
        pending
            .deliver_after_spawn(status.id())
            .expect("deliver secret");
        pending.close_parent_fds();
        let output = status.wait_with_output().expect("wait output");
        assert!(output.status.success());
        assert_eq!(std::fs::read(&secret_output).expect("read secret output"), b"trusted-value");
        assert_eq!(std::fs::read(&status_output).expect("read status output"), b"closed");
    }
}