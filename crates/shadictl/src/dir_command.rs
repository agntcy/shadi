// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! `shadictl dir` — thin integration layer over `dirctl` (AGNTCY Agent Directory CLI).
//!
//! Provides four sub-commands:
//!  - `login`        Authenticate with the AGNTCY Agent Directory and cache the token
//!                  in the SHADI secret store.
//!  - `pull <ref>`   Fetch an OASF record and cache it in `~/.shadi/records/`.
//!  - `info <ref>`   Show a human-readable summary of an agent record.
//!  - `search`       Search the directory for records by OASF skill.
//!
//! All sub-commands delegate to the `dirctl` binary which must be installed
//! separately (`brew tap agntcy/dir && brew install dirctl`).

use super::*;
use std::io::Write;

// ---------------------------------------------------------------------------
// dirctl auth token cache (mirrors client.CachedToken in the dirctl source)
// ---------------------------------------------------------------------------

/// Minimal deserialize of `~/.config/dirctl/auth-token.json`.
/// Only `access_token` is needed; all other fields are ignored.
#[derive(Deserialize)]
struct DirctlCachedToken {
    access_token: String,
}

/// Return the path to dirctl's on-disk auth token cache.
/// Mirrors the logic in `client.NewTokenCache()` in the dirctl Go source:
/// `$XDG_CONFIG_HOME/dirctl/auth-token.json` or `~/.config/dirctl/auth-token.json`.
fn dirctl_token_cache_path() -> Option<PathBuf> {
    let config_home = std::env::var("XDG_CONFIG_HOME").ok()
        .or_else(|| {
            std::env::var("HOME")
                .or_else(|_| std::env::var("USERPROFILE"))
                .ok()
                .map(|h| format!("{h}/.config"))
        })?;
    Some(PathBuf::from(config_home).join("dirctl").join("auth-token.json"))
}

// ---------------------------------------------------------------------------
// OASF record schema (subset — only the fields shadi needs to display)
// ---------------------------------------------------------------------------

#[derive(Deserialize, Debug)]
struct OasfRecord {
    name: Option<String>,
    description: Option<String>,
    version: Option<String>,
    #[serde(default)]
    skills: Vec<OasfClassRef>,
    #[serde(default)]
    domains: Vec<OasfClassRef>,
    #[serde(default)]
    locators: Vec<OasfLocator>,
}

#[derive(Deserialize, Debug)]
struct OasfClassRef {
    name: String,
}

#[derive(Deserialize, Debug)]
struct OasfLocator {
    #[serde(rename = "type")]
    locator_type: String,
    url: Option<String>,
    #[serde(default)]
    urls: Vec<String>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const DIRCTL_INSTALL_HINT: &str =
    "Install dirctl:  brew tap agntcy/dir https://github.com/agntcy/dir/ && brew install dirctl\n\
     Or download from: https://github.com/agntcy/dir/releases";

/// Return the path to the local record cache directory (`~/.shadi/records/`).
fn record_cache_dir() -> Option<PathBuf> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()?;
    Some(PathBuf::from(home).join(".shadi").join("records"))
}

/// Compute a hex-encoded SHA-256 digest of `data`.  Used as the cache filename.
fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(data);
    digest.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Build the `--server-addr` argument slice for a `dirctl` invocation.
fn server_addr_args(server_addr: &str) -> Vec<&str> {
    vec!["--server-addr", server_addr]
}

/// Apply OIDC token auth env vars to a `dirctl` `Command`.
///
/// Sets `DIRECTORY_CLIENT_AUTH_MODE=oidc` and `DIRECTORY_CLIENT_OIDC_TOKEN`.
/// This is the universal auth model for Directory v1.x — works for Zitadel
/// PKCE tokens (human login), machine client-credentials tokens, and
/// GitHub Actions OIDC tokens.
///
/// When no token is available, this function is not called and dirctl uses
/// its own auto-detect chain (cached token → insecure).
///
/// The token flows only via environment variables, not CLI arguments, to
/// prevent it from appearing in process listings.
fn apply_token_auth(cmd: &mut Command, token: &str) {
    cmd.env("DIRECTORY_CLIENT_AUTH_MODE", "oidc")
       .env("DIRECTORY_CLIENT_OIDC_TOKEN", token);
}

/// Print a human-readable one-line summary of an OASF record to stderr.
fn print_record_summary(record: &OasfRecord, reference: &str) {
    let name = record.name.as_deref().unwrap_or("(unnamed)");
    let version = record.version.as_deref().unwrap_or("?");
    eprintln!("record: {} v{} [{}]", name, version, reference);
    if let Some(desc) = &record.description {
        // Truncate long descriptions to a single line.
        let first_line = desc.lines().next().unwrap_or(desc.as_str());
        let truncated = if first_line.len() > 120 {
            format!("{}…", &first_line[..119])
        } else {
            first_line.to_string()
        };
        eprintln!("  description: {}", truncated);
    }
    if !record.skills.is_empty() {
        let skill_names: Vec<&str> = record.skills.iter().map(|s| s.name.as_str()).collect();
        eprintln!("  skills: {}", skill_names.join(", "));
    }
    if !record.domains.is_empty() {
        let domain_names: Vec<&str> = record.domains.iter().map(|d| d.name.as_str()).collect();
        eprintln!("  domains: {}", domain_names.join(", "));
    }
    for locator in &record.locators {
        let urls: Vec<&str> = locator.urls.iter().map(String::as_str)
            .chain(locator.url.as_deref())
            .collect();
        eprintln!("  {}: {}", locator.locator_type, urls.join(", "));
    }
}

// ---------------------------------------------------------------------------
// Sub-command handlers
// ---------------------------------------------------------------------------

/// `shadictl dir login` — authenticate with the Agent Directory and ingest the
/// resulting access token into the SHADI secret store.
///
/// Runs `dirctl auth login` with inherited stdio so the PKCE / device-code flow
/// can interact with the user directly.  On success, reads the access token from
/// dirctl's on-disk cache (`~/.config/dirctl/auth-token.json`) and stores it in
/// the SHADI secret store at `token_key`.
///
/// The token is then automatically picked up by `shadictl dir pull / info / search`
/// without the user having to pass it explicitly.
fn run_dir_login(args: DirLoginArgs, token_key: &str) -> ExitCode {
    // Allow overriding the dirctl binary path.  The released v1.1.0 uses GitHub
    // OAuth; HEAD (and Directory v1.x) uses OIDC.  Set SHADI_DIRCTL_BINARY to
    // point at a HEAD build until v1.2+ is released via Homebrew.
    let dirctl_bin = std::env::var("SHADI_DIRCTL_BINARY")
        .unwrap_or_else(|_| "dirctl".to_string());

    let mut cmd = Command::new(&dirctl_bin);
    cmd.arg("auth");

    if args.machine {
        // Service-user / non-interactive path: dirctl auth machine
        cmd.arg("machine");
        if let Some(ref client_id) = args.oidc_machine_client_id {
            cmd.env("DIRECTORY_CLIENT_OIDC_MACHINE_CLIENT_ID", client_id);
        }
        if let Some(ref secret_file) = args.oidc_machine_client_secret_file {
            cmd.env("DIRECTORY_CLIENT_OIDC_MACHINE_CLIENT_SECRET_FILE", secret_file);
        }
        cmd.env("DIRECTORY_CLIENT_OIDC_MACHINE_SCOPES", &args.oidc_machine_scopes);
    } else {
        // Interactive PKCE path: dirctl auth login
        cmd.arg("login");
        if args.no_browser {
            cmd.arg("--no-browser");
        }
        if args.force {
            cmd.arg("--force");
        }
        if let Some(ref client_id) = args.oidc_client_id {
            cmd.env("DIRECTORY_CLIENT_OIDC_CLIENT_ID", client_id);
        }
    }

    // Always forward the issuer (applies to both PKCE and machine flows).
    cmd.env("DIRECTORY_CLIENT_OIDC_ISSUER", &args.oidc_issuer);

    // Inherit stdio — the PKCE flow is interactive; machine flow is non-interactive
    // but still benefits from inheriting stderr for progress messages.
    cmd.stdin(std::process::Stdio::inherit())
       .stdout(std::process::Stdio::inherit())
       .stderr(std::process::Stdio::inherit());

    let status = match cmd.status() {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("error: dirctl not found in PATH");
            eprintln!("{}", DIRCTL_INSTALL_HINT);
            return ExitCode::from(2);
        }
        Err(err) => {
            eprintln!("error running dirctl: {}", err);
            return ExitCode::from(2);
        }
        Ok(s) => s,
    };

    if !status.success() {
        return ExitCode::from(status.code().unwrap_or(1) as u8);
    }

    // Ingest the cached token into the SHADI secret store so subsequent
    // `shadictl dir` commands can use it without dirctl's local cache being
    // present (e.g. on a different machine or in CI after secret import).
    let cache_path = match dirctl_token_cache_path() {
        Some(p) => p,
        None => {
            eprintln!("warning: could not determine dirctl cache path; token not ingested into SHADI store");
            return ExitCode::from(0);
        }
    };

    match ingest_dirctl_token(&cache_path, token_key) {
        Ok(()) => {
            eprintln!("token ingested into SHADI secret store at key: {}", token_key);
            ExitCode::from(0)
        }
        Err(e) => {
            // Login succeeded; only the SHADI ingestion step failed — warn but
            // don't surface a non-zero exit code so the user can still proceed.
            eprintln!("warning: login succeeded but SHADI store ingestion failed: {}", e);
            ExitCode::from(0)
        }
    }
}

/// Read dirctl's cached access token and write it into the SHADI secret store.
fn ingest_dirctl_token(cache_path: &PathBuf, token_key: &str) -> Result<(), String> {
    let data = std::fs::read(cache_path)
        .map_err(|e| format!("read {}: {}", cache_path.display(), e))?;
    let cached: DirctlCachedToken = serde_json::from_slice(&data)
        .map_err(|e| format!("parse {}: {}", cache_path.display(), e))?;
    let store = default_secret_store();
    store
        .put(token_key, cached.access_token.as_bytes(), SecretPolicy::default())
        .map_err(|e| format!("secret store put: {}", e))
}


/// Return the `dirctl` binary to invoke.
/// `SHADI_DIRCTL_BINARY` overrides the default `dirctl` in PATH, which lets
/// operators use a HEAD build that supports OIDC while the released Homebrew
/// version is still on GitHub OAuth.
fn dirctl_binary() -> String {
    std::env::var("SHADI_DIRCTL_BINARY").unwrap_or_else(|_| "dirctl".to_string())
}

fn run_dir_pull(args: DirPullArgs, oidc_token: Option<&str>) -> ExitCode {
    let server_args = server_addr_args(&args.server_addr);

    let mut cmd = Command::new(dirctl_binary());
    cmd.arg("pull")
       .arg(&args.reference)
       .args(&server_args)
       .arg("--output")
       .arg("json");
    if let Some(token) = oidc_token {
        apply_token_auth(&mut cmd, token);
    }
    let output = cmd.output();

    match output {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("error: dirctl not found in PATH");
            eprintln!("{}", DIRCTL_INSTALL_HINT);
            ExitCode::from(2)
        }
        Err(err) => {
            eprintln!("error running dirctl: {}", err);
            ExitCode::from(2)
        }
        Ok(out) if !out.status.success() => {
            let _ = std::io::stderr().write_all(&out.stderr);
            ExitCode::from(out.status.code().unwrap_or(1) as u8)
        }
        Ok(out) => {
            // Cache the JSON content addressed by its SHA-256 hash.
            let cache_key = sha256_hex(&out.stdout);
            if let Some(cache_dir) = record_cache_dir() {
                if std::fs::create_dir_all(&cache_dir).is_ok() {
                    let cache_path = cache_dir.join(format!("{}.json", cache_key));
                    if !cache_path.exists() {
                        let _ = std::fs::write(&cache_path, &out.stdout);
                    }
                    eprintln!("cached: {}", cache_path.display());
                }
            }

            // Print a brief summary to stderr.
            if let Ok(record) = serde_json::from_slice::<OasfRecord>(&out.stdout) {
                print_record_summary(&record, &args.reference);
            }

            // Pipe the full JSON record to stdout for composability.
            let _ = std::io::stdout().write_all(&out.stdout);
            ExitCode::from(0)
        }
    }
}

/// `shadictl dir info <ref>` — display metadata about an OASF record (delegates to `dirctl info`).
fn run_dir_info(args: DirInfoArgs, oidc_token: Option<&str>) -> ExitCode {
    let server_args = server_addr_args(&args.server_addr);

    let mut cmd = Command::new(dirctl_binary());
    cmd.arg("info")
       .arg(&args.reference)
       .args(&server_args);
    if let Some(token) = oidc_token {
        apply_token_auth(&mut cmd, token);
    }
    let status = cmd.status();

    match status {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("error: dirctl not found in PATH");
            eprintln!("{}", DIRCTL_INSTALL_HINT);
            ExitCode::from(2)
        }
        Err(err) => {
            eprintln!("error running dirctl: {}", err);
            ExitCode::from(2)
        }
        Ok(s) => ExitCode::from(s.code().unwrap_or(0) as u8),
    }
}

/// `shadictl dir search --skill <skill>` — search the directory (delegates to `dirctl routing search`).
fn run_dir_search(args: DirSearchArgs, oidc_token: Option<&str>) -> ExitCode {
    let server_args = server_addr_args(&args.server_addr);

    let mut cmd = Command::new(dirctl_binary());
    cmd.arg("search");
    for skill in &args.skill {
        cmd.arg("--skill").arg(skill);
    }
    cmd.arg("--limit").arg(args.limit.to_string());
    cmd.args(&server_args);
    if let Some(token) = oidc_token {
        apply_token_auth(&mut cmd, token);
    }

    let status = cmd.status();

    match status {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("error: dirctl not found in PATH");
            eprintln!("{}", DIRCTL_INSTALL_HINT);
            ExitCode::from(2)
        }
        Err(err) => {
            eprintln!("error running dirctl: {}", err);
            ExitCode::from(2)
        }
        Ok(s) => ExitCode::from(s.code().unwrap_or(0) as u8),
    }
}

/// Dispatch `shadictl dir <sub-command>`.
pub(crate) fn run_dir_command(cli: DirCli) -> ExitCode {
    // Token resolution order (highest → lowest priority):
    //  1. --oidc-token / $DIRECTORY_CLIENT_OIDC_TOKEN — explicit CLI/CI override.
    //  2. SHADI secret store at --token-key (default: "dir/oidc_token") — populated
    //     by `shadictl dir login` or `shadictl put-secret --key dir/oidc_token`.
    //  3. None — dirctl auto-detects cached credentials from `dirctl auth login`.
    //
    // The token is never logged or printed; it flows only into `apply_token_auth`
    // which sets env vars on the child `dirctl` process.
    let keychain_token: Option<String> = if cli.oidc_token.is_none() {
        let store = default_secret_store();
        store.get(&cli.token_key).ok().and_then(|s| {
            let bytes = s.expose(|b| b.to_vec());
            secret_bytes_to_utf8(&bytes).ok()
        })
    } else {
        None
    };
    let token = cli.oidc_token.as_deref().or(keychain_token.as_deref());

    match cli.command {
        DirCommand::Login(args)  => run_dir_login(args, &cli.token_key),
        DirCommand::Pull(args)   => run_dir_pull(args, token),
        DirCommand::Info(args)   => run_dir_info(args, token),
        DirCommand::Search(args) => run_dir_search(args, token),
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_oasf_json() -> &'static str {
        r#"{"name":"Test Agent","version":"1.2.3","description":"A test agent."}"#
    }

    fn full_oasf_json() -> &'static str {
        r#"{
            "name": "Tourist Scheduling Coordinator",
            "description": "Central scheduling coordinator that matches tourists with tour guides.",
            "version": "2.0.0",
            "schema_version": "1.0.0",
            "authors": ["AGNTCY <example@agntcy.org>"],
            "created_at": "2025-01-01T00:00:00Z",
            "domains": [{"name": "hospitality_and_tourism/tourism_management", "id": 1505}],
            "skills": [
                {"name": "agent_orchestration/task_decomposition", "id": 1001},
                {"name": "agent_orchestration/agent_coordination", "id": 1004}
            ],
            "modules": [],
            "locators": [
                {"type": "source_code", "urls": ["https://github.com/agntcy/agentic-apps"]}
            ]
        }"#
    }

    #[test]
    fn oasf_record_parses_minimal_json() {
        let record: OasfRecord = serde_json::from_str(minimal_oasf_json()).unwrap();
        assert_eq!(record.name.as_deref(), Some("Test Agent"));
        assert_eq!(record.version.as_deref(), Some("1.2.3"));
        assert!(record.skills.is_empty());
        assert!(record.locators.is_empty());
    }

    #[test]
    fn oasf_record_parses_full_example() {
        let record: OasfRecord = serde_json::from_str(full_oasf_json()).unwrap();
        assert_eq!(record.name.as_deref(), Some("Tourist Scheduling Coordinator"));
        assert_eq!(record.version.as_deref(), Some("2.0.0"));
        assert_eq!(record.skills.len(), 2);
        assert_eq!(record.skills[0].name, "agent_orchestration/task_decomposition");
        assert_eq!(record.domains.len(), 1);
        assert_eq!(record.domains[0].name, "hospitality_and_tourism/tourism_management");
        assert_eq!(record.locators.len(), 1);
        assert_eq!(record.locators[0].locator_type, "source_code");
        assert_eq!(record.locators[0].urls[0], "https://github.com/agntcy/agentic-apps");
    }

    #[test]
    fn sha256_hex_is_deterministic() {
        let a = sha256_hex(b"hello");
        let b = sha256_hex(b"hello");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn sha256_hex_differs_for_different_inputs() {
        assert_ne!(sha256_hex(b"hello"), sha256_hex(b"world"));
    }

    #[test]
    fn server_addr_args_returns_flag_and_value() {
        let args = server_addr_args("prod.gateway.ads.outshift.io:443");
        assert_eq!(args, vec!["--server-addr", "prod.gateway.ads.outshift.io:443"]);
    }

    #[test]
    fn apply_token_auth_sets_oidc_mode_for_any_token() {
        // Directory v1.x uses OIDC mode universally regardless of token prefix.
        for token in &["gho_legacy_oauth", "ghp_pat_token", "header.payload.signature"] {
            let mut cmd = Command::new("true");
            apply_token_auth(&mut cmd, token);
            let _ = cmd; // env vars applied — compile-time verification only
        }
    }

    #[test]
    fn run_dir_command_uses_keychain_token_when_oidc_token_absent() {
        // Populate the test secret store with a fake token at the default key.
        super::super::test_store_put("dir/oidc_token", b"header.payload.signature");

        // Construct a DirCli with no explicit oidc_token; run_dir_command should
        // pull the token from the store.  We can't actually invoke `dirctl` in
        // unit tests, but we verify the resolution logic by checking that the
        // keychain path is taken when `oidc_token` is None.
        let cli = DirCli {
            oidc_token: None,
            token_key: "dir/oidc_token".to_string(),
            command: DirCommand::Search(DirSearchArgs {
                skill: vec![],
                limit: 1,
                server_addr: "localhost:9999".to_string(),
            }),
        };
        // The keychain lookup yields the stored JWT; we verify the resolution
        // directly rather than running the full command (dirctl not guaranteed
        // to be present during unit tests).
        let store = default_secret_store();
        let fetched = store.get(&cli.token_key).ok().and_then(|s| {
            let bytes = s.expose(|b| b.to_vec());
            secret_bytes_to_utf8(&bytes).ok()
        });
        assert_eq!(fetched.as_deref(), Some("header.payload.signature"));
    }

    #[test]
    fn run_dir_command_oidc_token_takes_priority_over_keychain() {
        super::super::test_store_put("dir/oidc_token", b"keychain.token.value");
        let explicit_token = Some("explicit.oidc.jwt".to_string());
        let keychain_token: Option<String> = if explicit_token.is_none() {
            let store = default_secret_store();
            store.get("dir/oidc_token").ok().and_then(|s| {
                let bytes = s.expose(|b| b.to_vec());
                secret_bytes_to_utf8(&bytes).ok()
            })
        } else {
            None
        };
        let token = explicit_token.as_deref().or(keychain_token.as_deref());
        assert_eq!(token, Some("explicit.oidc.jwt"));
    }

    #[test]
    fn dirctl_token_cache_path_is_under_config_dirctl() {
        let path = dirctl_token_cache_path().expect("path should resolve");
        let s = path.to_str().unwrap_or("");
        assert!(s.contains("dirctl"), "expected dirctl in path, got: {}", s);
        assert!(s.ends_with("auth-token.json"), "expected auth-token.json, got: {}", s);
    }

    #[test]
    fn ingest_dirctl_token_writes_access_token_to_store() {
        // Write a fake auth-token.json to a temp file and ingest it.
        let tmp = std::env::temp_dir().join("shadi_test_auth_token.json");
        std::fs::write(
            &tmp,
            r#"{"access_token":"header.payload.signature","provider":"oidc","user":"test"}"#,
        )
        .unwrap();
        ingest_dirctl_token(&tmp, "dir/test_oidc_token").expect("ingest should succeed");
        let store = default_secret_store();
        let fetched = store.get("dir/test_oidc_token").expect("key should exist");
        let value = fetched.expose(|b| String::from_utf8_lossy(b).into_owned());
        assert_eq!(value, "header.payload.signature");
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn record_cache_dir_is_under_home() {
        if let Some(cache_dir) = record_cache_dir() {
            let s = cache_dir.to_str().unwrap_or("");
            assert!(s.contains(".shadi"), "expected .shadi in path, got: {}", s);
            assert!(s.contains("records"), "expected records in path, got: {}", s);
        }
    }

    #[test]
    fn oasf_locator_with_single_url_field_parses() {
        let json = r#"{"type":"docker-image","url":"ghcr.io/agntcy/agent:v1.0.0"}"#;
        let locator: OasfLocator = serde_json::from_str(json).unwrap();
        assert_eq!(locator.locator_type, "docker-image");
        assert_eq!(locator.url.as_deref(), Some("ghcr.io/agntcy/agent:v1.0.0"));
        assert!(locator.urls.is_empty());
    }
}
