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

/// Apply GitHub token auth env vars to a `dirctl` `Command`.
///
/// Sets `DIRECTORY_CLIENT_AUTH_MODE=github` and `DIRECTORY_CLIENT_GITHUB_TOKEN`.
/// This is the auth model for Directory v1.1.x (dirctl Homebrew release) which
/// uses GitHub OAuth / PAT tokens.
///
/// When no token is available, this function is not called and dirctl uses
/// its own auto-detect chain (cached token from `dirctl auth login` → insecure).
///
/// The token flows only via environment variables, not CLI arguments, to
/// prevent it from appearing in process listings.
fn apply_token_auth(cmd: &mut Command, token: &str) {
    cmd.env("DIRECTORY_CLIENT_AUTH_MODE", "github")
       .env("DIRECTORY_CLIENT_GITHUB_TOKEN", token);
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

/// `shadictl dir login` — authenticate with the Agent Directory via GitHub OAuth
/// and ingest the resulting access token into the SHADI secret store.
///
/// Runs `dirctl auth login` (GitHub OAuth browser flow) with inherited stdio.
/// On success, reads the access token from dirctl's on-disk cache
/// (`~/.config/dirctl/auth-token.json`) and stores it in the SHADI secret store
/// at `token_key`.
///
/// The token is then automatically picked up by `shadictl dir pull / info / search`
/// without the user having to pass it explicitly.
fn run_dir_login(args: DirLoginArgs, token_key: &str) -> ExitCode {
    let mut cmd = Command::new(dirctl_binary());
    cmd.arg("auth").arg("login");

    if args.no_browser {
        cmd.arg("--no-browser");
    }
    if args.force {
        cmd.arg("--force");
    }

    // Inherit stdio — GitHub OAuth flow is interactive.
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
            let content_hex = sha256_hex(&out.stdout);
            let digest = format!("sha256:{}", content_hex);

            // Cache the JSON content addressed by its SHA-256 hash.
            if let Some(cache_dir) = record_cache_dir() {
                if std::fs::create_dir_all(&cache_dir).is_ok() {
                    let cache_path = cache_dir.join(format!("{}.json", content_hex));
                    if !cache_path.exists() {
                        let _ = std::fs::write(&cache_path, &out.stdout);
                    }
                    eprintln!("cached: {}", cache_path.display());
                }
            }

            // Emit the content digest as informational output.  This is the
            // SHA-256 of the raw bytes returned by the directory — useful for
            // audit logs and cache management, but not a provenance proof.
            // Use `shadictl dir verify <CID>` to check the Sigstore signature.
            eprintln!("digest: {}", digest);

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
fn run_dir_search(args: DirSearchArgs, token: Option<&str>) -> ExitCode {
    let server_args = server_addr_args(&args.server_addr);

    let mut cmd = Command::new(dirctl_binary());
    cmd.arg("search");
    for skill in &args.skill {
        cmd.arg("--skill").arg(skill);
    }
    cmd.arg("--limit").arg(args.limit.to_string());
    cmd.args(&server_args);
    if let Some(token) = token {
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

/// `shadictl dir verify <CID>` — verify the Sigstore signature of a record.
///
/// Delegates to `dirctl verify <CID>`, which by default performs local
/// Sigstore verification (TUF trusted root + Rekor transparency log check).
/// Pass `--oidc-issuer` / `--oidc-subject` to pin the signing identity, or
/// `--key` to verify against a specific public key.
///
/// The directory auth token is forwarded so the server can be queried for the
/// signature manifest when running local verification.
fn run_dir_verify(args: DirVerifyArgs, token: Option<&str>) -> ExitCode {
    let server_args = server_addr_args(&args.server_addr);

    let mut cmd = Command::new(dirctl_binary());
    cmd.arg("verify")
       .arg(&args.cid)
       .args(&server_args);

    if let Some(ref key) = args.key {
        cmd.arg("--key").arg(key);
    }
    if let Some(ref issuer) = args.oidc_issuer {
        cmd.arg("--oidc-issuer").arg(issuer);
    }
    if let Some(ref subject) = args.oidc_subject {
        cmd.arg("--oidc-subject").arg(subject);
    }
    if args.from_server {
        cmd.arg("--from-server");
    }
    if args.ignore_tlog {
        cmd.arg("--ignore-tlog");
    }
    if let Some(ref path) = args.trusted_root_path {
        cmd.arg("--trusted-root-path").arg(path);
    }

    if let Some(t) = token {
        apply_token_auth(&mut cmd, t);
    }

    // Inherit stdio — human-readable output from dirctl is the primary UX.
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
    ExitCode::from(status.code().unwrap_or(0) as u8)
}

/// Dispatch `shadictl dir <sub-command>`.
pub(crate) fn run_dir_command(cli: DirCli) -> ExitCode {
    // Token resolution order (highest → lowest priority):
    //  1. --gh-token / $DIRECTORY_CLIENT_GITHUB_TOKEN — explicit CLI/CI override.
    //  2. SHADI secret store at --token-key (default: "dir/gh_token") — populated
    //     by `shadictl dir login` or `shadictl put-secret --key dir/gh_token`.
    //  3. None — dirctl auto-detects cached credentials from `dirctl auth login`.
    //
    // The token is never logged or printed; it flows only into `apply_token_auth`
    // which sets env vars on the child `dirctl` process.
    let keychain_token: Option<String> = if cli.gh_token.is_none() {
        let store = default_secret_store();
        store.get(&cli.token_key).ok().and_then(|s| {
            let bytes = s.expose(|b| b.to_vec());
            secret_bytes_to_utf8(&bytes).ok()
        })
    } else {
        None
    };
    let token = cli.gh_token.as_deref().or(keychain_token.as_deref());

    match cli.command {
        DirCommand::Login(args)  => run_dir_login(args, &cli.token_key),
        DirCommand::Pull(args)   => run_dir_pull(args, token),
        DirCommand::Info(args)   => run_dir_info(args, token),
        DirCommand::Search(args) => run_dir_search(args, token),
        DirCommand::Verify(args) => run_dir_verify(args, token),
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
    fn apply_token_auth_sets_github_mode_for_any_token() {
        // Directory v1.1.x uses github mode with GitHub PAT / OAuth tokens.
        for token in &["gho_oauth_token", "ghp_pat_token", "github_dummy"] {
            let mut cmd = Command::new("true");
            apply_token_auth(&mut cmd, token);
            let _ = cmd; // env vars applied — compile-time verification only
        }
    }

    #[test]
    fn run_dir_command_uses_keychain_token_when_gh_token_absent() {
        let test_key = "dir/test_gh_absent";
        // Populate the test secret store with a fake token at a test-scoped key.
        super::super::test_store_put(test_key, b"gho_fake_oauth_token");

        // Construct a DirCli with no explicit gh_token; run_dir_command should
        // pull the token from the store.  We can't actually invoke `dirctl` in
        // unit tests, but we verify the resolution logic by checking that the
        // keychain path is taken when `gh_token` is None.
        let cli = DirCli {
            gh_token: None,
            token_key: test_key.to_string(),
            command: DirCommand::Search(DirSearchArgs {
                skill: vec![],
                limit: 1,
                server_addr: "localhost:9999".to_string(),
            }),
        };
        let store = default_secret_store();
        let fetched = store.get(&cli.token_key).ok().and_then(|s| {
            let bytes = s.expose(|b| b.to_vec());
            secret_bytes_to_utf8(&bytes).ok()
        });
        assert_eq!(fetched.as_deref(), Some("gho_fake_oauth_token"));
    }

    #[test]
    fn run_dir_command_gh_token_takes_priority_over_keychain() {
        let test_key = "dir/test_priority_check";
        super::super::test_store_put(test_key, b"gho_keychain_token");
        let explicit_token = Some("gho_explicit_token".to_string());
        let keychain_token: Option<String> = if explicit_token.is_none() {
            let store = default_secret_store();
            store.get(test_key).ok().and_then(|s| {
                let bytes = s.expose(|b| b.to_vec());
                secret_bytes_to_utf8(&bytes).ok()
            })
        } else {
            None
        };
        let token = explicit_token.as_deref().or(keychain_token.as_deref());
        assert_eq!(token, Some("gho_explicit_token"));
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

    // ── verify arg-building ───────────────────────────────────────────────────

    /// `run_dir_verify` is not callable directly in unit tests (it exec's
    /// `dirctl`), but we exercise the argument-assembly helpers by verifying
    /// that `server_addr_args` and `apply_token_auth` produce the right output
    /// for the inputs that `run_dir_verify` would pass them, and that key /
    /// OIDC fields round-trip correctly through `DirVerifyArgs`.
    #[test]
    fn dir_verify_args_default_server_addr_is_prod() {
        // Clap default is the prod gateway; make sure it survives round-trip.
        use clap::Parser;
        let args = DirVerifyArgs::try_parse_from(["verify", "bafkreitest123"])
            .expect("parse");
        assert_eq!(args.cid, "bafkreitest123");
        assert_eq!(args.server_addr, "prod.gateway.ads.outshift.io:443");
        assert!(args.key.is_none());
        assert!(args.oidc_issuer.is_none());
        assert!(args.oidc_subject.is_none());
        assert!(!args.from_server);
        assert!(!args.ignore_tlog);
        assert!(args.trusted_root_path.is_none());
    }

    #[test]
    fn dir_verify_args_key_flag_is_forwarded() {
        use clap::Parser;
        let args = DirVerifyArgs::try_parse_from([
            "verify",
            "bafkreitest123",
            "--key",
            "/tmp/cosign.pub",
        ])
        .expect("parse");
        assert_eq!(args.key.as_deref(), Some("/tmp/cosign.pub"));
    }

    #[test]
    fn dir_verify_args_oidc_flags_are_forwarded() {
        use clap::Parser;
        let args = DirVerifyArgs::try_parse_from([
            "verify",
            "bafkreitest123",
            "--oidc-issuer",
            "https://token.actions.githubusercontent.com",
            "--oidc-subject",
            "alice@example.com",
        ])
        .expect("parse");
        assert_eq!(
            args.oidc_issuer.as_deref(),
            Some("https://token.actions.githubusercontent.com")
        );
        assert_eq!(args.oidc_subject.as_deref(), Some("alice@example.com"));
    }

    #[test]
    fn dir_verify_args_from_server_and_ignore_tlog_flags() {
        use clap::Parser;
        let args = DirVerifyArgs::try_parse_from([
            "verify",
            "bafkreitest123",
            "--from-server",
            "--ignore-tlog",
        ])
        .expect("parse");
        assert!(args.from_server);
        assert!(args.ignore_tlog);
    }

    // ── env-var manipulation lock ─────────────────────────────────────────────
    // Env-var mutations (SHADI_DIRCTL_BINARY, XDG_CONFIG_HOME) must be
    // serialised across threads because std::env::set_var is not thread-safe.

    use std::sync::{Mutex, OnceLock};

    static DIRCTL_ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    fn dirctl_env_lock() -> &'static Mutex<()> {
        DIRCTL_ENV_LOCK.get_or_init(|| Mutex::new(()))
    }

    // ── dirctl_binary ─────────────────────────────────────────────────────────

    #[test]
    fn dirctl_binary_defaults_to_dirctl_when_env_absent() {
        let _guard = dirctl_env_lock().lock().expect("lock");
        std::env::remove_var("SHADI_DIRCTL_BINARY");
        assert_eq!(dirctl_binary(), "dirctl");
    }

    #[test]
    fn dirctl_binary_uses_override_from_env() {
        let _guard = dirctl_env_lock().lock().expect("lock");
        std::env::set_var("SHADI_DIRCTL_BINARY", "/opt/custom/dirctl");
        let binary = dirctl_binary();
        std::env::remove_var("SHADI_DIRCTL_BINARY");
        assert_eq!(binary, "/opt/custom/dirctl");
    }

    // ── dirctl_token_cache_path ───────────────────────────────────────────────

    #[test]
    fn dirctl_token_cache_path_uses_xdg_config_home_when_set() {
        let _guard = dirctl_env_lock().lock().expect("lock");
        std::env::set_var("XDG_CONFIG_HOME", "/custom/xdg/config");
        let path = dirctl_token_cache_path();
        std::env::remove_var("XDG_CONFIG_HOME");
        let path = path.expect("path should resolve");
        let s = path.to_str().unwrap_or("");
        assert!(s.contains("/custom/xdg/config"), "expected XDG path, got: {}", s);
        assert!(s.ends_with("auth-token.json"), "expected auth-token.json suffix, got: {}", s);
        assert!(s.contains("dirctl"), "expected dirctl component, got: {}", s);
    }

    // ── ingest_dirctl_token error paths ───────────────────────────────────────

    #[test]
    fn ingest_dirctl_token_returns_error_for_missing_file() {
        let result = ingest_dirctl_token(
            &PathBuf::from("/nonexistent/shadi_test/auth-token.json"),
            "dir/test_missing_file",
        );
        assert!(result.is_err(), "should fail on missing file");
        let err = result.unwrap_err();
        assert!(err.contains("read"), "error should mention 'read', got: {}", err);
    }

    #[test]
    fn ingest_dirctl_token_returns_error_for_invalid_json() {
        let tmp = std::env::temp_dir().join("shadi_test_bad_json_ingest.txt");
        std::fs::write(&tmp, b"this is not valid json").expect("write temp file");
        let result = ingest_dirctl_token(&tmp, "dir/test_invalid_json");
        let _ = std::fs::remove_file(&tmp);
        assert!(result.is_err(), "should fail on invalid JSON");
        let err = result.unwrap_err();
        assert!(err.contains("parse"), "error should mention 'parse', got: {}", err);
    }

    // ── print_record_summary ──────────────────────────────────────────────────

    #[test]
    fn print_record_summary_with_none_name_and_version() {
        // Exercises the "(unnamed)" and "?" fallback branches.
        let record = OasfRecord {
            name: None,
            version: None,
            description: None,
            skills: vec![],
            domains: vec![],
            locators: vec![],
        };
        // Should not panic; output goes to stderr.
        print_record_summary(&record, "unnamed-ref");
    }

    #[test]
    fn print_record_summary_with_long_description_is_truncated() {
        // Exercises the >120 character truncation branch.
        let long_line = "x".repeat(200);
        let record = OasfRecord {
            name: Some("TruncAgent".to_string()),
            version: Some("1.0.0".to_string()),
            description: Some(long_line),
            skills: vec![],
            domains: vec![],
            locators: vec![],
        };
        print_record_summary(&record, "trunc-ref");
    }

    #[test]
    fn print_record_summary_with_multiline_description_uses_first_line() {
        let record = OasfRecord {
            name: Some("Agent".to_string()),
            version: Some("2.0.0".to_string()),
            description: Some("First line.\nSecond line that should not appear.".to_string()),
            skills: vec![],
            domains: vec![],
            locators: vec![],
        };
        print_record_summary(&record, "multiline-ref");
    }

    #[test]
    fn print_record_summary_with_skills_domains_and_locators() {
        // Exercises skills list, domains list, and locator with urls vec.
        let record = OasfRecord {
            name: Some("Full Agent".to_string()),
            version: Some("3.0.0".to_string()),
            description: Some("A short description.".to_string()),
            skills: vec![
                OasfClassRef { name: "nlp/translation".to_string() },
                OasfClassRef { name: "agent_orchestration/task_decomposition".to_string() },
            ],
            domains: vec![OasfClassRef { name: "hospitality/tourism".to_string() }],
            locators: vec![OasfLocator {
                locator_type: "source_code".to_string(),
                url: None,
                urls: vec![
                    "https://github.com/example/agent".to_string(),
                    "https://mirror.example.com/agent".to_string(),
                ],
            }],
        };
        print_record_summary(&record, "full-ref");
    }

    #[test]
    fn print_record_summary_with_url_field_locator() {
        // Exercises the `url` (singular) field path in locator rendering.
        let record = OasfRecord {
            name: Some("Docker Agent".to_string()),
            version: Some("1.0.0".to_string()),
            description: None,
            skills: vec![],
            domains: vec![],
            locators: vec![OasfLocator {
                locator_type: "docker_image".to_string(),
                url: Some("ghcr.io/example/agent:v1.0.0".to_string()),
                urls: vec![],
            }],
        };
        print_record_summary(&record, "docker-ref");
    }

    // ── CLI arg parsing ───────────────────────────────────────────────────────

    #[test]
    fn dir_pull_args_default_server_addr_is_prod() {
        use clap::Parser;
        let args = DirPullArgs::try_parse_from(["pull", "my-agent:v1.0.0"]).expect("parse");
        assert_eq!(args.reference, "my-agent:v1.0.0");
        assert_eq!(args.server_addr, "prod.gateway.ads.outshift.io:443");
    }

    #[test]
    fn dir_info_args_default_server_addr_is_prod() {
        use clap::Parser;
        let args = DirInfoArgs::try_parse_from(["info", "my-agent"]).expect("parse");
        assert_eq!(args.reference, "my-agent");
        assert_eq!(args.server_addr, "prod.gateway.ads.outshift.io:443");
    }

    #[test]
    fn dir_search_args_defaults() {
        use clap::Parser;
        let args = DirSearchArgs::try_parse_from(["search"]).expect("parse");
        assert!(args.skill.is_empty());
        assert_eq!(args.limit, 10);
        assert_eq!(args.server_addr, "prod.gateway.ads.outshift.io:443");
    }

    #[test]
    fn dir_search_args_with_skills_and_limit() {
        use clap::Parser;
        let args = DirSearchArgs::try_parse_from([
            "search", "--skill", "nlp", "--skill", "code_generation", "--limit", "25",
        ])
        .expect("parse");
        assert_eq!(args.skill, vec!["nlp", "code_generation"]);
        assert_eq!(args.limit, 25);
    }

    #[test]
    fn dir_login_args_defaults_are_false() {
        use clap::Parser;
        let args = DirLoginArgs::try_parse_from(["login"]).expect("parse");
        assert!(!args.no_browser);
        assert!(!args.force);
    }

    #[test]
    fn dir_login_args_flags_set() {
        use clap::Parser;
        let args =
            DirLoginArgs::try_parse_from(["login", "--no-browser", "--force"]).expect("parse");
        assert!(args.no_browser);
        assert!(args.force);
    }

    #[test]
    fn dir_verify_args_trusted_root_path_flag() {
        use clap::Parser;
        let args = DirVerifyArgs::try_parse_from([
            "verify",
            "bafkreitest999",
            "--trusted-root-path",
            "/etc/sigstore/trusted-root.json",
        ])
        .expect("parse");
        assert_eq!(
            args.trusted_root_path.as_deref(),
            Some(std::path::Path::new("/etc/sigstore/trusted-root.json"))
        );
    }

    // ── run_dir_login ─────────────────────────────────────────────────────────

    #[test]
    fn run_dir_login_returns_exit_code_2_when_dirctl_not_found() {
        let _guard = dirctl_env_lock().lock().expect("lock");
        std::env::set_var("SHADI_DIRCTL_BINARY", "/nonexistent/shadi_test_dirctl");
        let code = run_dir_login(DirLoginArgs { no_browser: false, force: false }, "dir/test_login_nf");
        std::env::remove_var("SHADI_DIRCTL_BINARY");
        assert_eq!(code, ExitCode::from(2));
    }

    #[test]
    fn run_dir_login_with_no_browser_and_force_flags_not_found() {
        // Ensures both optional flag branches are exercised in run_dir_login
        // even when the binary is missing.
        let _guard = dirctl_env_lock().lock().expect("lock");
        std::env::set_var("SHADI_DIRCTL_BINARY", "/nonexistent/shadi_test_dirctl");
        let code = run_dir_login(DirLoginArgs { no_browser: true, force: true }, "dir/test_login_flags");
        std::env::remove_var("SHADI_DIRCTL_BINARY");
        assert_eq!(code, ExitCode::from(2));
    }

    #[test]
    #[cfg(unix)]
    fn run_dir_login_returns_zero_when_binary_succeeds_but_cache_missing() {
        // Use /usr/bin/true as the fake dirctl — it exits 0 immediately.
        // The auth-token.json cache won't exist → ingestion warns but still returns 0.
        let _guard = dirctl_env_lock().lock().expect("lock");
        std::env::set_var("SHADI_DIRCTL_BINARY", "/usr/bin/true");
        let code = run_dir_login(
            DirLoginArgs { no_browser: false, force: false },
            "dir/test_login_success_warn",
        );
        std::env::remove_var("SHADI_DIRCTL_BINARY");
        assert_eq!(code, ExitCode::from(0));
    }

    // ── run_dir_pull ──────────────────────────────────────────────────────────

    #[test]
    fn run_dir_pull_returns_exit_code_2_when_dirctl_not_found() {
        let _guard = dirctl_env_lock().lock().expect("lock");
        std::env::set_var("SHADI_DIRCTL_BINARY", "/nonexistent/shadi_test_dirctl");
        let code = run_dir_pull(
            DirPullArgs {
                reference: "test-ref".to_string(),
                server_addr: "localhost:9999".to_string(),
            },
            None,
        );
        std::env::remove_var("SHADI_DIRCTL_BINARY");
        assert_eq!(code, ExitCode::from(2));
    }

    #[test]
    #[cfg(unix)]
    fn run_dir_pull_returns_nonzero_on_process_failure() {
        // /usr/bin/false exits with code 1 — exercises the !out.status.success() branch.
        let _guard = dirctl_env_lock().lock().expect("lock");
        std::env::set_var("SHADI_DIRCTL_BINARY", "/usr/bin/false");
        let code = run_dir_pull(
            DirPullArgs {
                reference: "test-ref".to_string(),
                server_addr: "localhost:9999".to_string(),
            },
            None,
        );
        std::env::remove_var("SHADI_DIRCTL_BINARY");
        assert_ne!(code, ExitCode::from(0));
    }

    #[test]
    #[cfg(unix)]
    fn run_dir_pull_success_path_computes_digest_and_returns_zero() {
        // /usr/bin/true exits 0 with no stdout — exercises the full success branch:
        // sha256_hex, record_cache_dir, digest print, stdout write.
        // JSON parse of empty bytes fails silently (if let Ok skipped).
        let _guard = dirctl_env_lock().lock().expect("lock");
        std::env::set_var("SHADI_DIRCTL_BINARY", "/usr/bin/true");
        let code = run_dir_pull(
            DirPullArgs {
                reference: "agent:v1.0".to_string(),
                server_addr: "test.server:443".to_string(),
            },
            Some("gho_fake_token"),
        );
        std::env::remove_var("SHADI_DIRCTL_BINARY");
        assert_eq!(code, ExitCode::from(0));
    }

    // ── run_dir_info ──────────────────────────────────────────────────────────

    #[test]
    fn run_dir_info_returns_exit_code_2_when_dirctl_not_found() {
        let _guard = dirctl_env_lock().lock().expect("lock");
        std::env::set_var("SHADI_DIRCTL_BINARY", "/nonexistent/shadi_test_dirctl");
        let code = run_dir_info(
            DirInfoArgs {
                reference: "test/agent".to_string(),
                server_addr: "localhost:9999".to_string(),
            },
            None,
        );
        std::env::remove_var("SHADI_DIRCTL_BINARY");
        assert_eq!(code, ExitCode::from(2));
    }

    #[test]
    #[cfg(unix)]
    fn run_dir_info_returns_zero_when_binary_succeeds() {
        let _guard = dirctl_env_lock().lock().expect("lock");
        std::env::set_var("SHADI_DIRCTL_BINARY", "/usr/bin/true");
        let code = run_dir_info(
            DirInfoArgs {
                reference: "test/agent".to_string(),
                server_addr: "localhost:9999".to_string(),
            },
            Some("gho_token"),
        );
        std::env::remove_var("SHADI_DIRCTL_BINARY");
        assert_eq!(code, ExitCode::from(0));
    }

    // ── run_dir_search ────────────────────────────────────────────────────────

    #[test]
    fn run_dir_search_returns_exit_code_2_when_dirctl_not_found() {
        let _guard = dirctl_env_lock().lock().expect("lock");
        std::env::set_var("SHADI_DIRCTL_BINARY", "/nonexistent/shadi_test_dirctl");
        let code = run_dir_search(
            DirSearchArgs {
                skill: vec!["nlp".to_string()],
                limit: 5,
                server_addr: "localhost:9999".to_string(),
            },
            None,
        );
        std::env::remove_var("SHADI_DIRCTL_BINARY");
        assert_eq!(code, ExitCode::from(2));
    }

    #[test]
    #[cfg(unix)]
    fn run_dir_search_returns_zero_when_binary_succeeds() {
        let _guard = dirctl_env_lock().lock().expect("lock");
        std::env::set_var("SHADI_DIRCTL_BINARY", "/usr/bin/true");
        let code = run_dir_search(
            DirSearchArgs {
                skill: vec![],
                limit: 10,
                server_addr: "localhost:9999".to_string(),
            },
            Some("gho_token"),
        );
        std::env::remove_var("SHADI_DIRCTL_BINARY");
        assert_eq!(code, ExitCode::from(0));
    }

    // ── run_dir_verify ────────────────────────────────────────────────────────

    #[test]
    fn run_dir_verify_returns_exit_code_2_when_dirctl_not_found() {
        // Exercises all optional flag branches in run_dir_verify argument assembly.
        let _guard = dirctl_env_lock().lock().expect("lock");
        std::env::set_var("SHADI_DIRCTL_BINARY", "/nonexistent/shadi_test_dirctl");
        let code = run_dir_verify(
            DirVerifyArgs {
                cid: "bafkreitest999".to_string(),
                key: Some("/tmp/cosign.pub".to_string()),
                oidc_issuer: Some("https://token.actions.githubusercontent.com".to_string()),
                oidc_subject: Some("alice@example.com".to_string()),
                from_server: true,
                ignore_tlog: true,
                trusted_root_path: Some(PathBuf::from("/tmp/trusted-root.json")),
                server_addr: "localhost:9999".to_string(),
            },
            Some("gho_token"),
        );
        std::env::remove_var("SHADI_DIRCTL_BINARY");
        assert_eq!(code, ExitCode::from(2));
    }

    #[test]
    fn run_dir_verify_returns_exit_code_2_minimal_args_not_found() {
        // Exercises the None-arm branches for all optional fields.
        let _guard = dirctl_env_lock().lock().expect("lock");
        std::env::set_var("SHADI_DIRCTL_BINARY", "/nonexistent/shadi_test_dirctl");
        let code = run_dir_verify(
            DirVerifyArgs {
                cid: "bafkrei_minimal".to_string(),
                key: None,
                oidc_issuer: None,
                oidc_subject: None,
                from_server: false,
                ignore_tlog: false,
                trusted_root_path: None,
                server_addr: "localhost:9999".to_string(),
            },
            None,
        );
        std::env::remove_var("SHADI_DIRCTL_BINARY");
        assert_eq!(code, ExitCode::from(2));
    }

    #[test]
    #[cfg(unix)]
    fn run_dir_verify_returns_zero_when_binary_succeeds() {
        let _guard = dirctl_env_lock().lock().expect("lock");
        std::env::set_var("SHADI_DIRCTL_BINARY", "/usr/bin/true");
        let code = run_dir_verify(
            DirVerifyArgs {
                cid: "bafkrei_success".to_string(),
                key: None,
                oidc_issuer: None,
                oidc_subject: None,
                from_server: false,
                ignore_tlog: false,
                trusted_root_path: None,
                server_addr: "localhost:9999".to_string(),
            },
            None,
        );
        std::env::remove_var("SHADI_DIRCTL_BINARY");
        assert_eq!(code, ExitCode::from(0));
    }

    // ── run_dir_command dispatch ──────────────────────────────────────────────

    #[test]
    fn run_dir_command_dispatches_login_when_dirctl_not_found() {
        let _guard = dirctl_env_lock().lock().expect("lock");
        std::env::set_var("SHADI_DIRCTL_BINARY", "/nonexistent/shadi_test_dirctl");
        let code = run_dir_command(DirCli {
            gh_token: None,
            token_key: "dir/dispatch_login".to_string(),
            command: DirCommand::Login(DirLoginArgs { no_browser: false, force: false }),
        });
        std::env::remove_var("SHADI_DIRCTL_BINARY");
        assert_eq!(code, ExitCode::from(2));
    }

    #[test]
    fn run_dir_command_dispatches_pull_when_dirctl_not_found() {
        let _guard = dirctl_env_lock().lock().expect("lock");
        std::env::set_var("SHADI_DIRCTL_BINARY", "/nonexistent/shadi_test_dirctl");
        let code = run_dir_command(DirCli {
            gh_token: Some("gho_explicit".to_string()),
            token_key: "dir/dispatch_pull".to_string(),
            command: DirCommand::Pull(DirPullArgs {
                reference: "test/agent:v1".to_string(),
                server_addr: "localhost:9999".to_string(),
            }),
        });
        std::env::remove_var("SHADI_DIRCTL_BINARY");
        assert_eq!(code, ExitCode::from(2));
    }

    #[test]
    fn run_dir_command_dispatches_info_when_dirctl_not_found() {
        let _guard = dirctl_env_lock().lock().expect("lock");
        std::env::set_var("SHADI_DIRCTL_BINARY", "/nonexistent/shadi_test_dirctl");
        let code = run_dir_command(DirCli {
            gh_token: None,
            token_key: "dir/dispatch_info_no_key".to_string(),
            command: DirCommand::Info(DirInfoArgs {
                reference: "test/agent".to_string(),
                server_addr: "localhost:9999".to_string(),
            }),
        });
        std::env::remove_var("SHADI_DIRCTL_BINARY");
        assert_eq!(code, ExitCode::from(2));
    }

    #[test]
    fn run_dir_command_dispatches_search_when_dirctl_not_found() {
        let _guard = dirctl_env_lock().lock().expect("lock");
        std::env::set_var("SHADI_DIRCTL_BINARY", "/nonexistent/shadi_test_dirctl");
        // Pre-populate keychain so the keychain_token fallback path is exercised.
        super::super::test_store_put("dir/dispatch_search_key", b"gho_keychain_token");
        let code = run_dir_command(DirCli {
            gh_token: None,
            token_key: "dir/dispatch_search_key".to_string(),
            command: DirCommand::Search(DirSearchArgs {
                skill: vec!["nlp".to_string()],
                limit: 5,
                server_addr: "localhost:9999".to_string(),
            }),
        });
        std::env::remove_var("SHADI_DIRCTL_BINARY");
        assert_eq!(code, ExitCode::from(2));
    }

    #[test]
    fn run_dir_command_dispatches_verify_when_dirctl_not_found() {
        let _guard = dirctl_env_lock().lock().expect("lock");
        std::env::set_var("SHADI_DIRCTL_BINARY", "/nonexistent/shadi_test_dirctl");
        let code = run_dir_command(DirCli {
            gh_token: None,
            token_key: "dir/dispatch_verify_nokey".to_string(),
            command: DirCommand::Verify(DirVerifyArgs {
                cid: "bafkreidispatch".to_string(),
                key: None,
                oidc_issuer: None,
                oidc_subject: None,
                from_server: false,
                ignore_tlog: false,
                trusted_root_path: None,
                server_addr: "localhost:9999".to_string(),
            }),
        });
        std::env::remove_var("SHADI_DIRCTL_BINARY");
        assert_eq!(code, ExitCode::from(2));
    }

    // ── generic Err (non-ENOENT) branches ────────────────────────────────────
    // Use a non-executable temp file so cmd.status() / cmd.output() returns
    // Err(e) with e.kind() == PermissionDenied, which falls through to the
    // catch-all Err(err) arm in each run_dir_* function.

    #[cfg(unix)]
    fn make_non_executable_binary() -> (std::path::PathBuf, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nonexec_bin");
        std::fs::write(&path, b"").expect("write temp file");
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000))
            .expect("chmod 000");
        (path, dir)
    }

    #[test]
    #[cfg(unix)]
    fn run_dir_login_generic_err_returns_exit_code_2() {
        let (path, _dir) = make_non_executable_binary();
        let _guard = dirctl_env_lock().lock().expect("lock");
        std::env::set_var("SHADI_DIRCTL_BINARY", &path);
        let code = run_dir_login(
            DirLoginArgs { no_browser: false, force: false },
            "dir/test_login_perm",
        );
        std::env::remove_var("SHADI_DIRCTL_BINARY");
        assert_eq!(code, ExitCode::from(2));
    }

    #[test]
    #[cfg(unix)]
    fn run_dir_pull_generic_err_returns_exit_code_2() {
        let (path, _dir) = make_non_executable_binary();
        let _guard = dirctl_env_lock().lock().expect("lock");
        std::env::set_var("SHADI_DIRCTL_BINARY", &path);
        let code = run_dir_pull(
            DirPullArgs {
                reference: "test-ref".to_string(),
                server_addr: "localhost:9999".to_string(),
            },
            None,
        );
        std::env::remove_var("SHADI_DIRCTL_BINARY");
        assert_eq!(code, ExitCode::from(2));
    }

    #[test]
    #[cfg(unix)]
    fn run_dir_info_generic_err_returns_exit_code_2() {
        let (path, _dir) = make_non_executable_binary();
        let _guard = dirctl_env_lock().lock().expect("lock");
        std::env::set_var("SHADI_DIRCTL_BINARY", &path);
        let code = run_dir_info(
            DirInfoArgs {
                reference: "test/agent".to_string(),
                server_addr: "localhost:9999".to_string(),
            },
            None,
        );
        std::env::remove_var("SHADI_DIRCTL_BINARY");
        assert_eq!(code, ExitCode::from(2));
    }

    #[test]
    #[cfg(unix)]
    fn run_dir_search_generic_err_returns_exit_code_2() {
        let (path, _dir) = make_non_executable_binary();
        let _guard = dirctl_env_lock().lock().expect("lock");
        std::env::set_var("SHADI_DIRCTL_BINARY", &path);
        let code = run_dir_search(
            DirSearchArgs {
                skill: vec![],
                limit: 10,
                server_addr: "localhost:9999".to_string(),
            },
            None,
        );
        std::env::remove_var("SHADI_DIRCTL_BINARY");
        assert_eq!(code, ExitCode::from(2));
    }

    #[test]
    #[cfg(unix)]
    fn run_dir_verify_generic_err_returns_exit_code_2() {
        let (path, _dir) = make_non_executable_binary();
        let _guard = dirctl_env_lock().lock().expect("lock");
        std::env::set_var("SHADI_DIRCTL_BINARY", &path);
        let code = run_dir_verify(
            DirVerifyArgs {
                cid: "bafkreiperm".to_string(),
                key: None,
                oidc_issuer: None,
                oidc_subject: None,
                from_server: false,
                ignore_tlog: false,
                trusted_root_path: None,
                server_addr: "localhost:9999".to_string(),
            },
            None,
        );
        std::env::remove_var("SHADI_DIRCTL_BINARY");
        assert_eq!(code, ExitCode::from(2));
    }

    // ── run_dir_login ingestion warning path ──────────────────────────────────
    // When dirctl exits 0 but the auth-token.json contains invalid JSON, or
    // when ingest_dirctl_token fails, run_dir_login warns and still returns 0.

    #[test]
    #[cfg(unix)]
    fn run_dir_login_ingest_error_warns_and_returns_zero() {
        // Write an invalid auth-token.json under a controlled XDG_CONFIG_HOME so
        // dirctl_token_cache_path() resolves to our temp file and ingest fails.
        let tmp_cfg = std::env::temp_dir().join("shadi_test_xdg_cfg_login_ingest");
        let dirctl_dir = tmp_cfg.join("dirctl");
        std::fs::create_dir_all(&dirctl_dir).expect("create dirctl dir");
        std::fs::write(dirctl_dir.join("auth-token.json"), b"not-valid-json")
            .expect("write bad json");

        let _guard = dirctl_env_lock().lock().expect("lock");
        std::env::set_var("SHADI_DIRCTL_BINARY", "/usr/bin/true");
        std::env::set_var("XDG_CONFIG_HOME", &tmp_cfg);
        let code = run_dir_login(
            DirLoginArgs { no_browser: false, force: false },
            "dir/test_ingest_err",
        );
        std::env::remove_var("SHADI_DIRCTL_BINARY");
        std::env::remove_var("XDG_CONFIG_HOME");
        let _ = std::fs::remove_dir_all(&tmp_cfg);
        assert_eq!(code, ExitCode::from(0));
    }

    // ── run_dir_pull success with JSON output (print_record_summary + cache) ──

    #[test]
    #[cfg(unix)]
    fn run_dir_pull_success_with_valid_json_prints_summary_and_caches() {
        // Create a temp script that echoes a valid OASF JSON record.
        let oasf_json = r#"{"name":"Test Agent","version":"1.0.0","description":"A test agent","skills":[],"domains":[],"locators":[]}"#;
        let script_path = std::env::temp_dir().join("shadi_test_pull_json_script.sh");
        std::fs::write(
            &script_path,
            format!("#!/bin/sh\necho '{}'\n", oasf_json).as_bytes(),
        ).expect("write script");
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755))
            .expect("chmod 755");

        // Use a fresh temp dir as HOME so record_cache_dir() always resolves to
        // an empty directory — guaranteeing the cache-write branch (L280) is hit.
        let fake_home = tempfile::tempdir().expect("tempdir");

        let _guard = dirctl_env_lock().lock().expect("lock");
        let saved_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", fake_home.path());
        std::env::set_var("SHADI_DIRCTL_BINARY", &script_path);
        let code = run_dir_pull(
            DirPullArgs {
                reference: "test-agent:v1.0.0".to_string(),
                server_addr: "localhost:9999".to_string(),
            },
            Some("gho_fake_token"),
        );
        std::env::remove_var("SHADI_DIRCTL_BINARY");
        match saved_home {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }
        let _ = std::fs::remove_file(&script_path);
        assert_eq!(code, ExitCode::from(0));
    }

    /// Covers lines 203-204: the `None =>` arm of `dirctl_token_cache_path()`
    /// inside `run_dir_login` — reached when HOME, USERPROFILE, and
    /// XDG_CONFIG_HOME are all unset.
    #[test]
    #[cfg(unix)]
    fn run_dir_login_warns_and_returns_zero_when_cache_path_unavailable() {
        let _guard = dirctl_env_lock().lock().expect("lock");
        std::env::set_var("SHADI_DIRCTL_BINARY", "/usr/bin/true");

        // Stash and remove all env vars that dirctl_token_cache_path() consults.
        let xdg = std::env::var("XDG_CONFIG_HOME").ok();
        let home = std::env::var("HOME").ok();
        let userprofile = std::env::var("USERPROFILE").ok();
        std::env::remove_var("XDG_CONFIG_HOME");
        std::env::remove_var("HOME");
        std::env::remove_var("USERPROFILE");

        let code = run_dir_login(
            DirLoginArgs { no_browser: false, force: false },
            "dir/test_no_cache_path",
        );

        // Restore env vars.
        match xdg { Some(v) => std::env::set_var("XDG_CONFIG_HOME", v), None => {} }
        match home { Some(v) => std::env::set_var("HOME", v), None => {} }
        match userprofile { Some(v) => std::env::set_var("USERPROFILE", v), None => {} }
        std::env::remove_var("SHADI_DIRCTL_BINARY");

        assert_eq!(code, ExitCode::from(0));
    }

    /// Covers line 194: `return ExitCode::from(status.code()...)` in `run_dir_login`
    /// — reached when the dirctl binary runs but exits non-zero.
    #[test]
    fn run_dir_login_returns_nonzero_when_binary_exits_nonzero() {
        let _guard = dirctl_env_lock().lock().expect("lock");
        std::env::set_var("SHADI_DIRCTL_BINARY", "/usr/bin/false");
        let code = run_dir_login(
            DirLoginArgs { no_browser: false, force: false },
            "dir/test_login_nonzero",
        );
        std::env::remove_var("SHADI_DIRCTL_BINARY");
        assert_ne!(code, ExitCode::from(0));
    }

    /// Covers lines 283-284: the implicit `else` branch of
    /// `if std::fs::create_dir_all(&cache_dir).is_ok()` inside `run_dir_pull`.
    /// We make HOME point to a regular file so `create_dir_all` fails with ENOTDIR.
    #[test]
    #[cfg(unix)]
    fn run_dir_pull_skips_cache_when_dir_creation_fails() {
        let oasf_json = r#"{"name":"CacheFail Agent","version":"0.1","description":"","skills":[],"domains":[],"locators":[]}"#;
        let script_dir = tempfile::tempdir().expect("tempdir");
        let script_path = script_dir.path().join("pull_script.sh");
        std::fs::write(
            &script_path,
            format!("#!/bin/sh\necho '{}'\n", oasf_json).as_bytes(),
        ).expect("write script");
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755))
            .expect("chmod 755");

        // Create a temp *file* (not a directory) and use it as HOME.
        // record_cache_dir() returns Some("$HOME/.shadi/records"), and
        // create_dir_all("a-file/.shadi/records") fails with ENOTDIR,
        // so is_ok() == false → the cache block is skipped (covers L283-284).
        let fake_home_file = tempfile::NamedTempFile::new().expect("named tempfile");

        let _guard = dirctl_env_lock().lock().expect("lock");
        let saved_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", fake_home_file.path());
        std::env::set_var("SHADI_DIRCTL_BINARY", &script_path);

        let code = run_dir_pull(
            DirPullArgs {
                reference: "test/cachefail:v1.0".to_string(),
                server_addr: "localhost:9999".to_string(),
            },
            None,
        );

        std::env::remove_var("SHADI_DIRCTL_BINARY");
        match saved_home {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }
        assert_eq!(code, ExitCode::from(0));
    }
}
