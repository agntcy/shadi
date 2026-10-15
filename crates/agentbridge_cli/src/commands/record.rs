//! `register --record`: run an agent skill from a DIR record.
//!
//! The record is resolved and pulled from one DIR node with `dirctl`; nothing
//! is pushed anywhere. Every `core/language_model/agentskills` module in it is
//! written into the harness's per-run configuration (`{config_root}`, from the
//! profile's `isolation` and `provision.skills` sections), so the harness starts
//! without the host user's own skills and settings and with the record's.
//!
//! The record's signature is not required: which skill to run is the human's
//! choice. Its name, version, CID and signature status are logged at start so
//! that choice is informed.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use agentbridge::{load_profile, CliProfile};
use base64::Engine;
use serde_json::Value;

/// The OASF module that carries an agent skill.
pub const AGENT_SKILLS_MODULE: &str = "core/language_model/agentskills";

/// The DIR node `--record` is pulled from by default: a local `dirctl daemon`.
pub const DEFAULT_RECORD_SERVER: &str = "localhost:8888";

const MEDIA_TYPE_MARKDOWN: &str = "application/agent-skills+md";
const MEDIA_TYPE_BUNDLE: &str = "application/agent-skills+gzip";

static CONFIG_ROOT: OnceLock<PathBuf> = OnceLock::new();

/// `--record` settings from the command line.
#[derive(Clone, Debug, Default)]
pub struct RecordOptions {
    /// `--record <cid | name[:version][@digest]>`.
    pub reference: Option<String>,
    /// `--record-server`: the DIR node holding the record.
    pub server: String,
}

/// What the agent advertises and announces about the record it runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceRecord {
    pub cid: String,
    pub name: String,
    pub version: String,
    pub schema_version: String,
    pub skills: Vec<String>,
    pub domains: Vec<String>,
}

/// One agent skill taken from a record.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SkillModule {
    name: String,
    media_type: String,
    data: Vec<u8>,
}

/// Pull the record, write its agent skills into a fresh config root for
/// `tool`, and remember the root for the adapter. `Ok(None)` without
/// `--record`.
pub fn prepare(opts: &RecordOptions, tool: &str) -> anyhow::Result<Option<SourceRecord>> {
    let Some(reference) = opts.reference.as_deref() else {
        return Ok(None);
    };

    let profile = load_profile(tool)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .ok_or_else(|| anyhow::anyhow!("--record needs a harness profile; '{tool}' has none"))?;
    let config_root = config_root_for(tool);

    let source = provision(reference, &opts.server, &profile, &config_root)?;

    CONFIG_ROOT
        .set(config_root)
        .map_err(|_| anyhow::anyhow!("--record was already prepared"))?;

    Ok(Some(source))
}

fn provision(
    reference: &str,
    server: &str,
    profile: &CliProfile,
    config_root: &Path,
) -> anyhow::Result<SourceRecord> {
    let tool = &profile.id;
    let skills_dir = profile.skills_dir(config_root).ok_or_else(|| {
        anyhow::anyhow!(
            "profile '{tool}' can't run a DIR record: it has no `isolation` and \
             `provision.skills` sections, so the harness would read the host user's \
             configuration and has nowhere to receive the skill. The bundled profiles \
             that can are claude-code-isolated and codex-isolated"
        )
    })?;

    let cid = resolve_cid(reference, server)?;
    let record = pull(&cid, server)?;
    let modules = skill_modules(&record)?;
    let source = source_record(&cid, &record);

    eprintln!(
        "[agentbridge] running DIR record {} {} ({}) from {}; signature: {}",
        source.name,
        source.version,
        source.cid,
        server,
        signature_status(&cid, server)
    );

    rebuild_dir(config_root)?;
    for module in &modules {
        let dir = write_skill(module, &skills_dir)?;
        eprintln!(
            "[agentbridge] provisioned agent skill '{}' into {}",
            module.name,
            dir.display()
        );
    }

    Ok(source)
}

/// The config root `--record` provisioned, for the adapter to run isolated.
pub fn config_root() -> Option<&'static Path> {
    CONFIG_ROOT.get().map(PathBuf::as_path)
}

/// Delete the config root `--record` provisioned, once the harness is done.
pub fn cleanup() {
    if let Some(root) = config_root() {
        let _ = std::fs::remove_dir_all(root);
    }
}

/// Per run: under `$SHADI_TMP_DIR` (writable in the SHADI sandbox), named by
/// tool and PID so instances don't share one.
fn config_root_for(tool: &str) -> PathBuf {
    let base = std::env::var_os("SHADI_TMP_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    real_path(&base).join("agentbridge-record").join(format!(
        "{}-{}",
        sanitize(tool),
        std::process::id()
    ))
}

/// `path` without symlinks, so a harness that canonicalizes its config
/// directory (codex does, for `CODEX_HOME`) needn't read a symlink the sandbox
/// hides. On macOS the temp dir is under `/var`, a symlink to `/private/var`
/// that the sandbox doesn't let a process resolve.
fn real_path(path: &Path) -> PathBuf {
    if let Ok(real) = std::fs::canonicalize(path) {
        return real;
    }
    if cfg!(target_os = "macos") {
        for link in ["/var", "/tmp", "/etc"] {
            if path == Path::new(link) || path.starts_with(format!("{link}/")) {
                return Path::new("/private").join(path.strip_prefix("/").unwrap_or(path));
            }
        }
    }
    path.to_path_buf()
}

fn rebuild_dir(dir: &Path) -> anyhow::Result<()> {
    match std::fs::remove_dir_all(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => anyhow::bail!("could not clear {}: {e}", dir.display()),
    }
    std::fs::create_dir_all(dir).map_err(|e| {
        let hint = if e.kind() == std::io::ErrorKind::PermissionDenied {
            let parent = dir.parent().unwrap_or(dir);
            format!(
                ". Under `shadictl`, allow it with `--allow {}`, or leave SHADI_TMP_DIR unset \
                 to use the temp dir",
                parent.display()
            )
        } else {
            String::new()
        };
        anyhow::anyhow!("could not create {}: {e}{hint}", dir.display())
    })
}

fn dirctl() -> String {
    std::env::var("SHADI_DIRCTL_BINARY").unwrap_or_else(|_| "dirctl".to_string())
}

/// Run `dirctl <args> --server-addr <server> --output json` and parse stdout.
fn dirctl_json(args: &[&str], server: &str) -> anyhow::Result<Value> {
    let output = Command::new(dirctl())
        .args(args)
        .args(["--server-addr", server, "--output", "json"])
        .output()
        .map_err(|e| {
            let binary = dirctl();
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                anyhow::anyhow!(
                    "could not run dirctl ({binary}): {e}. The SHADI sandbox may not allow \
                     running programs from that path (paths through the /tmp symlink are \
                     refused); put it under $HOME or use the real path (/private/tmp/…)"
                )
            } else {
                anyhow::anyhow!(
                    "could not run dirctl ({binary}): {e}; install it or set SHADI_DIRCTL_BINARY. \
                     brew tap agntcy/dir https://github.com/agntcy/dir/ && brew install dirctl"
                )
            }
        })?;

    if !output.status.success() {
        anyhow::bail!(
            "dirctl {} failed: {}",
            args.join(" "),
            first_line(&String::from_utf8_lossy(&output.stderr))
        );
    }

    serde_json::from_slice(&output.stdout)
        .map_err(|e| anyhow::anyhow!("dirctl {} printed no JSON: {e}", args.join(" ")))
}

/// The first non-empty line of dirctl's stderr: its error, without a panic's
/// stack trace.
fn first_line(stderr: &str) -> &str {
    stderr
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("no output")
}

/// The CID a reference (CID or name[:version][@digest]) resolves to.
fn resolve_cid(reference: &str, server: &str) -> anyhow::Result<String> {
    let info = dirctl_json(&["info", reference], server).map_err(|e| {
        anyhow::anyhow!(
            "could not find record '{reference}' on {server}: {e}\n\
             Under `shadictl --net-block`, dirctl needs `--net-allow {server}` and \
             `--read ~/.dir --read ~/.config/dirctl`."
        )
    })?;

    info.get("cid")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("dirctl info '{reference}' returned no CID"))
}

fn pull(cid: &str, server: &str) -> anyhow::Result<Value> {
    dirctl_json(&["pull", cid], server)
}

/// "unsigned (…)" or "trusted, signed by …", for the start-up log. Never fails:
/// the signature is informative, not required.
fn signature_status(cid: &str, server: &str) -> String {
    match dirctl_json(&["verify", cid], server) {
        Ok(value) => describe_verification(&value),
        Err(e) => format!("unknown ({e})"),
    }
}

fn describe_verification(value: &Value) -> String {
    if value.get("success").and_then(Value::as_bool) == Some(true) {
        let signers: Vec<String> = value
            .get("signers")
            .and_then(Value::as_array)
            .map(|signers| signers.iter().map(Value::to_string).collect())
            .unwrap_or_default();
        if signers.is_empty() {
            return "trusted".to_string();
        }
        return format!("trusted, signed by {}", signers.join(", "));
    }

    let reason = value
        .get("errorMessage")
        .and_then(Value::as_str)
        .unwrap_or("not verified");
    format!("not trusted ({reason})")
}

fn class_names(record: &Value, key: &str) -> Vec<String> {
    record
        .get(key)
        .and_then(Value::as_array)
        .map(|classes| {
            classes
                .iter()
                .filter_map(|c| c.get("name").and_then(Value::as_str))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn text(record: &Value, key: &str) -> String {
    record
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn source_record(cid: &str, record: &Value) -> SourceRecord {
    SourceRecord {
        cid: cid.to_string(),
        name: text(record, "name"),
        version: text(record, "version"),
        schema_version: text(record, "schema_version"),
        skills: class_names(record, "skills"),
        domains: class_names(record, "domains"),
    }
}

/// Every agent skill in the record. A record without one (e.g. an A2A-only
/// record) can't be run by a harness.
fn skill_modules(record: &Value) -> anyhow::Result<Vec<SkillModule>> {
    let record_name = text(record, "name");
    let mut modules = Vec::new();

    for module in record
        .get("modules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if module.get("name").and_then(Value::as_str) != Some(AGENT_SKILLS_MODULE) {
            continue;
        }

        let name = module
            .pointer("/data/skill_manifest/name")
            .and_then(Value::as_str)
            .unwrap_or(&record_name)
            .to_string();
        let artifact = module.get("artifact").ok_or_else(|| {
            anyhow::anyhow!("agent skill '{name}' in the record carries no artifact")
        })?;
        let media_type = text(artifact, "media_type");
        let data = base64::engine::general_purpose::STANDARD
            .decode(text(artifact, "data"))
            .map_err(|e| anyhow::anyhow!("agent skill '{name}': artifact isn't base64: {e}"))?;

        modules.push(SkillModule {
            name,
            media_type,
            data,
        });
    }

    if modules.is_empty() {
        anyhow::bail!(
            "record '{record_name}' has no agent skill ({AGENT_SKILLS_MODULE} module); \
             only agent-skill records can be run"
        );
    }

    Ok(modules)
}

/// Write one skill to `<skills_dir>/<name>/`; returns that directory.
fn write_skill(module: &SkillModule, skills_dir: &Path) -> anyhow::Result<PathBuf> {
    let dir = skills_dir.join(sanitize(&module.name));
    std::fs::create_dir_all(&dir)
        .map_err(|e| anyhow::anyhow!("could not create {}: {e}", dir.display()))?;

    match module.media_type.as_str() {
        MEDIA_TYPE_MARKDOWN => std::fs::write(dir.join("SKILL.md"), &module.data)
            .map_err(|e| anyhow::anyhow!("could not write SKILL.md for '{}': {e}", module.name))?,
        MEDIA_TYPE_BUNDLE => unpack_bundle(&module.data, &dir)
            .map_err(|e| anyhow::anyhow!("could not unpack skill bundle '{}': {e}", module.name))?,
        other => anyhow::bail!(
            "agent skill '{}' has an unknown artifact type '{other}'",
            module.name
        ),
    }

    if !dir.join("SKILL.md").is_file() {
        anyhow::bail!("agent skill '{}' has no SKILL.md", module.name);
    }

    Ok(dir)
}

/// Unpack a gzip-compressed tar of the skill folder into `dir`. Entries that
/// would land outside it (absolute paths, `..`) are refused by `tar`.
fn unpack_bundle(archive: &[u8], dir: &Path) -> std::io::Result<()> {
    let mut decoder = flate2::read::GzDecoder::new(archive);
    let mut tar_bytes = Vec::new();
    decoder.read_to_end(&mut tar_bytes)?;
    tar::Archive::new(tar_bytes.as_slice()).unpack(dir)
}

/// A directory name from a skill or tool name.
fn sanitize(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let cleaned = cleaned.trim_matches('.').to_string();
    if cleaned.is_empty() {
        "skill".to_string()
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn markdown_module(name: &str, body: &str) -> Value {
        json!({
            "name": AGENT_SKILLS_MODULE,
            "data": { "skill_file": "SKILL.md", "skill_manifest": { "name": name } },
            "artifact": { "media_type": MEDIA_TYPE_MARKDOWN, "data": b64(body.as_bytes()) }
        })
    }

    fn bundle(files: &[(&str, &str)]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, content) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, path, content.as_bytes())
                .unwrap();
        }
        let tar_bytes = builder.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut gz, &tar_bytes).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn source_record_reads_name_version_and_classes() {
        let record = json!({
            "name": "code-review", "version": "1.0.0", "schema_version": "1.1.0",
            "skills": [{ "name": "software_engineering/code_debugging/error_handling" }],
            "domains": [{ "name": "technology/software_engineering" }],
        });

        assert_eq!(
            source_record("bafy", &record),
            SourceRecord {
                cid: "bafy".into(),
                name: "code-review".into(),
                version: "1.0.0".into(),
                schema_version: "1.1.0".into(),
                skills: vec!["software_engineering/code_debugging/error_handling".into()],
                domains: vec!["technology/software_engineering".into()],
            }
        );
    }

    #[test]
    fn every_agent_skill_module_is_taken() {
        let record = json!({
            "name": "pair",
            "modules": [
                markdown_module("code-review", "---\nname: code-review\n---\n"),
                { "name": "integration/a2a", "data": {} },
                markdown_module("summarize", "---\nname: summarize\n---\n"),
            ]
        });

        let names: Vec<String> = skill_modules(&record)
            .unwrap()
            .into_iter()
            .map(|m| m.name)
            .collect();
        assert_eq!(names, vec!["code-review", "summarize"]);
    }

    #[test]
    fn a_record_without_an_agent_skill_is_rejected() {
        let record = json!({
            "name": "a2a-only",
            "modules": [{ "name": "integration/a2a", "data": {} }]
        });

        let err = skill_modules(&record).unwrap_err().to_string();
        assert!(err.contains("has no agent skill"), "{err}");
    }

    #[test]
    fn a_markdown_skill_is_written_as_skill_md() {
        let dir = tempfile::tempdir().unwrap();
        let record = json!({
            "name": "code-review",
            "modules": [markdown_module("code-review", "---\nname: code-review\n---\nReview.\n")]
        });

        let module = &skill_modules(&record).unwrap()[0];
        let written = write_skill(module, dir.path()).unwrap();

        assert_eq!(written, dir.path().join("code-review"));
        assert_eq!(
            std::fs::read_to_string(written.join("SKILL.md")).unwrap(),
            "---\nname: code-review\n---\nReview.\n"
        );
    }

    #[test]
    fn a_bundle_is_unpacked_into_the_skill_folder() {
        let dir = tempfile::tempdir().unwrap();
        let module = SkillModule {
            name: "tools".into(),
            media_type: MEDIA_TYPE_BUNDLE.into(),
            data: bundle(&[
                ("SKILL.md", "---\nname: tools\n---\n"),
                ("scripts/run.sh", "echo hi\n"),
            ]),
        };

        let written = write_skill(&module, dir.path()).unwrap();

        assert!(written.join("SKILL.md").is_file());
        assert_eq!(
            std::fs::read_to_string(written.join("scripts/run.sh")).unwrap(),
            "echo hi\n"
        );
    }

    #[test]
    fn a_bundle_without_skill_md_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let module = SkillModule {
            name: "empty".into(),
            media_type: MEDIA_TYPE_BUNDLE.into(),
            data: bundle(&[("README.md", "no skill here\n")]),
        };

        let err = write_skill(&module, dir.path()).unwrap_err().to_string();
        assert!(err.contains("has no SKILL.md"), "{err}");
    }

    #[test]
    fn real_path_resolves_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let real = std::fs::canonicalize(dir.path()).unwrap();
        assert_eq!(real_path(dir.path()), real);
        assert!(!real_path(dir.path()).starts_with("/var/"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn real_path_falls_back_to_private_on_macos() {
        assert_eq!(
            real_path(Path::new("/var/does-not-exist/x")),
            Path::new("/private/var/does-not-exist/x")
        );
        assert_eq!(real_path(Path::new("/variable")), Path::new("/variable"));
    }

    #[test]
    fn skill_names_cannot_escape_the_skills_dir() {
        assert_eq!(sanitize("../../etc"), "-..-etc");
        assert_eq!(sanitize(".."), "skill");
        assert_eq!(sanitize("org.agntcy/code review"), "org.agntcy-code-review");
    }

    #[test]
    fn verification_is_described_for_the_log() {
        assert_eq!(
            describe_verification(&json!({ "errorMessage": "no signatures found" })),
            "not trusted (no signatures found)"
        );
        assert_eq!(
            describe_verification(&json!({ "success": true })),
            "trusted"
        );
    }

    #[test]
    fn a_missing_dirctl_is_explained() {
        let _guard = dirctl_env_lock();
        std::env::set_var("SHADI_DIRCTL_BINARY", "/nonexistent/dirctl");
        let err = resolve_cid("code-review", "localhost:1")
            .unwrap_err()
            .to_string();
        std::env::remove_var("SHADI_DIRCTL_BINARY");
        assert!(err.contains("could not run dirctl"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn provision_writes_the_records_skills_with_a_fake_dirctl() {
        use std::os::unix::fs::PermissionsExt;

        let _guard = dirctl_env_lock();
        let bin = tempfile::tempdir().unwrap();
        let record = json!({
            "name": "code-review", "version": "1.0.0", "schema_version": "1.1.0",
            "skills": [{ "name": "software_engineering/code_debugging/error_handling" }],
            "modules": [markdown_module("code-review", "---\nname: code-review\n---\n")]
        });
        std::fs::write(bin.path().join("record.json"), record.to_string()).unwrap();
        let script = bin.path().join("dirctl");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\ncase \"$1\" in\n  info) echo '{{\"cid\":\"bafy-test\"}}' ;;\n  pull) cat '{}' ;;\n  verify) echo '{{\"errorMessage\":\"no signatures found\"}}' ;;\nesac\n",
                bin.path().join("record.json").display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        let profile: CliProfile = serde_json::from_str(
            r#"{"id":"record-test","bin":"true",
                "isolation":{"env":{"HOME_DIR":"{config_root}"}},
                "provision":{"skills":{"dir":"{config_root}/skills"}},
                "execute":{"args":[]}}"#,
        )
        .unwrap();
        let root = tempfile::tempdir().unwrap();
        let stale = root.path().join("stale.txt");
        std::fs::write(&stale, "from a previous run").unwrap();

        std::env::set_var("SHADI_DIRCTL_BINARY", &script);
        let result = provision("code-review", "localhost:1", &profile, root.path());
        std::env::remove_var("SHADI_DIRCTL_BINARY");

        let source = result.unwrap();
        assert_eq!(source.cid, "bafy-test");
        assert_eq!(
            source.skills,
            vec!["software_engineering/code_debugging/error_handling"]
        );
        assert!(root.path().join("skills/code-review/SKILL.md").is_file());
        assert!(!stale.exists(), "the config root is rebuilt on every start");
    }

    #[test]
    fn a_profile_without_isolation_cant_run_a_record() {
        let profile: CliProfile =
            serde_json::from_str(r#"{"id":"plain","bin":"true","execute":{"args":[]}}"#).unwrap();

        let err = provision("x", "localhost:1", &profile, Path::new("/nonexistent"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("can't run a DIR record"), "{err}");
    }

    /// `SHADI_DIRCTL_BINARY` and friends are process-global.
    fn dirctl_env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }
}
