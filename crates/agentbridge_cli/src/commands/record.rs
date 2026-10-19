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
use std::sync::{Mutex, OnceLock};

use agentbridge::{load_profile, CliProfile};
use base64::Engine;
use serde_json::Value;

/// The OASF module that carries an agent skill.
pub const AGENT_SKILLS_MODULE: &str = "core/language_model/agentskills";

/// The DIR node `--record` is pulled from by default: a local `dirctl daemon`.
pub const DEFAULT_RECORD_SERVER: &str = "localhost:8888";

const MEDIA_TYPE_MARKDOWN: &str = "application/agent-skills+md";
const MEDIA_TYPE_BUNDLE: &str = "application/agent-skills+gzip";

/// The isolated run's config root, for the adapter, once provisioning is done.
static CONFIG_ROOT: OnceLock<Option<PathBuf>> = OnceLock::new();

/// Every directory `--record` created (the config root, skill folders), each
/// recorded as soon as it is created, so [`cleanup`] removes them however the
/// run ends. Nothing it didn't create is in here.
static CREATED: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

/// Parents created on the way to a skills directory (e.g. `.claude/skills` in
/// the work directory), removed only if they are empty again.
static CREATED_PARENTS: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

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
pub fn prepare(
    opts: &RecordOptions,
    tool: &str,
    workdir: &Path,
) -> anyhow::Result<Option<SourceRecord>> {
    let Some(reference) = opts.reference.as_deref() else {
        return Ok(None);
    };

    let profile = load_profile(tool)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .ok_or_else(|| anyhow::anyhow!("--record needs a harness profile; '{tool}' has none"))?;
    // Remove what was provisioned on SIGTERM, with or without --dir-announce.
    super::announce::on_sigterm();
    let config_root = if profile.is_isolated() {
        Some(config_root_for(tool)?)
    } else {
        None
    };
    let source = provision(
        reference,
        &opts.server,
        &profile,
        config_root.as_deref(),
        workdir,
    )
    .inspect_err(|_| cleanup())?;

    CONFIG_ROOT
        .set(config_root)
        .map_err(|_| anyhow::anyhow!("--record was already prepared"))?;

    Ok(Some(source))
}

/// Write the record's skills where the profile says. Returns the record.
fn provision(
    reference: &str,
    server: &str,
    profile: &CliProfile,
    config_root: Option<&Path>,
    workdir: &Path,
) -> anyhow::Result<SourceRecord> {
    let tool = &profile.id;
    let skills_dir = profile.skills_dir(config_root, workdir).ok_or_else(|| {
        anyhow::anyhow!(
            "profile '{tool}' can't run a DIR record: it has no `provision.skills` section, \
             so there is nowhere to put the record's skills"
        )
    })?;

    if config_root.is_none() {
        eprintln!(
            "[agentbridge] warning: profile '{tool}' isn't isolated. The harness also reads \
             your own configuration (skills, settings, MCP servers, login), and whoever sends \
             it a task can try to make it reveal or use them. The record's skills go into \
             {} and are removed when register stops. Use a profile with `isolation` \
             (claude-code-isolated, codex-isolated) to run the record on its own.",
            skills_dir.display()
        );
    }

    let cid = resolve_cid(reference, server)?;
    let record = pull(&cid, server)?;
    let modules = skill_modules(&record)?;
    let source = source_record(&cid, &record);

    eprintln!(
        "[agentbridge] running DIR record {} {} ({}) from {}; signature: {}",
        printable(&source.name),
        printable(&source.version),
        source.cid,
        server,
        signature_status(&cid, server)
    );

    match config_root {
        Some(root) => {
            rebuild_dir(root)?;
            created(root);
        }
        None => {
            // The harness's own skills directory: never replace a skill
            // that is already there. Checked up front so nothing is written
            // when one is; write_skill still claims each folder exclusively.
            for module in &modules {
                let dir = skills_dir.join(sanitize(&module.name));
                if dir.exists() {
                    anyhow::bail!(
                        "{} already exists; not replacing it with the record's skill '{}'",
                        dir.display(),
                        module.name
                    );
                }
            }
        }
    }

    for module in &modules {
        let dir = write_skill(module, &skills_dir)?;
        eprintln!(
            "[agentbridge] provisioned agent skill '{}' into {}",
            printable(&module.name),
            dir.display()
        );
    }

    Ok(source)
}

fn created(dir: &Path) {
    if let Ok(mut created) = CREATED.lock() {
        created.push(dir.to_path_buf());
    }
}

/// The config root `--record` provisioned, for the adapter to run isolated.
pub fn config_root() -> Option<&'static Path> {
    CONFIG_ROOT.get()?.as_deref()
}

/// Delete what `--record` created, once the harness is done or provisioning
/// failed.
pub fn cleanup() {
    let Ok(mut created) = CREATED.lock() else {
        return;
    };
    for dir in created.drain(..).rev() {
        let _ = std::fs::remove_dir_all(dir);
    }
    drop(created);
    if let Ok(mut parents) = CREATED_PARENTS.lock() {
        for dir in parents.drain(..).rev() {
            let _ = std::fs::remove_dir(dir);
        }
    }
}

/// `create_dir_all(dir)`, recording the directories it had to create.
fn create_parents(dir: &Path) -> std::io::Result<()> {
    let missing: Vec<PathBuf> = dir
        .ancestors()
        .take_while(|d| !d.as_os_str().is_empty() && !d.exists())
        .map(Path::to_path_buf)
        .collect();
    std::fs::create_dir_all(dir)?;
    if let Ok(mut parents) = CREATED_PARENTS.lock() {
        // Outermost first, so cleanup removes the innermost first.
        parents.extend(missing.into_iter().rev());
    }
    Ok(())
}

/// A record's text for the log, with control characters (a `\r`, ANSI
/// escapes) shown escaped instead of acting on the terminal.
fn printable(text: &str) -> String {
    text.chars()
        .flat_map(|c| {
            if c.is_control() {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}

/// Per run: a fresh, private (0700) directory with a random name under
/// `$SHADI_TMP_DIR/agentbridge-record` (writable in the SHADI sandbox), or the
/// temp dir's. The parent must be this user's own real directory, so nobody
/// else can plant configuration (hooks, skills) the harness would load.
fn config_root_for(tool: &str) -> anyhow::Result<PathBuf> {
    let base = std::env::var_os("SHADI_TMP_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let parent = real_path(&base).join("agentbridge-record");
    private_parent(&parent)?;

    let prefix = format!("{}-{}-", sanitize(tool), std::process::id());
    let mut builder = tempfile::Builder::new();
    builder.prefix(&prefix);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    let root = builder
        .tempdir_in(&parent)
        .map_err(|e| {
            anyhow::anyhow!(
                "could not create a config root in {}: {e}. Under `shadictl`, allow it with \
                 `--allow {}`, or leave SHADI_TMP_DIR unset to use the temp dir",
                parent.display(),
                base.display()
            )
        })?
        .keep();
    created(&root);
    Ok(root)
}

/// Create `dir` (0700) if missing, and refuse one that is a symlink or
/// belongs to another user.
fn private_parent(dir: &Path) -> anyhow::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(dir) {
        Ok(()) => return Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => anyhow::bail!(
            "could not create {}: {e}. Under `shadictl`, allow its parent with `--allow`",
            dir.display()
        ),
    }

    let meta = std::fs::symlink_metadata(dir)
        .map_err(|e| anyhow::anyhow!("could not inspect {}: {e}", dir.display()))?;
    if !meta.is_dir() {
        anyhow::bail!(
            "{} is not a directory (a symlink?); not putting a config root there",
            dir.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no preconditions and cannot fail.
        let me = unsafe { libc::geteuid() };
        if meta.uid() != me {
            anyhow::bail!(
                "{} belongs to another user (uid {}); not putting a config root there",
                dir.display(),
                meta.uid()
            );
        }
    }
    Ok(())
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
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir).map_err(|e| {
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

/// Run `dirctl <command> --server-addr <server> --output json -- <operands>`
/// and parse stdout.
fn dirctl_json(args: &[&str], server: &str) -> anyhow::Result<Value> {
    let (command, operands) = args.split_first().unwrap_or((&"", &[]));
    let mut cmd = Command::new(dirctl());
    cmd.arg(command)
        .args(["--server-addr", server, "--output", "json", "--"])
        .args(operands);
    // dirctl needs none of SHADI's or SLIM's settings, seeds included.
    for (key, _) in std::env::vars_os() {
        let key_str = key.to_string_lossy();
        if key_str.starts_with("SHADI_") || key_str.starts_with("SLIM_") {
            cmd.env_remove(&key);
        }
    }
    let output = cmd
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

    let cid = info
        .get("cid")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("dirctl info '{reference}' returned no CID"))?;
    if !is_cid(cid) {
        anyhow::bail!(
            "dirctl info '{reference}' returned {}, which isn't a CID",
            printable(cid)
        );
    }
    Ok(cid.to_string())
}

/// A CID as DIR prints it (multibase, letters and digits only), so it can't
/// pass for a flag or carry anything else into dirctl's arguments.
fn is_cid(cid: &str) -> bool {
    (8..=128).contains(&cid.len()) && cid.bytes().all(|b| b.is_ascii_alphanumeric())
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

/// Write one skill to `<skills_dir>/<name>/`, which must not exist yet (another
/// registration's skill, or a module whose name sanitizes the same); returns
/// that directory.
fn write_skill(module: &SkillModule, skills_dir: &Path) -> anyhow::Result<PathBuf> {
    let dir = skills_dir.join(sanitize(&module.name));
    create_parents(skills_dir)
        .map_err(|e| anyhow::anyhow!("could not create {}: {e}", skills_dir.display()))?;
    match std::fs::create_dir(&dir) {
        Ok(()) => created(&dir),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => anyhow::bail!(
            "{} already exists; not replacing it with the record's skill '{}'",
            dir.display(),
            module.name
        ),
        Err(e) => anyhow::bail!("could not create {}: {e}", dir.display()),
    }

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

/// Most a bundle may unpack to, and how many entries it may have: a skill is
/// a few files, and a small gzip can expand to fill the disk.
const MAX_BUNDLE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_BUNDLE_ENTRIES: usize = 1000;

/// Unpack a gzip-compressed tar of the skill folder into `dir`. Only regular
/// files and directories are taken, each inside `dir` (no absolute paths, no
/// `..`), within [`MAX_BUNDLE_BYTES`] and [`MAX_BUNDLE_ENTRIES`].
fn unpack_bundle(archive: &[u8], dir: &Path) -> std::io::Result<()> {
    let invalid = |msg: String| std::io::Error::new(std::io::ErrorKind::InvalidData, msg);
    // One byte over the limit tells an oversize bundle from one that fits.
    let decoder = flate2::read::GzDecoder::new(archive).take(MAX_BUNDLE_BYTES + 1);
    let mut tar_bytes = Vec::new();
    std::io::BufReader::new(decoder).read_to_end(&mut tar_bytes)?;
    if tar_bytes.len() as u64 > MAX_BUNDLE_BYTES {
        return Err(invalid(format!(
            "bundle unpacks to more than {MAX_BUNDLE_BYTES} bytes"
        )));
    }

    let mut archive = tar::Archive::new(tar_bytes.as_slice());
    for (count, entry) in archive.entries()?.enumerate() {
        if count >= MAX_BUNDLE_ENTRIES {
            return Err(invalid(format!(
                "bundle has more than {MAX_BUNDLE_ENTRIES} entries"
            )));
        }
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let kind = entry.header().entry_type();
        if !(kind.is_file() || kind.is_dir()) {
            return Err(invalid(format!(
                "bundle entry {} is not a regular file or directory",
                path.display()
            )));
        }
        if path.is_absolute()
            || path
                .components()
                .any(|c| !matches!(c, std::path::Component::Normal(_) | std::path::Component::CurDir))
        {
            return Err(invalid(format!(
                "bundle entry {} would land outside the skill folder",
                path.display()
            )));
        }
        if !entry.unpack_in(dir)? {
            return Err(invalid(format!(
                "bundle entry {} would land outside the skill folder",
                path.display()
            )));
        }
    }
    Ok(())
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
                "#!/bin/sh\ncase \"$1\" in\n  info) echo '{{\"cid\":\"bafytestcid\"}}' ;;\n  pull) cat '{}' ;;\n  verify) echo '{{\"errorMessage\":\"no signatures found\"}}' ;;\nesac\n",
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
        let result = provision(
            "code-review",
            "localhost:1",
            &profile,
            Some(root.path()),
            Path::new("/unused"),
        );
        std::env::remove_var("SHADI_DIRCTL_BINARY");

        let source = result.unwrap();
        assert!(
            CREATED.lock().unwrap().contains(&root.path().to_path_buf()),
            "an isolated run removes its root"
        );
        assert_eq!(source.cid, "bafytestcid");
        assert_eq!(
            source.skills,
            vec!["software_engineering/code_debugging/error_handling"]
        );
        assert!(root.path().join("skills/code-review/SKILL.md").is_file());
        assert!(!stale.exists(), "the config root is rebuilt on every start");
    }

    #[test]
    fn a_profile_with_nowhere_to_put_skills_cant_run_a_record() {
        let profile: CliProfile =
            serde_json::from_str(r#"{"id":"plain","bin":"true","execute":{"args":[]}}"#).unwrap();

        let err = provision("x", "localhost:1", &profile, None, Path::new("/w"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("nowhere to put the record's skills"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn a_profile_without_isolation_gets_the_skills_in_its_workdir() {
        let _guard = dirctl_env_lock();
        let (script, _bin) = fake_dirctl("code-review");
        let profile: CliProfile = serde_json::from_str(
            r#"{"id":"plain","bin":"true",
                "provision":{"skills":{"dir":"{workdir}/.claude/skills"}},
                "execute":{"args":[]}}"#,
        )
        .unwrap();
        let work = tempfile::tempdir().unwrap();

        std::env::set_var("SHADI_DIRCTL_BINARY", &script);
        let first = provision("code-review", "localhost:1", &profile, None, work.path());
        let again = provision("code-review", "localhost:1", &profile, None, work.path());
        std::env::remove_var("SHADI_DIRCTL_BINARY");

        first.unwrap();
        let skill = work.path().join(".claude/skills/code-review");
        assert!(CREATED.lock().unwrap().contains(&skill));
        assert!(skill.join("SKILL.md").is_file());
        let err = again.unwrap_err().to_string();
        assert!(err.contains("already exists"), "{err}");
        cleanup();
        assert!(!skill.exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_provision_is_rolled_back_by_cleanup() {
        let _guard = dirctl_env_lock();
        let (script, _bin) = fake_dirctl_serving(json!({
            "name": "two", "version": "1.0.0", "schema_version": "1.1.0",
            "modules": [
                markdown_module("first", "---\nname: first\n---\n"),
                {
                    "name": AGENT_SKILLS_MODULE,
                    "data": { "skill_manifest": { "name": "broken" } },
                    "artifact": {
                        "media_type": MEDIA_TYPE_BUNDLE,
                        "data": b64(&bundle(&[("README.md", "no skill here\n")]))
                    }
                }
            ]
        }));
        let profile: CliProfile = serde_json::from_str(
            r#"{"id":"plain","bin":"true",
                "provision":{"skills":{"dir":"{workdir}/skills"}},
                "execute":{"args":[]}}"#,
        )
        .unwrap();
        let work = tempfile::tempdir().unwrap();
        let mine = work.path().join("skills/mine");
        std::fs::create_dir_all(&mine).unwrap();

        std::env::set_var("SHADI_DIRCTL_BINARY", &script);
        let err = provision("two", "localhost:1", &profile, None, work.path()).unwrap_err();
        std::env::remove_var("SHADI_DIRCTL_BINARY");

        assert!(err.to_string().contains("has no SKILL.md"), "{err}");
        assert!(work.path().join("skills/first/SKILL.md").is_file());
        cleanup();
        assert!(!work.path().join("skills/first").exists());
        assert!(!work.path().join("skills/broken").exists());
        assert!(mine.is_dir(), "only what provisioning created is removed");
    }

    #[cfg(unix)]
    #[test]
    fn two_skills_with_the_same_folder_are_refused() {
        let _guard = dirctl_env_lock();
        let (script, _bin) = fake_dirctl_serving(json!({
            "name": "dup", "version": "1.0.0", "schema_version": "1.1.0",
            "modules": [
                markdown_module("dup", "---\nname: dup\n---\n"),
                markdown_module("dup", "---\nname: dup\n---\n")
            ]
        }));
        let profile: CliProfile = serde_json::from_str(
            r#"{"id":"iso","bin":"true",
                "isolation":{"env":{"HOME":"{config_root}"}},
                "provision":{"skills":{"dir":"{config_root}/skills"}},
                "execute":{"args":[]}}"#,
        )
        .unwrap();
        let root = tempfile::tempdir().unwrap();

        std::env::set_var("SHADI_DIRCTL_BINARY", &script);
        let err = provision(
            "dup",
            "localhost:1",
            &profile,
            Some(root.path()),
            Path::new("/w"),
        )
        .unwrap_err()
        .to_string();
        std::env::remove_var("SHADI_DIRCTL_BINARY");

        assert!(err.contains("already exists"), "{err}");
        cleanup();
        assert!(!root.path().exists());
    }

    /// A gzip'd tar with `entries` written as given, bypassing the `tar`
    /// crate's own path checks: (name, entry type, content, link target).
    fn raw_bundle(entries: &[(&str, tar::EntryType, &str, &str)]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, kind, content, link) in entries {
            let mut header = tar::Header::new_gnu();
            {
                let gnu = header.as_gnu_mut().unwrap();
                gnu.name[..name.len()].copy_from_slice(name.as_bytes());
                gnu.linkname[..link.len()].copy_from_slice(link.as_bytes());
            }
            header.set_entry_type(*kind);
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, content.as_bytes()).unwrap();
        }
        let tar_bytes = builder.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut gz, &tar_bytes).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn a_bundle_cannot_escape_or_link_out_of_the_skill_folder() {
        let regular = tar::EntryType::Regular;
        for (what, entries) in [
            ("..", vec![("../escape.md", regular, "x", "")]),
            ("absolute", vec![("/tmp/escape.md", regular, "x", "")]),
            (
                "symlink",
                vec![("SKILL.md", tar::EntryType::Symlink, "", "/etc/passwd")],
            ),
            (
                "hard link",
                vec![("SKILL.md", tar::EntryType::Link, "", "/etc/passwd")],
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let err = unpack_bundle(&raw_bundle(&entries), dir.path())
                .expect_err(what)
                .to_string();
            assert!(
                err.contains("outside the skill folder") || err.contains("not a regular file"),
                "{what}: {err}"
            );
            assert!(!dir.path().join("SKILL.md").exists(), "{what}");
        }
    }

    #[test]
    fn an_oversize_or_crowded_bundle_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let big = "x".repeat(MAX_BUNDLE_BYTES as usize + 1);
        let err = unpack_bundle(&bundle(&[("SKILL.md", big.as_str())]), dir.path())
            .unwrap_err()
            .to_string();
        assert!(err.contains("more than"), "{err}");

        let names: Vec<String> = (0..=MAX_BUNDLE_ENTRIES).map(|i| format!("f{i}")).collect();
        let files: Vec<(&str, &str)> = names.iter().map(|n| (n.as_str(), "")).collect();
        let err = unpack_bundle(&bundle(&files), dir.path())
            .unwrap_err()
            .to_string();
        assert!(err.contains("entries"), "{err}");
    }

    #[test]
    fn record_text_is_logged_without_control_characters() {
        assert_eq!(
            printable("code-review\r\u{1b}[2Ksignature: trusted"),
            "code-review\\r\\u{1b}[2Ksignature: trusted"
        );
        assert_eq!(printable("plain 1.0.0"), "plain 1.0.0");
    }

    #[test]
    fn only_a_cid_shaped_value_is_passed_to_dirctl() {
        assert!(is_cid("baeareiackl4kjbdnpw2fxofkujd4y5q4akumi6f6jczrb7s26hz5nj636m"));
        assert!(!is_cid("--output=yaml"));
        assert!(!is_cid("bafy test"));
        assert!(!is_cid(""));
    }

    #[cfg(unix)]
    #[test]
    fn parents_made_for_skills_are_removed_when_empty_again() {
        let _guard = dirctl_env_lock();
        let work = tempfile::tempdir().unwrap();
        let skills = work.path().join(".claude/skills");

        create_parents(&skills).unwrap();
        assert!(skills.is_dir());
        cleanup();
        assert!(!work.path().join(".claude").exists());

        // A directory that was already there stays.
        std::fs::create_dir_all(&skills).unwrap();
        create_parents(&skills).unwrap();
        cleanup();
        assert!(skills.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn the_config_root_is_private_and_only_in_a_parent_of_ours() {
        use std::os::unix::fs::PermissionsExt;
        let _guard = dirctl_env_lock();
        let base = tempfile::tempdir().unwrap();
        std::env::set_var("SHADI_TMP_DIR", base.path());

        let root = config_root_for("codex-isolated").unwrap();
        let other = config_root_for("codex-isolated").unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_ne!(root, other, "a random name per run");
        assert_eq!(mode(&root), 0o700);
        assert_eq!(mode(root.parent().unwrap()), 0o700);
        cleanup();

        // A symlinked parent is refused.
        let elsewhere = tempfile::tempdir().unwrap();
        let link_base = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), link_base.path().join("agentbridge-record"))
            .unwrap();
        std::env::set_var("SHADI_TMP_DIR", link_base.path());
        let err = config_root_for("codex-isolated").unwrap_err().to_string();
        std::env::remove_var("SHADI_TMP_DIR");
        assert!(err.contains("not a directory"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn dirctl_gets_the_cid_after_dashes_and_none_of_shadis_settings() {
        use std::os::unix::fs::PermissionsExt;
        let _guard = dirctl_env_lock();
        let bin = tempfile::tempdir().unwrap();
        let log = bin.path().join("log");
        let script = bin.path().join("dirctl");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{log}'\nenv | grep -c '^SLIM_HUMAN_SEED=' >> '{log}'\necho '{{}}'\n",
                log = log.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::env::set_var("SHADI_DIRCTL_BINARY", &script);
        std::env::set_var("SLIM_HUMAN_SEED", "secret-seed");

        let result = pull("bafytestcid", "localhost:1");

        std::env::remove_var("SLIM_HUMAN_SEED");
        std::env::remove_var("SHADI_DIRCTL_BINARY");
        result.unwrap();
        let lines: Vec<String> = std::fs::read_to_string(&log)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        assert_eq!(
            lines,
            ["pull", "--server-addr", "localhost:1", "--output", "json", "--", "bafytestcid", "0"],
            "the last line counts SLIM_HUMAN_SEED in dirctl's environment"
        );
    }

    /// A `dirctl` stand-in serving one agent-skill record named `name`.
    #[cfg(unix)]
    fn fake_dirctl(name: &str) -> (PathBuf, tempfile::TempDir) {
        fake_dirctl_serving(json!({
            "name": name, "version": "1.0.0", "schema_version": "1.1.0",
            "modules": [markdown_module(name, &format!("---\nname: {name}\n---\n"))]
        }))
    }

    /// A `dirctl` stand-in serving `record`.
    #[cfg(unix)]
    fn fake_dirctl_serving(record: Value) -> (PathBuf, tempfile::TempDir) {
        use std::os::unix::fs::PermissionsExt;

        let bin = tempfile::tempdir().unwrap();
        std::fs::write(bin.path().join("record.json"), record.to_string()).unwrap();
        let script = bin.path().join("dirctl");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\ncase \"$1\" in\n  info) echo '{{\"cid\":\"bafytestcid\"}}' ;;\n  pull) cat '{}' ;;\n  verify) echo '{{}}' ;;\nesac\n",
                bin.path().join("record.json").display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        (script, bin)
    }

    /// `SHADI_DIRCTL_BINARY` and friends are process-global.
    fn dirctl_env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }
}
