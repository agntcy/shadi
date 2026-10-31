use super::*;

use shadi_credential::{CredentialRecord, CredentialVault, Disclosure, VaultBackend};

pub(crate) fn run_credential_command(cli: CredentialCli) -> ExitCode {
    if let CredentialCommand::FetchJwks { idp, out } = &cli.command {
        return run_fetch_jwks(idp, out);
    }
    let vault = match open_vault(&cli) {
        Ok(vault) => vault,
        Err(err) => {
            eprintln!("{}", err);
            return ExitCode::from(1);
        }
    };
    match &cli.command {
        CredentialCommand::Issue { .. } => run_issue(&cli.command, vault.as_ref()),
        other => match handle_credential_command(other, vault.as_ref()) {
            Ok(output) => {
                println!("{}", output);
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("{}", err);
                ExitCode::from(1)
            }
        },
    }
}

fn open_vault(cli: &CredentialCli) -> Result<Box<dyn CredentialVault>, String> {
    let backend = choose_backend(
        cli.backend.as_deref(),
        cli.db.is_some() || cli.key.is_some(),
        shadi_credential::default_backend,
    )?;

    // Resolving the key unlocks the database, so only do it for the backend
    // that needs one: on a machine with no secret store the keychain path
    // would otherwise fail on a key it never uses.
    let key = match backend {
        VaultBackend::SqlCipher => Some(resolve_credential_key(cli)?),
        VaultBackend::Keychain => None,
    };

    shadi_credential::default_vault(backend, cli.db.as_deref(), key.as_deref())
        .map_err(|err| err.to_string())
}

/// An explicit backend is an instruction and is never second-guessed. Without
/// one, naming a database or key only makes sense for sqlcipher, so it must not
/// be silently ignored in favour of the keychain. Both vars are vault-specific,
/// so an exported one counts the same as a flag.
fn choose_backend(
    explicit: Option<&str>,
    db_or_key_given: bool,
    default: impl FnOnce() -> VaultBackend,
) -> Result<VaultBackend, String> {
    match explicit {
        Some(name) => name.parse(),
        None if db_or_key_given => Ok(VaultBackend::SqlCipher),
        None => Ok(default()),
    }
}

/// The vault's own key, never the memory one — the two databases are separate
/// so that reading credentials does not also unlock memory.
fn resolve_credential_key(cli: &CredentialCli) -> Result<String, String> {
    if let Some(key) = cli.key.as_deref() {
        if key.is_empty() {
            return Err("SHADI_CREDENTIAL_KEY is empty".to_string());
        }
        return Ok(key.to_string());
    }

    let secret = default_secret_store()
        .get(&cli.key_name)
        .map_err(|_| format!("missing SHADI key: {}", cli.key_name))?;
    let raw = secret.expose(|bytes| bytes.to_vec());
    String::from_utf8(raw).map_err(|_| "the credential vault key is not utf-8".to_string())
}

pub(crate) fn handle_credential_command(
    command: &CredentialCommand,
    vault: &dyn CredentialVault,
) -> Result<String, String> {
    let span = info_span!(
        "shadi.credential.command",
        credential.command = field::Empty,
        credential.id = field::Empty,
    );
    let _guard = span.enter();

    match command {
        CredentialCommand::List { json } => {
            span.record("credential.command", &"list");
            let records = vault.list().map_err(|err| err.to_string())?;
            let summaries: Vec<_> = records
                .iter()
                .map(|record| summarise(record, false))
                .collect();
            if *json {
                return serde_json::to_string_pretty(&summaries).map_err(|err| err.to_string());
            }
            Ok(format_summaries(&summaries))
        }
        CredentialCommand::Show { id, disclose, json } => {
            span.record("credential.command", &"show");
            span.record("credential.id", &field::display(id));
            let record = vault
                .get(id)
                .map_err(|err| err.to_string())?
                .ok_or_else(|| format!("no credential with id {id}"))?;
            let summary = summarise(&record, *disclose);
            if *json {
                return serde_json::to_string_pretty(&summary).map_err(|err| err.to_string());
            }
            Ok(format_summaries(std::slice::from_ref(&summary)))
        }
        CredentialCommand::Delete { id } => {
            span.record("credential.command", &"delete");
            span.record("credential.id", &field::display(id));
            let deleted = vault.delete(id).map_err(|err| err.to_string())?;
            Ok(json!({ "deleted": deleted }).to_string())
        }
        CredentialCommand::Import { file } => {
            span.record("credential.command", &"import");
            let raw = std::fs::read_to_string(file)
                .map_err(|err| format!("failed to read {}: {}", file.display(), err))?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| "system clock is before the unix epoch".to_string())?
                .as_secs() as i64;
            let record =
                shadi_credential::import(vault, &raw, now).map_err(|err| err.to_string())?;
            span.record("credential.id", &field::display(&record.id));
            Ok(json!({
                "status": "imported",
                "id": record.id,
                "credential_type": record.credential_type,
                "format": record.format,
                "issuer": record.issuer,
                "agent_did": record.agent_did,
                "expires_at": record.expires_at,
            })
            .to_string())
        }
        CredentialCommand::Issue { .. } => Err("issue is handled by run_issue".to_string()),
        CredentialCommand::FetchJwks { .. } => {
            Err("fetch-jwks is handled by run_fetch_jwks".to_string())
        }
    }
}

fn run_fetch_jwks(idp: &str, out: &std::path::Path) -> ExitCode {
    match crate::credential_issue::client().and_then(|http| fetch_jwks_file(&http, idp, out)) {
        Ok(report) => {
            println!("{report}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

/// Checks the document before `out` exists, so a rejected one leaves no file.
/// The issuer line is the exact string the policy's `iss` must carry.
pub(crate) fn fetch_jwks_file(
    http: &dyn crate::credential_issue::Http,
    idp: &str,
    out: &std::path::Path,
) -> Result<String, String> {
    let (issuer, text) = crate::credential_issue::fetch_jwks(http, idp)?;
    let mut store = shadi_credential::JwksStore::new();
    store.add_json(&issuer, &text).map_err(|err| err.to_string())?;
    let doc: Value = serde_json::from_str(&text).map_err(|err| err.to_string())?;
    let usable = doc["keys"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|jwk| jwk["kid"].as_str())
        .filter(|kid| store.key(&issuer, Some(kid)).is_ok())
        .count();
    std::fs::write(out, &text)
        .map_err(|err| format!("failed to write {}: {}", out.display(), err))?;
    Ok(format!(
        "issuer: {issuer}\nusable keys: {usable}\nwrote: {}",
        out.display()
    ))
}

/// Always a JSON array, one entry per agent; any failure is a nonzero exit.
fn run_issue(command: &CredentialCommand, vault: &dyn CredentialVault) -> ExitCode {
    let CredentialCommand::Issue {
        idp,
        client_id,
        email,
        configuration_id,
        agent,
        key_prefix,
    } = command
    else {
        return ExitCode::from(1);
    };
    let span = info_span!(
        "shadi.credential.command",
        credential.command = "issue",
        credential.agents = field::Empty,
    );
    let _guard = span.enter();

    let result = (|| {
        let identities = agent_identities(key_prefix, agent)?;
        span.record("credential.agents", identities.len());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "system clock is before the unix epoch".to_string())?
            .as_secs() as i64;
        let http = crate::credential_issue::client()?;
        crate::credential_issue::issue_all(
            &http,
            vault,
            &identities,
            &crate::credential_issue::IssueArgs {
                idp,
                client_id,
                email,
                configuration_id,
            },
            now,
        )
    })();

    match result {
        Ok(results) => {
            let failed = results.iter().any(|(_, outcome)| outcome.is_err());
            println!("{}", issue_report(&results));
            if failed {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(err) => {
            eprintln!("{}", err);
            ExitCode::from(1)
        }
    }
}

/// Deduplicated in order, since nothing replaces a stored credential. Loaded
/// up front so a missing key costs no interactive login.
fn agent_identities(
    prefix: &str,
    agents: &[String],
) -> Result<Vec<(String, shadi_identity::AgentIdentity)>, String> {
    let mut identities: Vec<(String, shadi_identity::AgentIdentity)> = Vec::new();
    for name in agents {
        if identities.iter().all(|(seen, _)| seen != name) {
            identities.push((name.clone(), agent_identity(prefix, name)?));
        }
    }
    Ok(identities)
}

fn issue_report(results: &[(String, Result<CredentialRecord, String>)]) -> String {
    let entries: Vec<Value> = results
        .iter()
        .map(|(agent, outcome)| match outcome {
            Ok(record) => json!({
                "agent": agent,
                "status": "issued",
                "id": record.id,
                "credential_type": record.credential_type,
                "format": record.format,
                "issuer": record.issuer,
                "agent_did": record.agent_did,
                "expires_at": record.expires_at,
            }),
            Err(error) => json!({ "agent": agent, "status": "failed", "error": error }),
        })
        .collect();
    Value::Array(entries).to_string()
}

/// The derived agent key that signs the proof of possession.
fn agent_identity(prefix: &str, agent: &str) -> Result<shadi_identity::AgentIdentity, String> {
    let name = format!("{prefix}/{agent}/private");
    let secret = default_secret_store()
        .get(&name)
        .map_err(|_| format!("missing SHADI key: {name}"))?;
    let encoded = secret.expose(|bytes| bytes.to_vec());
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| format!("the secret {name} is not base64"))?;
    shadi_identity::AgentIdentity::from_signing_key_slice(&bytes)
        .map_err(|_| format!("the secret {name} is not a 32-byte signing key"))
}

/// What may be printed about a credential. Never the credential itself, and
/// never a claim value unless `disclose` asked for it.
#[derive(Serialize)]
struct CredentialSummary {
    id: String,
    credential_type: String,
    format: String,
    issuer: String,
    agent_did: String,
    created_at: i64,
    /// `null` when the credential carries no `exp` — non-expiring.
    expires_at: Option<i64>,
    claims: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    disclosed: Option<Vec<Value>>,
    /// Why `claims` is empty, when the reason is that `raw` could not be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    unreadable: Option<String>,
}

/// The columns are always printable; the claims are not, so a credential this
/// binary cannot parse is still listed rather than failing the whole command.
fn summarise(record: &CredentialRecord, disclose: bool) -> CredentialSummary {
    let mut summary = CredentialSummary {
        id: record.id.clone(),
        credential_type: record.credential_type.clone(),
        format: record.format.clone(),
        issuer: record.issuer.clone(),
        agent_did: record.agent_did.clone(),
        created_at: record.created_at,
        expires_at: record.expires_at,
        claims: Vec::new(),
        disclosed: None,
        unreadable: None,
    };

    match disclosures(record) {
        Ok(disclosures) => {
            summary.claims = disclosures.iter().map(claim_name).collect();
            if disclose {
                // A list, not a map: array elements have no name and
                // names may repeat, so any key would collapse entries.
                summary.disclosed = Some(
                    disclosures
                        .iter()
                        .map(|d| json!({ "name": d.name, "value": d.value }))
                        .collect(),
                );
            }
        }
        Err(err) => summary.unreadable = Some(err),
    }
    summary
}

/// Only a format this binary knows how to read is parsed; the vault stores
/// others verbatim and nothing here may assume they are SD-JWT.
fn disclosures(record: &CredentialRecord) -> Result<Vec<Disclosure>, String> {
    if record.format != shadi_credential::SD_JWT_FORMAT {
        return Err(format!("unsupported format {}", record.format));
    }
    shadi_credential::parse_sd_jwt(&record.raw)
        .map(|parsed| parsed.disclosures)
        .map_err(|err| err.to_string())
}

/// Array-element disclosures have no claim name.
fn claim_name(disclosure: &Disclosure) -> String {
    disclosure
        .name
        .clone()
        .unwrap_or_else(|| "<array element>".to_string())
}

fn format_summaries(summaries: &[CredentialSummary]) -> String {
    if summaries.is_empty() {
        return "no credentials".to_string();
    }
    summaries
        .iter()
        .map(|summary| {
            let expires = match summary.expires_at {
                Some(exp) => exp.to_string(),
                None => "never".to_string(),
            };
            let claims = match summary.unreadable.as_deref() {
                Some(reason) => format!("(unreadable: {reason})"),
                None if summary.claims.is_empty() => "(none)".to_string(),
                None => summary.claims.join(", "),
            };
            let mut text = format!(
                "{}\n  type:      {}\n  format:    {}\n  issuer:    {}\n  agent:     {}\n  expires:   {}\n  claims:    {}",
                summary.id,
                summary.credential_type,
                summary.format,
                summary.issuer,
                summary.agent_did,
                expires,
                claims,
            );
            if let Some(disclosed) = summary.disclosed.as_ref() {
                text.push_str("\n  disclosed:");
                for entry in disclosed {
                    let name = entry["name"].as_str().unwrap_or("<array element>");
                    text.push_str(&format!("\n    {name}: {}", entry["value"]));
                }
            }
            text
        })
        .collect::<Vec<_>>()
        .join("\n\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;
    use shadi_credential::SqlCipherVault;

    fn vault() -> SqlCipherVault {
        let file = tempfile::NamedTempFile::new().expect("tempfile");
        let path = file.path().to_path_buf();
        std::mem::forget(file);
        SqlCipherVault::open(&path, "test-key").expect("open vault")
    }

    /// `dc+sd-jwt`, one disclosure, trailing tilde, no key-binding JWT.
    fn fixture() -> String {
        fixture_with(&[json!(["c2FsdA", "groups", "platform-admins"])])
    }

    /// The same credential carrying exactly `disclosures`.
    fn fixture_with(disclosures: &[Value]) -> String {
        let b64 = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let key =
            ed25519_dalek::VerifyingKey::from(&ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]));
        let segments: Vec<String> = disclosures
            .iter()
            .map(|d| b64(d.to_string().as_bytes()))
            .collect();
        let sd: Vec<String> = segments
            .iter()
            .map(|s| b64(&sha2::Sha256::digest(s.as_bytes())))
            .collect();
        let payload = json!({
            "iss": "https://idp.example/realms/eng",
            "vct": "urn:shadi:agent-admission:1",
            "exp": 2_000,
            "_sd": sd,
            "cnf": { "jwk": { "kty": "OKP", "crv": "Ed25519", "x": b64(key.as_bytes()) } },
        });
        let mut raw = format!(
            "{}.{}.c2ln~",
            b64(br#"{"alg":"EdDSA","typ":"dc+sd-jwt"}"#),
            b64(payload.to_string().as_bytes()),
        );
        for segment in &segments {
            raw.push_str(segment);
            raw.push('~');
        }
        raw
    }

    /// The same credential with nothing disclosable — legal, and the operator
    /// commands have to render it.
    fn fixture_without_disclosures() -> String {
        let raw = fixture();
        let (issuer_jwt, _) = raw.split_once('~').expect("tilde");
        format!("{issuer_jwt}~")
    }

    /// A stored record, for the cases import would refuse to create.
    fn record(id: &str) -> CredentialRecord {
        CredentialRecord {
            id: id.to_string(),
            agent_did: "did:key:zAgent".to_string(),
            issuer: "https://idp.example/realms/eng".to_string(),
            credential_type: "urn:shadi:agent-admission:1".to_string(),
            format: "dc+sd-jwt".to_string(),
            raw: fixture(),
            created_at: 1_000,
            expires_at: None,
        }
    }

    fn import_fixture(vault: &dyn CredentialVault) -> String {
        shadi_credential::import(vault, &fixture(), 1_000)
            .expect("import")
            .id
    }

    /// A `CredentialCli` pinned to sqlcipher.
    fn cli(db: Option<PathBuf>, key: Option<&str>, command: CredentialCommand) -> CredentialCli {
        CredentialCli {
            db,
            key: key.map(str::to_string),
            key_name: "shadi/credential/absent-in-tests".to_string(),
            backend: Some("sqlcipher".to_string()),
            command,
        }
    }

    fn list() -> CredentialCommand {
        CredentialCommand::List { json: false }
    }

    #[test]
    fn import_accepts_a_hand_issued_credential() {
        let vault = vault();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("credential.txt");
        std::fs::write(&path, fixture()).expect("write");

        let output = handle_credential_command(&CredentialCommand::Import { file: path }, &vault)
            .expect("import");
        assert!(output.contains("imported"), "{output}");
        assert_eq!(vault.list().expect("list").len(), 1);
    }

    #[test]
    fn import_rejects_a_non_parseable_credential_with_a_reason() {
        let vault = vault();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("credential.txt");
        std::fs::write(&path, "not-an-sd-jwt").expect("write");

        let err = handle_credential_command(&CredentialCommand::Import { file: path }, &vault)
            .expect_err("reject");
        assert!(err.contains("malformed credential"), "{err}");
        assert!(vault.list().expect("list").is_empty());
    }

    #[test]
    fn list_names_the_claims_but_never_their_values() {
        let vault = vault();
        import_fixture(&vault);

        for json in [false, true] {
            let output =
                handle_credential_command(&CredentialCommand::List { json }, &vault).expect("list");
            assert!(output.contains("groups"), "{output}");
            assert!(!output.contains("platform-admins"), "{output}");
            // Never the credential itself.
            assert!(!output.contains("c2ln"), "{output}");
        }
    }

    #[test]
    fn show_hides_values_until_disclose() {
        let vault = vault();
        let id = import_fixture(&vault);

        let hidden = handle_credential_command(
            &CredentialCommand::Show {
                id: id.clone(),
                disclose: false,
                json: false,
            },
            &vault,
        )
        .expect("show");
        assert!(hidden.contains("groups"), "{hidden}");
        assert!(!hidden.contains("platform-admins"), "{hidden}");

        let shown = handle_credential_command(
            &CredentialCommand::Show {
                id,
                disclose: true,
                json: false,
            },
            &vault,
        )
        .expect("show");
        assert!(shown.contains("platform-admins"), "{shown}");
    }

    #[test]
    fn json_output_is_assertable_from_a_shell_script() {
        let vault = vault();
        let id = import_fixture(&vault);

        let output = handle_credential_command(&CredentialCommand::List { json: true }, &vault)
            .expect("list");
        let parsed: Value = serde_json::from_str(&output).expect("json");
        assert_eq!(parsed[0]["id"], id);
        assert_eq!(parsed[0]["credential_type"], "urn:shadi:agent-admission:1");
        assert_eq!(parsed[0]["format"], "dc+sd-jwt");
        assert_eq!(parsed[0]["expires_at"], 2_000);
        assert_eq!(parsed[0]["claims"][0], "groups");
        assert!(parsed[0].get("raw").is_none());
    }

    #[test]
    fn show_reports_a_missing_id() {
        let vault = vault();
        let err = handle_credential_command(
            &CredentialCommand::Show {
                id: "nope".to_string(),
                disclose: false,
                json: false,
            },
            &vault,
        )
        .expect_err("missing");
        assert!(err.contains("no credential with id nope"), "{err}");
    }

    #[test]
    fn delete_reports_whether_anything_was_removed() {
        let vault = vault();
        let id = import_fixture(&vault);

        let removed =
            handle_credential_command(&CredentialCommand::Delete { id: id.clone() }, &vault)
                .expect("delete");
        assert!(removed.contains("\"deleted\":true"), "{removed}");

        let again = handle_credential_command(&CredentialCommand::Delete { id }, &vault)
            .expect("delete again");
        assert!(again.contains("\"deleted\":false"), "{again}");
    }

    #[test]
    fn list_is_empty_on_a_fresh_vault() {
        let vault = vault();
        let output = handle_credential_command(&CredentialCommand::List { json: false }, &vault)
            .expect("list");
        assert_eq!(output, "no credentials");
    }

    #[test]
    fn show_json_reveals_values_only_under_disclose() {
        let vault = vault();
        let id = import_fixture(&vault);

        let hidden = handle_credential_command(
            &CredentialCommand::Show {
                id: id.clone(),
                disclose: false,
                json: true,
            },
            &vault,
        )
        .expect("show");
        let parsed: Value = serde_json::from_str(&hidden).expect("json");
        assert_eq!(parsed["id"], id);
        assert_eq!(parsed["claims"][0], "groups");
        assert!(parsed.get("disclosed").is_none(), "{hidden}");
        assert!(parsed.get("raw").is_none(), "{hidden}");

        let shown = handle_credential_command(
            &CredentialCommand::Show {
                id,
                disclose: true,
                json: true,
            },
            &vault,
        )
        .expect("show");
        let parsed: Value = serde_json::from_str(&shown).expect("json");
        assert_eq!(
            parsed["disclosed"],
            json!([{ "name": "groups", "value": "platform-admins" }])
        );
    }

    fn disclosed_json(disclosures: &[Value]) -> Value {
        let vault = vault();
        let raw = fixture_with(disclosures);
        let id = shadi_credential::import(&vault, &raw, 1_000)
            .expect("import")
            .id;
        let shown = handle_credential_command(
            &CredentialCommand::Show {
                id,
                disclose: true,
                json: true,
            },
            &vault,
        )
        .expect("show");
        serde_json::from_str::<Value>(&shown).expect("json")["disclosed"].clone()
    }

    #[test]
    fn disclose_shows_every_array_element() {
        let disclosed = disclosed_json(&[json!(["c2FsdA", "first"]), json!(["c2FsdA", "second"])]);
        assert_eq!(
            disclosed,
            json!([
                { "name": null, "value": "first" },
                { "name": null, "value": "second" },
            ])
        );
    }

    #[test]
    fn disclose_shows_every_claim_sharing_a_name() {
        let disclosed = disclosed_json(&[
            json!(["c2FsdA", "groups", "admins"]),
            json!(["c2FsdA", "groups", "auditors"]),
        ]);
        assert_eq!(
            disclosed,
            json!([
                { "name": "groups", "value": "admins" },
                { "name": "groups", "value": "auditors" },
            ])
        );
    }

    #[test]
    fn a_credential_with_no_disclosures_lists_no_claims() {
        let vault = vault();
        shadi_credential::import(&vault, &fixture_without_disclosures(), 1_000).expect("import");

        let output = handle_credential_command(&list(), &vault).expect("list");
        assert!(output.contains("claims:    (none)"), "{output}");
    }

    /// A record this binary cannot read must not take the rest of the listing
    /// with it, and must say why rather than look like a credential with no
    /// claims.
    #[test]
    fn an_unreadable_credential_is_listed_with_the_reason() {
        let vault = vault();
        import_fixture(&vault);

        let mut other_format = record("mdoc-1");
        other_format.format = "mso_mdoc".to_string();
        vault.put(&other_format).expect("put");

        let mut corrupt = record("corrupt-1");
        corrupt.raw = "no-longer-an-sd-jwt".to_string();
        vault.put(&corrupt).expect("put");

        let output = handle_credential_command(&list(), &vault).expect("list");
        assert!(output.contains("groups"), "{output}");
        assert!(
            output.contains("(unreadable: unsupported format mso_mdoc)"),
            "{output}"
        );
        assert!(
            output.contains("(unreadable: malformed credential"),
            "{output}"
        );

        // And one of them on its own still shows what the columns know.
        let shown = handle_credential_command(
            &CredentialCommand::Show {
                id: "mdoc-1".to_string(),
                disclose: true,
                json: true,
            },
            &vault,
        )
        .expect("show");
        let parsed: Value = serde_json::from_str(&shown).expect("json");
        assert_eq!(parsed["issuer"], "https://idp.example/realms/eng");
        assert_eq!(parsed["claims"], json!([]));
        assert!(parsed.get("disclosed").is_none(), "{shown}");
        assert_eq!(parsed["unreadable"], "unsupported format mso_mdoc");
    }

    /// A credential with no `exp` is non-expiring, and says so.
    #[test]
    fn list_renders_a_missing_exp_as_never() {
        let vault = vault();
        let mut record = shadi_credential::import(&vault, &fixture(), 1_000).expect("import");
        record.expires_at = None;
        vault.put(&record).expect("put");

        let output = handle_credential_command(&CredentialCommand::List { json: false }, &vault)
            .expect("list");
        assert!(output.contains("expires:   never"), "{output}");
    }

    /// The vault is unlocked by its own key under its own name. A credential
    /// read must not require — or accept — the memory key.
    #[test]
    fn the_command_takes_the_credential_environment_not_the_memory_one() {
        use clap::CommandFactory;

        let names: Vec<String> = CredentialCli::command()
            .get_arguments()
            .filter_map(|arg| arg.get_env())
            .map(|env| env.to_string_lossy().into_owned())
            .collect();

        for expected in [
            "SHADI_CREDENTIAL_DB",
            "SHADI_CREDENTIAL_KEY",
            "SHADI_CREDENTIAL_KEY_NAME",
        ] {
            assert!(names.contains(&expected.to_string()), "{names:?}");
        }
        assert!(
            !names.iter().any(|name| name.starts_with("SHADI_MEMORY")),
            "{names:?}"
        );
    }

    #[test]
    fn agent_identity_names_a_missing_secret() {
        let err = agent_identity("absent_prefix", "nobody").err().expect("missing");
        assert!(err.contains("absent_prefix/nobody/private"), "{err}");
    }

    #[test]
    fn agent_identity_rejects_a_malformed_secret_without_echoing_it() {
        let b64 = base64::engine::general_purpose::STANDARD;
        test_store_put("bad_b64/a/private", b"not base64 !!SECRET");
        test_store_put("short/a/private", b64.encode([9u8; 16]).as_bytes());

        let err = agent_identity("bad_b64", "a").err().expect("not base64");
        assert!(err.contains("bad_b64/a/private") && err.contains("base64"), "{err}");
        assert!(!err.contains("SECRET"), "{err}");

        let err = agent_identity("short", "a").err().expect("wrong length");
        assert!(err.contains("short/a/private") && err.contains("32-byte"), "{err}");
    }

    #[test]
    fn agent_identity_loads_a_stored_key() {
        let b64 = base64::engine::general_purpose::STANDARD;
        test_store_put("good/a/private", b64.encode([7u8; 32]).as_bytes());
        assert!(agent_identity("good", "a").is_ok());
    }

    #[test]
    fn the_issue_arguments_are_reachable_from_the_environment() {
        use clap::CommandFactory;

        let command = CredentialCli::command();
        let issue = command.find_subcommand("issue").expect("issue subcommand");
        let names: Vec<String> = issue
            .get_arguments()
            .filter_map(|arg| arg.get_env())
            .map(|env| env.to_string_lossy().into_owned())
            .collect();

        for expected in [
            "SHADI_CREDENTIAL_IDP",
            "SHADI_CREDENTIAL_CLIENT_ID",
            "SHADI_CREDENTIAL_EMAIL",
            "SHADI_CREDENTIAL_CONFIGURATION_ID",
        ] {
            assert!(names.contains(&expected.to_string()), "{names:?}");
        }
        assert!(
            !names.iter().any(|name| name.starts_with("SHADI_MEMORY")),
            "{names:?}"
        );
    }

    #[test]
    fn importing_then_listing_works_through_the_command_entry_point() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("credentials.db");
        let file = dir.path().join("credential.txt");
        std::fs::write(&file, fixture()).expect("write");

        assert_eq!(
            run_credential_command(cli(
                Some(db.clone()),
                Some("test-key"),
                CredentialCommand::Import { file },
            )),
            ExitCode::SUCCESS
        );
        // A second process, opening the same database again.
        assert_eq!(
            run_credential_command(cli(Some(db), Some("test-key"), list())),
            ExitCode::SUCCESS
        );
    }

    /// The keychain holds one item per credential, so it needs neither a
    /// database nor a key — and must not demand one to open.
    #[test]
    fn the_keychain_backend_opens_without_a_database_or_key() {
        let cli = CredentialCli {
            backend: Some("keychain".to_string()),
            ..cli(None, None, list())
        };
        assert!(open_vault(&cli).is_ok());
    }

    /// With no `--backend`, the choice comes from the secret store rather than
    /// from a hard-coded target: a keychain where one exists, sqlcipher
    /// otherwise. Either answer opens here.
    #[test]
    fn an_unset_backend_takes_the_default() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cli = CredentialCli {
            backend: None,
            ..cli(
                Some(dir.path().join("credentials.db")),
                Some("test-key"),
                list(),
            )
        };
        assert!(open_vault(&cli).is_ok());
    }

    #[test]
    fn a_db_or_key_without_a_backend_selects_sqlcipher() {
        let keychain = || VaultBackend::Keychain;
        assert_eq!(
            choose_backend(None, true, keychain),
            Ok(VaultBackend::SqlCipher)
        );
        let with_db = CredentialCli {
            backend: None,
            ..cli(Some(PathBuf::from("/tmp/x.db")), None, list())
        };
        let with_key = CredentialCli {
            backend: None,
            ..cli(None, Some("k"), list())
        };
        let neither = CredentialCli {
            backend: None,
            ..cli(None, None, list())
        };
        for (cli, expected) in [
            (&with_db, VaultBackend::SqlCipher),
            (&with_key, VaultBackend::SqlCipher),
            (&neither, VaultBackend::Keychain),
        ] {
            assert_eq!(
                choose_backend(
                    cli.backend.as_deref(),
                    cli.db.is_some() || cli.key.is_some(),
                    keychain
                ),
                Ok(expected)
            );
        }
        assert_eq!(
            choose_backend(None, false, || VaultBackend::SqlCipher),
            Ok(VaultBackend::SqlCipher)
        );
    }

    #[test]
    fn an_explicit_backend_is_honoured_over_db_and_key() {
        assert_eq!(
            choose_backend(Some("keychain"), true, || VaultBackend::SqlCipher),
            Ok(VaultBackend::Keychain)
        );
        let cli = CredentialCli {
            backend: Some("keychain".to_string()),
            ..cli(Some(PathBuf::from("/nonexistent/x.db")), Some("k"), list())
        };
        assert!(open_vault(&cli).is_ok());
    }

    #[test]
    fn a_vault_that_cannot_be_opened_is_a_nonzero_exit() {
        assert_eq!(
            run_credential_command(cli(None, Some("test-key"), list())),
            ExitCode::from(1)
        );
    }

    #[test]
    fn open_vault_says_which_part_of_the_configuration_is_missing() {
        let db = || Some(PathBuf::from("/nonexistent/credentials.db"));

        for (cli, needle) in [
            (cli(None, Some("k"), list()), "database path"),
            (cli(db(), Some(""), list()), "SHADI_CREDENTIAL_KEY is empty"),
            // No key given, so the secret store is consulted under the
            // vault's own name — which the error has to name.
            (cli(db(), None, list()), "shadi/credential/absent-in-tests"),
            (
                CredentialCli {
                    backend: Some("postgres".to_string()),
                    ..cli(db(), Some("k"), list())
                },
                "unknown vault backend",
            ),
        ] {
            let Err(err) = open_vault(&cli) else {
                panic!("expected an error mentioning {needle}");
            };
            assert!(err.contains(needle), "{needle}: {err}");
        }
    }

    fn issue_command(agent: &[&str], key_prefix: &str) -> CredentialCommand {
        CredentialCommand::Issue {
            idp: "https://idp.invalid".to_string(),
            client_id: "c".to_string(),
            email: "e@example.com".to_string(),
            configuration_id: "cfg".to_string(),
            agent: agent.iter().map(|a| a.to_string()).collect(),
            key_prefix: key_prefix.to_string(),
        }
    }

    #[test]
    fn a_missing_agent_key_is_refused_before_any_login() {
        let b64 = base64::engine::general_purpose::STANDARD;
        test_store_put("multi_missing/a/private", b64.encode([7u8; 32]).as_bytes());

        let agents = ["a".to_string(), "b".to_string()];
        let err = agent_identities("multi_missing", &agents)
            .err()
            .expect("missing");
        assert!(err.contains("multi_missing/b/private"), "{err}");

        // The idp is unresolvable, so reaching the network would also fail;
        // the exit code alone cannot tell, hence the helper assertion above.
        let vault = vault();
        assert_eq!(
            run_issue(&issue_command(&["a", "b"], "multi_missing"), &vault),
            ExitCode::from(1)
        );
    }

    #[test]
    fn duplicate_agents_are_loaded_once_in_order() {
        let b64 = base64::engine::general_purpose::STANDARD;
        test_store_put("multi_dup/a/private", b64.encode([1u8; 32]).as_bytes());
        test_store_put("multi_dup/b/private", b64.encode([2u8; 32]).as_bytes());

        let agents: Vec<String> = ["b", "a", "b", "a"].iter().map(|a| a.to_string()).collect();
        let identities = agent_identities("multi_dup", &agents).expect("load");
        let names: Vec<&str> = identities.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["b", "a"]);
    }

    #[test]
    fn repeated_agent_flags_parse_into_a_list() {
        use clap::Parser;

        let cli = CredentialCli::try_parse_from([
            "credential",
            "issue",
            "--idp",
            "https://idp.example",
            "--client-id",
            "c",
            "--email",
            "e@example.com",
            "--configuration-id",
            "cfg",
            "--agent",
            "a",
            "--agent",
            "b",
        ])
        .expect("parse");
        let CredentialCommand::Issue { agent, .. } = cli.command else {
            panic!("not issue");
        };
        assert_eq!(agent, ["a", "b"]);
    }

    #[test]
    fn the_issue_report_names_each_agent() {
        let report = issue_report(&[
            ("w".to_string(), Ok(record("id-1"))),
            ("p".to_string(), Err("boom".to_string())),
        ]);
        let parsed: Value = serde_json::from_str(&report).expect("json");
        assert_eq!(parsed[0]["agent"], "w");
        assert_eq!(parsed[0]["status"], "issued");
        assert_eq!(parsed[0]["id"], "id-1");
        assert_eq!(
            parsed[1],
            json!({ "agent": "p", "status": "failed", "error": "boom" })
        );
    }
}
