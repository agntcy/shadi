use super::*;

use shadi_credential::{CredentialRecord, CredentialVault, Disclosure, VaultBackend};

pub(crate) fn run_credential_command(cli: CredentialCli) -> ExitCode {
    match open_vault(&cli).and_then(|vault| handle_credential_command(&cli.command, vault.as_ref()))
    {
        Ok(output) => {
            println!("{}", output);
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{}", err);
            ExitCode::from(1)
        }
    }
}

fn open_vault(cli: &CredentialCli) -> Result<Box<dyn CredentialVault>, String> {
    let backend = match cli.backend.as_deref() {
        Some(name) => name.parse::<VaultBackend>()?,
        None => shadi_credential::default_backend(),
    };

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
            let summaries = records
                .iter()
                .map(|record| summarise(record, false))
                .collect::<Result<Vec<_>, _>>()?;
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
            let summary = summarise(&record, *disclose)?;
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
    }
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
    disclosed: Option<Value>,
}

fn summarise(record: &CredentialRecord, disclose: bool) -> Result<CredentialSummary, String> {
    let parsed = shadi_credential::parse_sd_jwt(&record.raw).map_err(|err| err.to_string())?;
    Ok(CredentialSummary {
        id: record.id.clone(),
        credential_type: record.credential_type.clone(),
        format: record.format.clone(),
        issuer: record.issuer.clone(),
        agent_did: record.agent_did.clone(),
        created_at: record.created_at,
        expires_at: record.expires_at,
        claims: parsed.disclosures.iter().map(claim_name).collect(),
        disclosed: disclose.then(|| {
            Value::Object(
                parsed
                    .disclosures
                    .iter()
                    .map(|d| (claim_name(d), d.value.clone()))
                    .collect(),
            )
        }),
    })
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
            let mut text = format!(
                "{}\n  type:      {}\n  format:    {}\n  issuer:    {}\n  agent:     {}\n  expires:   {}\n  claims:    {}",
                summary.id,
                summary.credential_type,
                summary.format,
                summary.issuer,
                summary.agent_did,
                expires,
                if summary.claims.is_empty() {
                    "(none)".to_string()
                } else {
                    summary.claims.join(", ")
                },
            );
            if let Some(Value::Object(disclosed)) = summary.disclosed.as_ref() {
                text.push_str("\n  disclosed:");
                for (name, value) in disclosed {
                    text.push_str(&format!("\n    {name}: {value}"));
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
    use shadi_credential::SqlCipherVault;

    fn vault() -> SqlCipherVault {
        let file = tempfile::NamedTempFile::new().expect("tempfile");
        let path = file.path().to_path_buf();
        std::mem::forget(file);
        SqlCipherVault::open(&path, "test-key").expect("open vault")
    }

    /// Mirrors the T1 fixture shape: `dc+sd-jwt`, two disclosures, trailing
    /// tilde, no key-binding JWT.
    fn fixture() -> String {
        let b64 = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let key =
            ed25519_dalek::VerifyingKey::from(&ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]));
        let payload = json!({
            "iss": "https://idp.example/realms/eng",
            "vct": "urn:shadi:agent-admission:1",
            "exp": 2_000,
            "cnf": { "jwk": { "kty": "OKP", "crv": "Ed25519", "x": b64(key.as_bytes()) } },
        });
        let groups = b64(json!(["c2FsdA", "groups", "platform-admins"])
            .to_string()
            .as_bytes());
        format!(
            "{}.{}.c2ln~{groups}~",
            b64(br#"{"alg":"EdDSA","typ":"dc+sd-jwt"}"#),
            b64(payload.to_string().as_bytes()),
        )
    }

    /// The same credential with nothing disclosable — legal, and the operator
    /// commands have to render it.
    fn fixture_without_disclosures() -> String {
        let raw = fixture();
        let (issuer_jwt, _) = raw.split_once('~').expect("tilde");
        format!("{issuer_jwt}~")
    }

    fn import_fixture(vault: &dyn CredentialVault) -> String {
        shadi_credential::import(vault, &fixture(), 1_000)
            .expect("import")
            .id
    }

    /// A `CredentialCli` pinned to sqlcipher, so nothing in these tests can
    /// reach a developer's real keychain.
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
        assert_eq!(parsed["disclosed"]["groups"], "platform-admins");
    }

    #[test]
    fn a_credential_with_no_disclosures_lists_no_claims() {
        let vault = vault();
        shadi_credential::import(&vault, &fixture_without_disclosures(), 1_000).expect("import");

        let output = handle_credential_command(&list(), &vault).expect("list");
        assert!(output.contains("claims:    (none)"), "{output}");
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
}
