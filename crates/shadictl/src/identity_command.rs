use super::*;

pub(crate) fn run_derive_agent_did_command(parsed: DeriveAgentDidArgs) -> ExitCode {
    match run_derive_agent_did(parsed) {
        Ok(()) => ExitCode::from(0),
        Err(err) => {
            eprintln!("{}", err);
            ExitCode::from(2)
        }
    }
}

pub(crate) fn run_derive_agent_identity_command(parsed: DeriveAgentIdentityArgs) -> ExitCode {
    match run_derive_agent_identity(parsed) {
        Ok(()) => ExitCode::from(0),
        Err(err) => {
            eprintln!("{}", err);
            ExitCode::from(2)
        }
    }
}

pub(crate) fn run_verify_agent_identity_command(parsed: VerifyAgentIdentityArgs) -> ExitCode {
    match run_verify_agent_identity(parsed) {
        Ok(()) => ExitCode::from(0),
        Err(err) => {
            eprintln!("{}", err);
            ExitCode::from(2)
        }
    }
}

pub(crate) fn run_get_secret_command(parsed: GetSecretArgs) -> ExitCode {
    match run_get_secret(parsed) {
        Ok(()) => ExitCode::from(0),
        Err(err) => {
            eprintln!("{}", err);
            ExitCode::from(2)
        }
    }
}

pub(crate) fn run_did_from_github_command(parsed: DidFromGitHubArgs) -> ExitCode {
    match run_did_from_github(parsed) {
        Ok(()) => ExitCode::from(0),
        Err(err) => {
            eprintln!("{}", err);
            ExitCode::from(2)
        }
    }
}

pub(crate) fn run_did_from_ssh_command(parsed: DidFromSshArgs) -> ExitCode {
    match run_did_from_ssh(parsed) {
        Ok(()) => ExitCode::from(0),
        Err(err) => {
            eprintln!("{}", err);
            ExitCode::from(2)
        }
    }
}

pub(crate) fn run_did_from_gpg_command(parsed: DidFromGpgArgs) -> ExitCode {
    match run_did_from_gpg(parsed) {
        Ok(()) => ExitCode::from(0),
        Err(err) => {
            eprintln!("{}", err);
            ExitCode::from(2)
        }
    }
}

pub(crate) fn run_did_from_gpg(args: DidFromGpgArgs) -> Result<(), String> {
    let public_key = read_openpgp_input("--key", args.key_ref.as_deref(), args.input.as_ref())?;

    let pkey = extract_ed25519_public_key(&public_key)?;

    let (did, vm_id, doc) = build_did_document(&pkey)?;
    let output = serde_json::to_string_pretty(&doc).map_err(|err| err.to_string())?;
    std::fs::write(&args.out_file, format!("{}\n", output))
        .map_err(|err| format!("failed to write {}: {}", args.out_file.display(), err))?;

    println!("DID: {}", did);
    println!("Verification Method ID: {}", vm_id);
    println!("Wrote DID Document: {}", args.out_file.display());
    Ok(())
}

pub(crate) fn run_did_from_github(args: DidFromGitHubArgs) -> Result<(), String> {
    let pkey = match args.key_type {
        GitHubKeyType::Gpg => {
            let public_key = fetch_github_gpg_key(&args.user)?;
            extract_ed25519_public_key(&public_key)?
        }
        GitHubKeyType::Ssh => {
            let listing = fetch_github_ssh_keys(&args.user)?;
            let vk = shadi_identity::ssh::first_ed25519_in_authorized_keys(&listing)
                .map_err(|err| err.to_string())?;
            vk.as_bytes().to_vec()
        }
    };

    let (did, vm_id, doc) = build_did_document(&pkey)?;
    let output = serde_json::to_string_pretty(&doc).map_err(|err| err.to_string())?;

    let did_key = format!("github/{}/did", args.user);
    let did_doc_key = format!("github/{}/diddoc", args.user);

    let store = default_secret_store();
    store
        .put(&did_key, did.as_bytes(), SecretPolicy::default())
        .map_err(|err| format!("failed to store secret {}: {}", did_key, err))?;
    store
        .put(&did_doc_key, output.as_bytes(), SecretPolicy::default())
        .map_err(|err| format!("failed to store secret {}: {}", did_doc_key, err))?;

    if let Some(out_file) = args.out_file.as_ref() {
        std::fs::write(out_file, format!("{}\n", output))
            .map_err(|err| format!("failed to write {}: {}", out_file.display(), err))?;
    }

    println!("DID: {}", did);
    println!("Verification Method ID: {}", vm_id);
    println!("Stored DID in secret key: {}", did_key);
    println!("Stored DID Document in secret key: {}", did_doc_key);
    if let Some(out_file) = args.out_file.as_ref() {
        println!("Wrote DID Document: {}", out_file.display());
    }
    Ok(())
}

pub(crate) fn run_get_secret(args: GetSecretArgs) -> Result<(), String> {
    let store = default_secret_store();
    let secret = store
        .get(&args.key)
        .map_err(|_| format!("keychain lookup failed for {}", args.key))?;
    let value = secret.expose(|bytes| bytes.to_vec());
    let value = secret_bytes_to_utf8(&value)?;
    println!("{}", value);
    Ok(())
}

pub(crate) fn run_derive_agent_did(args: DeriveAgentDidArgs) -> Result<(), String> {
    let secret_key = read_openpgp_input("--secret", args.secret.as_deref(), args.input.as_ref())?;
    let (private_key, public_key) = derive_agent_keypair(&secret_key, &args.agent_name)?;
    let (did, vm_id, doc) = build_did_document(&public_key)?;
    let output = serde_json::to_string_pretty(&doc).map_err(|err| err.to_string())?;

    store_derived_agent_identity(
        args.prefix.trim_end_matches('/'),
        &args.agent_name,
        &private_key,
        &public_key,
        &did,
        &output,
        None,
    )?;

    if let Some(out_file) = args.out_file.as_ref() {
        std::fs::write(out_file, format!("{}\n", output))
            .map_err(|err| format!("failed to write {}: {}", out_file.display(), err))?;
    }

    println!("DID: {}", did);
    println!("Verification Method ID: {}", vm_id);
    println!(
        "Stored private key: {}/{}/private",
        args.prefix.trim_end_matches('/'),
        args.agent_name
    );
    println!(
        "Stored public key: {}/{}/public",
        args.prefix.trim_end_matches('/'),
        args.agent_name
    );
    println!(
        "Stored DID: {}/{}/did",
        args.prefix.trim_end_matches('/'),
        args.agent_name
    );
    println!(
        "Stored DID Document: {}/{}/diddoc",
        args.prefix.trim_end_matches('/'),
        args.agent_name
    );
    if let Some(out_file) = args.out_file.as_ref() {
        println!("Wrote DID Document: {}", out_file.display());
    }
    Ok(())
}

pub(crate) fn run_derive_agent_identity(args: DeriveAgentIdentityArgs) -> Result<(), String> {
    let seed_material = match args.source {
        HumanIdentitySource::Gpg => {
            read_openpgp_input("--human-secret", args.human_secret.as_deref(), args.input.as_ref())?
        }
        HumanIdentitySource::Seed => {
            read_seed_input("--human-secret", args.human_secret.as_deref(), args.input.as_ref())?
        }
        HumanIdentitySource::Ssh => read_ssh_seed_input(
            "--human-secret",
            args.human_secret.as_deref(),
            args.input.as_ref(),
            args.ssh_passphrase_secret.as_deref(),
        )?,
    };

    let human_did = match args.human_did_key.as_deref() {
        Some(key) => {
            let store = default_secret_store();
            let secret = store
                .get(key)
                .map_err(|_| format!("keychain lookup failed for {}", key))?;
            Some(secret_bytes_to_utf8(&secret.expose(|bytes| bytes.to_vec()))?)
        }
        None => None,
    };

    let prefix = args.prefix.trim_end_matches('/');
    if let Some(out_dir) = args.out_dir.as_ref() {
        std::fs::create_dir_all(out_dir)
            .map_err(|err| format!("failed to create {}: {}", out_dir.display(), err))?;
    }

    for agent_name in &args.agent_names {
        let (private_key, public_key) = derive_agent_keypair(&seed_material, agent_name)?;
        let (did, vm_id, doc) = build_did_document(&public_key)?;
        let output = serde_json::to_string_pretty(&doc).map_err(|err| err.to_string())?;

        store_derived_agent_identity(
            prefix,
            agent_name,
            &private_key,
            &public_key,
            &did,
            &output,
            human_did.as_deref(),
        )?;

        if let Some(out_dir) = args.out_dir.as_ref() {
            let out_file = out_dir.join(format!("{}.did.json", agent_name));
            std::fs::write(&out_file, format!("{}\n", output))
                .map_err(|err| format!("failed to write {}: {}", out_file.display(), err))?;
            println!("Wrote DID Document: {}", out_file.display());
        }

        println!("Agent: {}", agent_name);
        println!("DID: {}", did);
        println!("Verification Method ID: {}", vm_id);
        println!("Stored private key: {}/{}/private", prefix, agent_name);
        println!("Stored public key: {}/{}/public", prefix, agent_name);
        println!("Stored DID: {}/{}/did", prefix, agent_name);
        println!("Stored DID Document: {}/{}/diddoc", prefix, agent_name);
        if args.human_did_key.is_some() {
            println!("Stored human binding: {}/{}/human_did", prefix, agent_name);
        }
    }

    Ok(())
}

pub(crate) fn run_verify_agent_identity(args: VerifyAgentIdentityArgs) -> Result<(), String> {
    let seed_material = match args.source {
        HumanIdentitySource::Gpg => {
            read_openpgp_input("--human-secret", args.human_secret.as_deref(), args.input.as_ref())?
        }
        HumanIdentitySource::Seed => {
            read_seed_input("--human-secret", args.human_secret.as_deref(), args.input.as_ref())?
        }
        HumanIdentitySource::Ssh => read_ssh_seed_input(
            "--human-secret",
            args.human_secret.as_deref(),
            args.input.as_ref(),
            args.ssh_passphrase_secret.as_deref(),
        )?,
    };

    let (_private_key, expected_public_key) = derive_agent_keypair(&seed_material, &args.agent_name)?;
    let (expected_did, _vm_id, _doc) = build_did_document(&expected_public_key)?;

    let prefix = args.prefix.trim_end_matches('/');
    let public_key_name = args
        .public_key_key
        .clone()
        .unwrap_or_else(|| format!("{}/{}/public", prefix, args.agent_name));
    let did_key_name = args
        .did_key
        .clone()
        .unwrap_or_else(|| format!("{}/{}/did", prefix, args.agent_name));

    let store = default_secret_store();
    let stored_public_b64 = store
        .get(&public_key_name)
        .map_err(|_| format!("keychain lookup failed for {}", public_key_name))?
        .expose(|bytes| bytes.to_vec());
    let stored_public_b64 = secret_bytes_to_utf8(&stored_public_b64)?;
    let stored_public_key = base64::engine::general_purpose::STANDARD
        .decode(stored_public_b64.as_bytes())
        .map_err(|err| format!("failed to decode {}: {}", public_key_name, err))?;

    if stored_public_key != expected_public_key {
        return Err("agent public key mismatch: derived key does not match stored key".to_string());
    }

    let stored_did = store
        .get(&did_key_name)
        .map_err(|_| format!("keychain lookup failed for {}", did_key_name))?
        .expose(|bytes| bytes.to_vec());
    let stored_did = secret_bytes_to_utf8(&stored_did)?;

    if stored_did != expected_did {
        return Err("agent DID mismatch: derived DID does not match stored DID".to_string());
    }

    if args.require_human_binding || args.human_did_key.is_some() {
        let binding_key = format!("{}/{}/human_did", prefix, args.agent_name);
        let bound_human_did = store
            .get(&binding_key)
            .map_err(|_| format!("missing human binding at {}", binding_key))?
            .expose(|bytes| bytes.to_vec());
        let bound_human_did = secret_bytes_to_utf8(&bound_human_did)?;

        if let Some(human_did_key) = args.human_did_key.as_deref() {
            let expected_human_did = store
                .get(human_did_key)
                .map_err(|_| format!("keychain lookup failed for {}", human_did_key))?
                .expose(|bytes| bytes.to_vec());
            let expected_human_did = secret_bytes_to_utf8(&expected_human_did)?;

            if bound_human_did != expected_human_did {
                return Err(
                    "human binding mismatch: agent bound DID does not match expected human DID"
                        .to_string(),
                );
            }
        }
    }

    println!("verified: true");
    println!("agent: {}", args.agent_name);
    println!("stored_public_key: {}", public_key_name);
    println!("stored_did: {}", did_key_name);
    println!("derived_did: {}", expected_did);

    Ok(())
}

pub(crate) fn store_derived_agent_identity(
    prefix: &str,
    agent_name: &str,
    private_key: &[u8],
    public_key: &[u8],
    did: &str,
    diddoc_json: &str,
    human_did: Option<&str>,
) -> Result<(), String> {
    let private_key_name = format!("{}/{}/private", prefix, agent_name);
    let public_key_name = format!("{}/{}/public", prefix, agent_name);
    let did_key_name = format!("{}/{}/did", prefix, agent_name);
    let diddoc_key_name = format!("{}/{}/diddoc", prefix, agent_name);

    let store = default_secret_store();
    let private_b64 = base64::engine::general_purpose::STANDARD.encode(private_key);
    let public_b64 = base64::engine::general_purpose::STANDARD.encode(public_key);

    store
        .put(&private_key_name, private_b64.as_bytes(), SecretPolicy::default())
        .map_err(|err| format!("failed to store secret {}: {}", private_key_name, err))?;
    store
        .put(&public_key_name, public_b64.as_bytes(), SecretPolicy::default())
        .map_err(|err| format!("failed to store secret {}: {}", public_key_name, err))?;
    store
        .put(&did_key_name, did.as_bytes(), SecretPolicy::default())
        .map_err(|err| format!("failed to store secret {}: {}", did_key_name, err))?;
    store
        .put(&diddoc_key_name, diddoc_json.as_bytes(), SecretPolicy::default())
        .map_err(|err| format!("failed to store secret {}: {}", diddoc_key_name, err))?;

    if let Some(human_did) = human_did {
        let binding_key = format!("{}/{}/human_did", prefix, agent_name);
        store
            .put(&binding_key, human_did.as_bytes(), SecretPolicy::default())
            .map_err(|err| format!("failed to store secret {}: {}", binding_key, err))?;
    }

    Ok(())
}

pub(crate) fn read_seed_input(
    label: &str,
    secret_key: Option<&str>,
    input: Option<&PathBuf>,
) -> Result<Vec<u8>, String> {
    if let Some(secret_key) = secret_key {
        let store = default_secret_store();
        let secret = store
            .get(secret_key)
            .map_err(|_| format!("keychain lookup failed for {}", secret_key))?;
        return Ok(secret.expose(|bytes| bytes.to_vec()));
    }

    if let Some(input) = input {
        return std::fs::read(input)
            .map_err(|err| format!("failed to read {}: {}", input.display(), err));
    }

    Err(format!("missing {} or --in", label))
}

pub(crate) fn build_did_document(pkey: &[u8]) -> Result<(String, String, serde_json::Value), String> {
    let pubkey = if pkey.len() == 33 && pkey[0] == 0x40 {
        pkey[1..].to_vec()
    } else if pkey.len() == 32 {
        pkey.to_vec()
    } else {
        return Err(format!("unexpected Ed25519 key material length: {}", pkey.len()));
    };

    let mut multicodec = Vec::with_capacity(2 + pubkey.len());
    multicodec.push(0xED);
    multicodec.push(0x01);
    multicodec.extend_from_slice(&pubkey);
    let fingerprint = format!("z{}", bs58::encode(multicodec).into_string());

    let did = format!("did:key:{}", fingerprint);
    let vm_id = format!("{}#{}", did, fingerprint);

    let doc = json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        "id": did,
        "verificationMethod": [
            {
                "id": vm_id,
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyMultibase": fingerprint
            }
        ],
        "authentication": [vm_id],
        "assertionMethod": [vm_id],
        "capabilityDelegation": [vm_id],
        "capabilityInvocation": [vm_id]
    });

    Ok((did, vm_id, doc))
}

pub(crate) fn run_put_key_command(parsed: PutKeyArgs) -> ExitCode {
    match run_put_key(parsed) {
        Ok(()) => ExitCode::from(0),
        Err(err) => {
            eprintln!("{}", err);
            ExitCode::from(2)
        }
    }
}

pub(crate) fn run_put_key(args: PutKeyArgs) -> Result<(), String> {
    let payload = std::fs::read(&args.input)
        .map_err(|err| format!("failed to read {}: {}", args.input.display(), err))?;
    let store = default_secret_store();
    store
        .put(&args.key, &payload, SecretPolicy::default())
        .map_err(|err| format!("failed to store secret {}: {}", args.key, err))?;
    println!("Stored OpenPGP key in secret: {}", args.key);
    Ok(())
}

pub(crate) fn read_openpgp_input(
    label: &str,
    secret_key: Option<&str>,
    input: Option<&PathBuf>,
) -> Result<Vec<u8>, String> {
    if let Some(secret_key) = secret_key {
        let store = default_secret_store();
        let secret = store
            .get(secret_key)
            .map_err(|_| format!("keychain lookup failed for {}", secret_key))?;
        return Ok(secret.expose(|bytes| bytes.to_vec()));
    }

    if let Some(input) = input {
        return std::fs::read(input)
            .map_err(|err| format!("failed to read {}: {}", input.display(), err));
    }

    Err(format!("missing {} or --in", label))
}

pub(crate) fn fetch_github_gpg_key(user: &str) -> Result<Vec<u8>, String> {
    let payload = github_api_get_gpg_keys(user)?;
    extract_github_public_key(&payload).and_then(decode_github_public_key)
}

pub(crate) fn extract_github_public_key(payload: &str) -> Result<String, String> {
    let value: Value = serde_json::from_str(payload).map_err(|err| err.to_string())?;
    let keys = value
        .as_array()
        .ok_or_else(|| "unexpected GitHub response format".to_string())?;
    let first = keys
        .first()
        .ok_or_else(|| "no GPG keys found for GitHub user".to_string())?;
    let public_key = first
        .get("public_key")
        .and_then(|value| value.as_str())
        .ok_or_else(|| "missing public_key in GitHub response".to_string())?;
    Ok(public_key.to_string())
}

pub(crate) fn decode_github_public_key(public_key: String) -> Result<Vec<u8>, String> {
    if public_key.contains("BEGIN PGP PUBLIC KEY BLOCK") {
        return Ok(public_key.into_bytes());
    }

    let compact = public_key.lines().map(str::trim).collect::<Vec<_>>().join("");
    if compact.is_empty() {
        return Err("GitHub public_key is empty".to_string());
    }

    base64::engine::general_purpose::STANDARD
        .decode(compact.as_bytes())
        .map_err(|err| format!("failed to decode GitHub public_key: {}", err))
}

#[cfg(test)]
static TEST_GITHUB_PAYLOAD: OnceLock<Mutex<Option<String>>> = OnceLock::new();

#[cfg(test)]
fn test_github_payload_slot() -> &'static Mutex<Option<String>> {
    TEST_GITHUB_PAYLOAD.get_or_init(|| Mutex::new(None))
}

#[cfg(test)]
pub(crate) fn set_test_github_payload(payload: Option<String>) {
    let mut guard = test_github_payload_slot().lock().expect("github payload lock");
    *guard = payload;
}

#[cfg(test)]
fn github_api_get_gpg_keys(_user: &str) -> Result<String, String> {
    let guard = test_github_payload_slot().lock().expect("github payload lock");
    guard
        .clone()
        .ok_or_else(|| "test github payload not set".to_string())
}

#[cfg(not(test))]
fn github_api_get_gpg_keys(user: &str) -> Result<String, String> {
    let token = std::env::var("GH_TOKEN")
        .or_else(|_| std::env::var("GITHUB_TOKEN"))
        .map_err(|_| "GH_TOKEN or GITHUB_TOKEN must be set for GitHub API".to_string())?;

    let url = format!("https://api.github.com/users/{}/gpg_keys", user);
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static("application/vnd.github+json"));
    headers.insert(USER_AGENT, HeaderValue::from_static("shadi-shadictl"));
    let auth = format!("Bearer {}", token);
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&auth).map_err(|_| "invalid GitHub token".to_string())?,
    );

    let client = Client::builder()
        .default_headers(headers)
        .build()
        .map_err(|err| format!("failed to build HTTP client: {}", err))?;

    let response = client
        .get(url)
        .send()
        .map_err(|err| format!("GitHub API request failed: {}", err))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().unwrap_or_default();
        return Err(format!("GitHub API error {}: {}", status, body));
    }

    response
        .text()
        .map_err(|err| format!("failed to read GitHub response: {}", err))
}

pub(crate) fn derive_agent_keypair(secret_key: &[u8], agent_name: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    // Canonical HKDF agent derivation lives in shadi_identity; delegate so there
    // is a single did:key derivation code path across the workspace.
    let id = shadi_identity::AgentIdentity::derive(secret_key, agent_name)
        .map_err(|err| err.to_string())?;
    Ok((
        id.signing_key_bytes().to_vec(),
        id.verifying_key_bytes().to_vec(),
    ))
}

pub(crate) fn extract_ed25519_public_key(openpgp_bytes: &[u8]) -> Result<Vec<u8>, String> {
    use openpgp::crypto::mpi::PublicKey as MpiPublicKey;
    use openpgp::crypto::Curve;
    use openpgp::parse::Parse;
    use openpgp::policy::StandardPolicy;

    let cert = openpgp::Cert::from_reader(openpgp_bytes)
        .map_err(|err| format!("failed to parse OpenPGP certificate: {}", err))?;
    let policy = &StandardPolicy::new();

    for key in cert
        .keys()
        .with_policy(policy, None)
        .supported()
        .alive()
        .revoked(false)
    {
        match key.key().mpis() {
            MpiPublicKey::Ed25519 { a } => return Ok(a.to_vec()),
            MpiPublicKey::EdDSA { curve, q } if *curve == Curve::Ed25519 => {
                return Ok(q.value().to_vec());
            }
            _ => {}
        }
    }

    Err("no Ed25519 public key found in OpenPGP certificate".to_string())
}

/// Resolve an SSH key passphrase without ever taking it as a CLI argument,
/// which would expose it to anyone able to run `ps`.
pub(crate) fn resolve_ssh_passphrase(secret_ref: Option<&str>) -> Result<Option<String>, String> {
    if let Some(secret_ref) = secret_ref {
        let store = default_secret_store();
        let secret = store
            .get(secret_ref)
            .map_err(|_| format!("keychain lookup failed for {}", secret_ref))?;
        let bytes = secret.expose(|b| b.to_vec());
        return Ok(Some(secret_bytes_to_utf8(&bytes)?));
    }
    match std::env::var("SHADI_SSH_PASSPHRASE") {
        Ok(value) if !value.is_empty() => Ok(Some(value)),
        _ => Ok(None),
    }
}

/// Read an OpenSSH private key from the secret store or a file and reduce it to
/// the 32-byte Ed25519 seed used as the agent-derivation root (agntcy/shadi#140).
pub(crate) fn read_ssh_seed_input(
    label: &str,
    secret_key: Option<&str>,
    input: Option<&PathBuf>,
    passphrase_secret: Option<&str>,
) -> Result<Vec<u8>, String> {
    let key_bytes = read_seed_input(label, secret_key, input)?;
    let passphrase = resolve_ssh_passphrase(passphrase_secret)?;
    let seed = shadi_identity::ssh::seed_from_openssh_private_key(&key_bytes, passphrase.as_deref())
        .map_err(|err| err.to_string())?;
    Ok(seed.to_vec())
}

/// `did-from-ssh`: build a human `did:key` from an SSH Ed25519 key.
///
/// The input may be a public `ssh-ed25519 AAAA...` line or an OpenSSH private
/// key; which one is detected from the content, so there is no flag to get wrong.
pub(crate) fn run_did_from_ssh(args: DidFromSshArgs) -> Result<(), String> {
    let raw = read_seed_input("--key", args.key_ref.as_deref(), args.input.as_ref())?;
    let text = String::from_utf8_lossy(&raw);

    let vk = if text.contains("OPENSSH PRIVATE KEY") {
        let passphrase = resolve_ssh_passphrase(args.passphrase_secret.as_deref())?;
        shadi_identity::ssh::verifying_key_from_openssh_private_key(&raw, passphrase.as_deref())
            .map_err(|err| err.to_string())?
    } else {
        shadi_identity::ssh::first_ed25519_in_authorized_keys(&text)
            .map_err(|err| err.to_string())?
    };

    let (did, vm_id, doc) = build_did_document(vk.as_bytes())?;
    let output = serde_json::to_string_pretty(&doc).map_err(|err| err.to_string())?;
    std::fs::write(&args.out_file, format!("{}\n", output))
        .map_err(|err| format!("failed to write {}: {}", args.out_file.display(), err))?;

    println!("Wrote DID Document: {}", args.out_file.display());
    println!("DID: {}", did);
    println!("Verification Method ID: {}", vm_id);
    Ok(())
}

/// `github.com/<user>.keys` — the published SSH keys.
///
/// Unauthenticated on purpose: unlike `/users/<u>/gpg_keys` this needs no token,
/// so anyone can verify a human DID against the account that claims it.
#[cfg(not(test))]
fn fetch_github_ssh_keys(user: &str) -> Result<String, String> {
    let url = format!("https://github.com/{}.keys", user);
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_static("shadi-shadictl"));
    let client = Client::builder()
        .default_headers(headers)
        .build()
        .map_err(|err| format!("failed to build HTTP client: {}", err))?;
    let response = client
        .get(&url)
        .send()
        .map_err(|err| format!("GitHub request failed: {}", err))?;
    if !response.status().is_success() {
        return Err(format!("GitHub returned {} for {}", response.status(), url));
    }
    response
        .text()
        .map_err(|err| format!("failed to read GitHub response: {}", err))
}

#[cfg(test)]
fn fetch_github_ssh_keys(_user: &str) -> Result<String, String> {
    let guard = test_github_payload_slot().lock().expect("github payload lock");
    guard
        .clone()
        .ok_or_else(|| "test github payload not set".to_string())
}
