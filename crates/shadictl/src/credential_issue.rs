use std::time::Duration;

use base64::Engine;
use reqwest::Url;
use serde_json::{json, Value};
use shadi_credential::{CredentialRecord, CredentialVault, IdpOrigin};
use shadi_identity::AgentIdentity;

/// Every network call the flow makes. Bodies come back parsed whatever the
/// status: OAuth reports failure as a JSON `error` with a 4xx.
pub(crate) trait Http {
    fn get(&self, url: &Url, bearer: Option<&str>) -> Result<Value, String>;
    fn post_form(&self, url: &Url, form: &[(&str, &str)]) -> Result<Value, String>;
    fn post_json(&self, url: &Url, body: &Value, bearer: &str) -> Result<Value, String>;
    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

pub(crate) struct ReqwestHttp(reqwest::blocking::Client);

pub(crate) fn client() -> Result<ReqwestHttp, String> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        // Origin pinning only holds for the first request.
        .redirect(reqwest::redirect::Policy::none())
        .referer(false)
        .build()
        .map(ReqwestHttp)
        .map_err(|err| format!("failed to build the http client: {}", err.without_url()))
}

/// Transport and decode failures only; a body never reaches the message.
fn parse(response: reqwest::Result<reqwest::blocking::Response>) -> Result<Value, String> {
    let response = response.map_err(|err| format!("request failed: {}", err.without_url()))?;
    response
        .json()
        .map_err(|_| "the server returned a non-JSON body".to_string())
}

impl Http for ReqwestHttp {
    fn get(&self, url: &Url, bearer: Option<&str>) -> Result<Value, String> {
        let request = self.0.get(url.clone());
        parse(
            match bearer {
                Some(token) => request.bearer_auth(token),
                None => request,
            }
            .send(),
        )
    }

    fn post_form(&self, url: &Url, form: &[(&str, &str)]) -> Result<Value, String> {
        parse(self.0.post(url.clone()).form(form).send())
    }

    fn post_json(&self, url: &Url, body: &Value, bearer: &str) -> Result<Value, String> {
        parse(
            self.0
                .post(url.clone())
                .bearer_auth(bearer)
                .json(body)
                .send(),
        )
    }
}

pub(crate) struct IssueArgs<'a> {
    pub(crate) idp: &'a str,
    pub(crate) client_id: &'a str,
    pub(crate) email: &'a str,
    pub(crate) configuration_id: &'a str,
}

const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
const PRE_AUTH_GRANT: &str = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

fn str_field<'v>(value: &'v Value, name: &str) -> Result<&'v str, String> {
    value[name]
        .as_str()
        .ok_or_else(|| format!("the response is missing `{name}`"))
}

/// Appends to the IdP path, since `Url::join` would replace its last segment.
fn under(idp: &str, tail: &str) -> Result<Url, String> {
    let mut url = Url::parse(idp).map_err(|err| format!("invalid idp url: {err}"))?;
    let path = format!("{}/{tail}", url.path().trim_end_matches('/'));
    url.set_path(&path);
    Ok(url)
}

fn well_known(idp: &str, name: &str) -> Result<Url, String> {
    under(idp, &format!(".well-known/{name}"))
}

/// RFC 8414 form: the well-known segment goes between the origin and the issuer path.
fn well_known_inserted(idp: &str, name: &str) -> Result<Url, String> {
    let mut url = Url::parse(idp).map_err(|err| format!("invalid idp url: {err}"))?;
    let path = format!("/.well-known/{name}{}", url.path().trim_end_matches('/'));
    url.set_path(&path);
    Ok(url)
}

/// Tries the inserted path first, then the appended one.
fn issuer_metadata(http: &dyn Http, idp: &str) -> Result<Value, String> {
    let name = "openid-credential-issuer";
    if let Ok(meta) = http.get(&well_known_inserted(idp, name)?, None) {
        if meta["credential_issuer"].is_string() {
            return Ok(meta);
        }
    }
    http.get(&well_known(idp, name)?, None)
}

/// Exact match apart from one trailing slash.
fn same_id(a: &str, b: &str) -> bool {
    a.strip_suffix('/').unwrap_or(a) == b.strip_suffix('/').unwrap_or(b)
}

fn endpoint(origin: &IdpOrigin, doc: &Value, name: &str) -> Result<Url, String> {
    origin
        .check(str_field(doc, name)?)
        .map_err(|err| format!("{name}: {err}"))
}

struct Token {
    access_token: String,
    id_token: String,
}

fn poll_token(
    http: &dyn Http,
    token_url: &Url,
    client_id: &str,
    device: &Value,
) -> Result<Token, String> {
    let device_code = str_field(device, "device_code")?;
    let expires_in = device["expires_in"].as_u64().unwrap_or(600);
    let mut interval = device["interval"].as_u64().unwrap_or(5).clamp(1, 60);
    let mut elapsed = 0;
    loop {
        let body = http.post_form(
            token_url,
            &[
                ("grant_type", DEVICE_GRANT),
                ("device_code", device_code),
                ("client_id", client_id),
            ],
        )?;
        match body["error"].as_str() {
            Some("authorization_pending") => {}
            Some("slow_down") => interval += 5,
            Some(code) => return Err(format!("the token endpoint refused: {code}")),
            None => {
                return Ok(Token {
                    access_token: str_field(&body, "access_token")?.to_string(),
                    id_token: str_field(&body, "id_token")?.to_string(),
                })
            }
        }
        http.sleep(Duration::from_secs(interval));
        elapsed += interval;
        if elapsed >= expires_in {
            return Err("timed out waiting for the device login".to_string());
        }
    }
}

/// Mints an offer reference; this endpoint is Keycloak-specific.
fn mint_offer(
    http: &dyn Http,
    idp: &str,
    configuration_id: &str,
    bearer: &str,
) -> Result<Value, String> {
    let mut url = under(idp, "protocol/oid4vc/create-credential-offer")?;
    url.query_pairs_mut()
        .append_pair("credential_configuration_id", configuration_id)
        .append_pair("pre_authorized", "true")
        .append_pair("type", "uri");
    http.get(&url, Some(bearer))
}

/// Turns the minted reference into the offer document; Keycloak-specific shapes.
fn resolve_offer(http: &dyn Http, origin: &IdpOrigin, reference: &Value) -> Result<Value, String> {
    if reference["nonce"].is_string() {
        let issuer = str_field(reference, "issuer")?;
        let mut url = origin
            .check(issuer)
            .map_err(|err| format!("offer issuer: {err}"))?;
        url.path_segments_mut()
            .map_err(|()| "offer issuer cannot take a path".to_string())?
            .pop_if_empty()
            .push(str_field(reference, "nonce")?);
        return http.get(&url, None);
    }
    if let Some(uri) = reference.as_str().and_then(|s| Url::parse(s).ok()) {
        let param = |key: &str| {
            uri.query_pairs()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.into_owned())
        };
        if let Some(target) = param("credential_offer_uri") {
            let url = origin
                .check(&target)
                .map_err(|err| format!("credential_offer_uri: {err}"))?;
            return http.get(&url, None);
        }
        if let Some(inline) = param("credential_offer") {
            return serde_json::from_str(&inline)
                .map_err(|_| "the credential offer is not valid JSON".to_string());
        }
    }
    Ok(reference.clone())
}

fn pre_authorized_code(offer: &Value) -> Result<String, String> {
    let grant = &offer["grants"][PRE_AUTH_GRANT];
    if grant.is_null() {
        return Err("the offer carries no pre-authorized grant".to_string());
    }
    if grant.get("tx_code").is_some() {
        return Err(
            "the offer requires a transaction code, which this command cannot collect".to_string(),
        );
    }
    Ok(str_field(grant, "pre-authorized_code")?.to_string())
}

/// Second token request; returns the access token and its `c_nonce`.
fn redeem_code(
    http: &dyn Http,
    token_url: &Url,
    client_id: &str,
    code: &str,
) -> Result<(String, Option<String>), String> {
    let body = http.post_form(
        token_url,
        &[
            ("grant_type", PRE_AUTH_GRANT),
            ("pre-authorized_code", code),
            ("client_id", client_id),
        ],
    )?;
    if let Some(code) = body["error"].as_str() {
        return Err(format!("the token endpoint refused: {code}"));
    }
    Ok((
        str_field(&body, "access_token")?.to_string(),
        body["c_nonce"].as_str().map(str::to_string),
    ))
}

/// First `credential_identifiers` entry in the access token's `authorization_details`.
fn credential_identifier(access_token: &str) -> Option<String> {
    let part = access_token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(part)
        .ok()?;
    let payload: Value = serde_json::from_slice(&bytes).ok()?;
    payload["authorization_details"]
        .as_array()?
        .iter()
        .filter_map(|detail| detail["credential_identifiers"].as_array())
        .flatten()
        .find_map(|id| id.as_str().map(str::to_string))
}

/// Accepts a bare string, a list of strings, or a list of `{credential}` objects.
fn extract_credential(body: &Value) -> Result<String, String> {
    let found = body["credential"].as_str().or_else(|| {
        let first = body["credentials"].as_array()?.first()?;
        first.as_str().or_else(|| first["credential"].as_str())
    });
    found
        .map(str::to_string)
        .ok_or_else(|| "the credential response held no credential".to_string())
}

/// What the shared login leg yields; each agent's issuance runs from it.
struct Session {
    origin: IdpOrigin,
    credential_issuer: String,
    credential_endpoint: Url,
    nonce_endpoint: Option<Url>,
    token_url: Url,
    access_token: String,
    now: i64,
}

fn login(
    http: &dyn Http,
    vault: &dyn CredentialVault,
    args: &IssueArgs<'_>,
    agents: &[&str],
    now: i64,
) -> Result<Session, String> {
    let origin = IdpOrigin::new(args.idp).map_err(|err| err.to_string())?;

    let meta = issuer_metadata(http, args.idp)?;
    let credential_issuer = str_field(&meta, "credential_issuer")?;
    let credential_endpoint = endpoint(&origin, &meta, "credential_endpoint")?;
    let nonce_endpoint = match meta["nonce_endpoint"].as_str() {
        Some(url) => Some(
            origin
                .check(url)
                .map_err(|err| format!("nonce_endpoint: {err}"))?,
        ),
        None => None,
    };
    if !same_id(credential_issuer, args.idp) {
        return Err("credential_issuer does not match the IdP".to_string());
    }
    if let Some(servers) = meta["authorization_servers"].as_array() {
        let listed = servers
            .iter()
            .any(|s| s.as_str().is_some_and(|s| same_id(s, args.idp)));
        if !listed {
            return Err("authorization_servers does not list the IdP".to_string());
        }
    }

    let config = http.get(&well_known(args.idp, "openid-configuration")?, None)?;
    let oidc_issuer = str_field(&config, "issuer")?;
    if !same_id(oidc_issuer, args.idp) {
        return Err("issuer does not match the IdP".to_string());
    }
    let token_url = endpoint(&origin, &config, "token_endpoint")?;
    let device_url = endpoint(&origin, &config, "device_authorization_endpoint")?;

    let device = http.post_form(
        &device_url,
        &[("client_id", args.client_id), ("scope", "openid email")],
    )?;
    let user_code = str_field(&device, "user_code")?;
    let verification_uri = origin
        .check(str_field(&device, "verification_uri")?)
        .map_err(|err| format!("verification_uri: {err}"))?;
    if !agents.is_empty() {
        eprintln!("Issuing for {}.", agents.join(", "));
    }
    match device["verification_uri_complete"].as_str() {
        Some(complete) => {
            let complete = origin
                .check(complete)
                .map_err(|err| format!("verification_uri_complete: {err}"))?;
            eprintln!("Open {complete} to approve this login.");
        }
        None => eprintln!("Open {verification_uri} and enter the code {user_code}."),
    }

    let token = poll_token(http, &token_url, args.client_id, &device)?;

    let claims = shadi_credential::check_id_token(
        &token.id_token,
        oidc_issuer,
        args.client_id,
        args.email,
        now,
    )
    .map_err(|err| err.to_string())?;

    let pinned = vault
        .pin_subject(oidc_issuer, &claims.email, &claims.subject)
        .map_err(|err| err.to_string())?;
    if pinned != claims.subject {
        return Err("this email is already pinned to a different account at this IdP".to_string());
    }

    Ok(Session {
        origin,
        credential_issuer: credential_issuer.to_string(),
        credential_endpoint,
        nonce_endpoint,
        token_url,
        access_token: token.access_token,
        now,
    })
}

fn issue_for(
    http: &dyn Http,
    vault: &dyn CredentialVault,
    identity: &AgentIdentity,
    session: &Session,
    args: &IssueArgs<'_>,
) -> Result<CredentialRecord, String> {
    let offer_ref = mint_offer(http, args.idp, args.configuration_id, &session.access_token)?;
    let offer = resolve_offer(http, &session.origin, &offer_ref)?;
    let code = pre_authorized_code(&offer)?;
    let (access_token, c_nonce) = redeem_code(http, &session.token_url, args.client_id, &code)?;

    let nonce = match (c_nonce, session.nonce_endpoint.as_ref()) {
        (Some(nonce), _) => nonce,
        (None, Some(url)) => {
            str_field(&http.post_json(url, &json!({}), &access_token)?, "c_nonce")?.to_string()
        }
        (None, None) => return Err("the IdP offered no c_nonce".to_string()),
    };

    let proof = shadi_credential::proof_jwt(
        identity,
        args.client_id,
        &session.credential_issuer,
        &nonce,
        session.now,
    );
    let proofs = json!({ "jwt": [proof] });
    let body = match credential_identifier(&access_token) {
        Some(id) => json!({ "credential_identifier": id, "proofs": proofs }),
        None => json!({ "credential_configuration_id": args.configuration_id, "proofs": proofs }),
    };
    let response = http.post_json(&session.credential_endpoint, &body, &access_token)?;
    let raw = extract_credential(&response)?;

    let parsed = shadi_credential::parse_sd_jwt(&raw).map_err(|err| err.to_string())?;
    if parsed.agent_did != identity.did() {
        return Err("the issued credential is bound to another key".to_string());
    }
    if !same_id(&parsed.issuer, &session.credential_issuer) {
        return Err("the issued credential names another issuer".to_string());
    }
    shadi_credential::import(vault, &raw, session.now).map_err(|err| err.to_string())
}

#[cfg(test)]
pub(crate) fn issue(
    http: &dyn Http,
    vault: &dyn CredentialVault,
    identity: &AgentIdentity,
    args: &IssueArgs<'_>,
    now: i64,
) -> Result<CredentialRecord, String> {
    let session = login(http, vault, args, &[], now)?;
    issue_for(http, vault, identity, &session, args)
}

/// `Err` means the shared login failed and no agent was tried.
pub(crate) fn issue_all(
    http: &dyn Http,
    vault: &dyn CredentialVault,
    identities: &[(String, AgentIdentity)],
    args: &IssueArgs<'_>,
    now: i64,
) -> Result<Vec<(String, Result<CredentialRecord, String>)>, String> {
    let names: Vec<&str> = identities.iter().map(|(name, _)| name.as_str()).collect();
    let session = login(http, vault, args, &names, now)?;
    Ok(identities
        .iter()
        .map(|(name, identity)| {
            (
                name.clone(),
                issue_for(http, vault, identity, &session, args),
            )
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use shadi_credential::SqlCipherVault;
    use std::cell::RefCell;
    use std::collections::{HashMap, VecDeque};

    const IDP: &str = "https://idp.example/realms/eng";
    const NOW: i64 = 1_000;
    const META: &str = "/.well-known/openid-credential-issuer/realms/eng";
    const META_APPENDED: &str = "/realms/eng/.well-known/openid-credential-issuer";
    const MINT: &str = "/realms/eng/protocol/oid4vc/create-credential-offer";
    const OFFER: &str = "https://idp.example/realms/eng/offer/abc";
    const TOKEN: &str = "/realms/eng/token";

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    fn vault() -> SqlCipherVault {
        let file = tempfile::NamedTempFile::new().expect("tempfile");
        let path = file.path().to_path_buf();
        std::mem::forget(file);
        SqlCipherVault::open(&path, "test-key").expect("open vault")
    }

    fn sd_jwt(holder: &AgentIdentity, issuer: &str) -> String {
        let payload = json!({
            "iss": issuer,
            "vct": "urn:shadi:agent-admission:1",
            "exp": 2_000,
            "cnf": { "jwk": { "kty": "OKP", "crv": "Ed25519", "x": b64(&holder.verifying_key_bytes()) } },
        });
        format!(
            "{}.{}.c2ln~{}~",
            b64(br#"{"alg":"EdDSA","typ":"dc+sd-jwt"}"#),
            b64(payload.to_string().as_bytes()),
            b64(json!(["c2FsdA", "groups", "admins"]).to_string().as_bytes()),
        )
    }

    fn id_token() -> String {
        let payload = json!({
            "iss": IDP, "aud": "agent-cli", "sub": "sub-1", "exp": 5_000,
            "email": "dev@example.com", "email_verified": true,
        });
        format!(
            "{}.{}.c2ln",
            b64(b"{}"),
            b64(payload.to_string().as_bytes())
        )
    }

    fn access_jwt(details: Value) -> String {
        let payload = json!({ "authorization_details": details });
        format!(
            "{}.{}.c2ln",
            b64(b"{}"),
            b64(payload.to_string().as_bytes())
        )
    }

    fn default_details() -> Value {
        json!([{ "credential_identifiers": ["agent-admission_0000"] }])
    }

    fn second_token() -> Value {
        json!({ "access_token": access_jwt(default_details()), "c_nonce": "n-second" })
    }

    fn offer_doc() -> Value {
        json!({ "grants": { PRE_AUTH_GRANT: { "pre-authorized_code": "pac-1" } } })
    }

    struct Fake {
        script: RefCell<HashMap<String, VecDeque<Value>>>,
        requests: RefCell<Vec<(String, Value)>>,
        sleeps: RefCell<Vec<Duration>>,
    }

    impl Fake {
        fn set(&self, path: &str, responses: Vec<Value>) {
            self.script
                .borrow_mut()
                .insert(path.to_string(), responses.into());
        }

        fn reply(&self, url: &Url, body: Value) -> Result<Value, String> {
            self.requests
                .borrow_mut()
                .push((url.path().to_string(), body));
            let mut script = self.script.borrow_mut();
            let queue = script
                .get_mut(url.path())
                .ok_or_else(|| format!("unscripted {}", url.path()))?;
            // The last response repeats.
            Ok(if queue.len() > 1 {
                queue.pop_front().unwrap()
            } else {
                queue[0].clone()
            })
        }

        fn requests_to(&self, path: &str) -> Vec<Value> {
            let all = self.requests.borrow();
            all.iter()
                .filter(|(p, _)| p == path)
                .map(|(_, b)| b.clone())
                .collect()
        }
    }

    impl Http for Fake {
        fn get(&self, url: &Url, bearer: Option<&str>) -> Result<Value, String> {
            self.reply(url, json!(bearer))
        }
        fn post_form(&self, url: &Url, form: &[(&str, &str)]) -> Result<Value, String> {
            self.reply(url, json!(form))
        }
        fn post_json(&self, url: &Url, body: &Value, _bearer: &str) -> Result<Value, String> {
            self.reply(url, body.clone())
        }
        fn sleep(&self, duration: Duration) {
            self.sleeps.borrow_mut().push(duration);
        }
    }

    fn fake() -> Fake {
        let fake = Fake {
            script: RefCell::default(),
            requests: RefCell::default(),
            sleeps: RefCell::default(),
        };
        fake.set(
            META,
            vec![json!({
                "credential_issuer": IDP,
                "credential_endpoint": "https://idp.example/realms/eng/credential",
                "authorization_servers": [IDP],
            })],
        );
        fake.set(
            "/realms/eng/.well-known/openid-configuration",
            vec![json!({
                "issuer": IDP,
                "token_endpoint": "https://idp.example/realms/eng/token",
                "device_authorization_endpoint": "https://idp.example/realms/eng/device",
            })],
        );
        fake.set(
            "/realms/eng/device",
            vec![json!({
                "device_code": "dc", "user_code": "ABCD",
                "verification_uri": "https://idp.example/realms/eng/activate",
            })],
        );
        fake.set(TOKEN, vec![success(), second_token()]);
        fake.set(
            MINT,
            vec![json!({ "issuer": "https://idp.example/realms/eng/offer", "nonce": "abc" })],
        );
        fake.set("/realms/eng/offer/abc", vec![offer_doc()]);
        fake
    }

    fn serve(fake: &Fake, credential: String) {
        fake.set(
            "/realms/eng/credential",
            vec![json!({ "credential": credential })],
        );
    }

    fn run(fake: &Fake, vault: &SqlCipherVault) -> Result<CredentialRecord, String> {
        let identity = AgentIdentity::generate().expect("identity");
        serve(fake, sd_jwt(&identity, IDP));
        run_as(fake, vault, &identity)
    }

    fn run_as(
        fake: &Fake,
        vault: &SqlCipherVault,
        identity: &AgentIdentity,
    ) -> Result<CredentialRecord, String> {
        issue(
            fake,
            vault,
            identity,
            &IssueArgs {
                idp: IDP,
                client_id: "agent-cli",
                email: "dev@example.com",
                configuration_id: "agent-admission",
            },
            NOW,
        )
    }

    fn args() -> IssueArgs<'static> {
        IssueArgs {
            idp: IDP,
            client_id: "agent-cli",
            email: "dev@example.com",
            configuration_id: "agent-admission",
        }
    }

    fn named(name: &str) -> (String, AgentIdentity) {
        (
            name.to_string(),
            AgentIdentity::generate().expect("identity"),
        )
    }

    #[test]
    fn two_agents_issue_from_one_device_login() {
        let fake = fake();
        let vault = vault();
        let ids = [named("worker"), named("planner")];
        fake.set(
            "/realms/eng/credential",
            ids.iter()
                .map(|(_, id)| json!({ "credential": sd_jwt(id, IDP) }))
                .collect(),
        );
        let results = issue_all(&fake, &vault, &ids, &args(), NOW).expect("login");

        assert_eq!(fake.requests_to("/realms/eng/device").len(), 1);
        assert_eq!(results.len(), 2);
        let a = results[0].1.as_ref().expect("first");
        let b = results[1].1.as_ref().expect("second");
        assert_ne!(a.id, b.id);
        assert_eq!(vault.list().expect("list").len(), 2);
    }

    #[test]
    fn a_failing_agent_does_not_lose_the_one_before_it() {
        let fake = fake();
        let vault = vault();
        let ids = [named("worker"), named("planner")];
        fake.set(
            "/realms/eng/credential",
            vec![
                json!({ "credential": sd_jwt(&ids[0].1, IDP) }),
                json!({ "error": "invalid_proof" }),
            ],
        );
        let results = issue_all(&fake, &vault, &ids, &args(), NOW).expect("login");

        assert!(results[0].1.is_ok());
        let err = results[1].1.as_ref().expect_err("second fails");
        assert!(err.contains("no credential"), "{err}");
        assert_eq!(vault.list().expect("list").len(), 1);
    }

    fn pending() -> Value {
        json!({ "error": "authorization_pending" })
    }

    fn success() -> Value {
        json!({ "access_token": "at", "id_token": id_token(), "c_nonce": "n-first" })
    }

    fn proof_part(sent: &Value, i: usize) -> Value {
        let jwt = sent["proofs"]["jwt"][0].as_str().expect("jwt");
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(jwt.split('.').nth(i).expect("part"))
            .expect("b64");
        serde_json::from_slice(&bytes).expect("json")
    }

    #[test]
    fn happy_path_stores_one_credential_with_a_bound_proof() {
        let fake = fake();
        let vault = vault();
        let identity = AgentIdentity::generate().expect("identity");
        serve(&fake, sd_jwt(&identity, IDP));
        let record = run_as(&fake, &vault, &identity).expect("issue");

        assert_eq!(vault.list().expect("list").len(), 1);
        assert_eq!(record.credential_type, "urn:shadi:agent-admission:1");

        let sent = &fake.requests_to("/realms/eng/credential")[0];
        assert_eq!(sent["credential_identifier"], "agent-admission_0000");
        assert!(sent.get("credential_configuration_id").is_none());
        assert_eq!(proof_part(sent, 1)["nonce"], "n-second");
        let part = |i| proof_part(sent, i);
        assert_eq!(part(1)["aud"], IDP);
        assert_eq!(
            part(0)["jwk"]["x"],
            b64(&identity.verifying_key_bytes()).as_str()
        );
    }

    #[test]
    fn pending_then_success_polls() {
        let fake = fake();
        fake.set(TOKEN, vec![pending(), pending(), success(), second_token()]);
        run(&fake, &vault()).expect("issue");
        assert_eq!(fake.requests_to(TOKEN).len(), 4);
        assert_eq!(fake.sleeps.borrow().len(), 2);
    }

    #[test]
    fn slow_down_lengthens_the_interval() {
        let fake = fake();
        fake.set(
            "/realms/eng/token",
            vec![
                json!({ "error": "slow_down" }),
                pending(),
                success(),
                second_token(),
            ],
        );
        run(&fake, &vault()).expect("issue");
        let secs: Vec<u64> = fake.sleeps.borrow().iter().map(|d| d.as_secs()).collect();
        assert_eq!(secs, [10, 10]);
    }

    #[test]
    fn another_token_error_fails_without_retrying() {
        let fake = fake();
        fake.set(
            TOKEN,
            vec![json!({ "error": "access_denied", "error_description": "secret-detail" })],
        );
        let err = run(&fake, &vault()).expect_err("denied");
        assert!(err.contains("access_denied"), "{err}");
        assert!(!err.contains("secret-detail"), "{err}");
        assert_eq!(fake.requests_to(TOKEN).len(), 1);
    }

    #[test]
    fn a_credential_endpoint_on_another_origin_is_refused() {
        let fake = fake();
        fake.set(
            META,
            vec![json!({
                "credential_issuer": IDP,
                "credential_endpoint": "https://evil.example/credential",
            })],
        );
        let vault = vault();
        assert!(run(&fake, &vault).is_err());
        assert!(fake.requests_to("/credential").is_empty());
        assert!(vault.list().expect("list").is_empty());
    }

    #[test]
    fn a_verification_uri_on_another_origin_is_refused() {
        let fake = fake();
        fake.set(
            "/realms/eng/device",
            vec![json!({
                "device_code": "dc", "user_code": "ABCD",
                "verification_uri": "https://evil.example/activate",
            })],
        );
        assert!(run(&fake, &vault()).is_err());
        assert!(fake.requests_to(TOKEN).is_empty());
    }

    #[test]
    fn an_email_pinned_to_another_subject_is_refused() {
        let fake = fake();
        let vault = vault();
        vault
            .pin_subject(IDP, "dev@example.com", "someone-else")
            .expect("pin");
        let err = run(&fake, &vault).expect_err("refused");
        assert!(
            !err.contains("someone-else") && !err.contains("sub-1"),
            "{err}"
        );
        assert!(fake.requests_to("/realms/eng/credential").is_empty());
        assert!(vault.list().expect("list").is_empty());
    }

    #[test]
    fn expiry_stops_the_poll_loop() {
        let fake = fake();
        fake.set(
            "/realms/eng/device",
            vec![json!({
                "device_code": "dc", "user_code": "ABCD", "expires_in": 12,
                "verification_uri": "https://idp.example/realms/eng/activate",
            })],
        );
        fake.set(TOKEN, vec![pending()]);
        let err = run(&fake, &vault()).expect_err("timeout");
        assert!(err.contains("timed out"), "{err}");
        assert_eq!(fake.requests_to(TOKEN).len(), 3);
    }

    #[test]
    fn a_zero_interval_still_times_out() {
        let fake = fake();
        fake.set(
            "/realms/eng/device",
            vec![json!({
                "device_code": "dc", "user_code": "ABCD", "expires_in": 3, "interval": 0,
                "verification_uri": "https://idp.example/realms/eng/activate",
            })],
        );
        fake.set(TOKEN, vec![pending()]);
        let err = run(&fake, &vault()).expect_err("timeout");
        assert!(err.contains("timed out"), "{err}");
        assert_eq!(fake.requests_to(TOKEN).len(), 3);
    }

    #[test]
    fn a_credential_bound_to_another_key_is_refused_and_stores_nothing() {
        let fake = fake();
        let other = AgentIdentity::generate().expect("identity");
        serve(&fake, sd_jwt(&other, IDP));
        let vault = vault();
        let identity = AgentIdentity::generate().expect("identity");
        let err = run_as(&fake, &vault, &identity).expect_err("refused");
        assert!(err.contains("another key"), "{err}");
        assert!(
            !err.contains(&other.did()) && !err.contains(&identity.did()),
            "{err}"
        );
        assert!(!err.contains(&b64(&other.verifying_key_bytes())), "{err}");
        assert!(vault.list().expect("list").is_empty());
    }

    #[test]
    fn a_credential_naming_another_issuer_is_refused_and_stores_nothing() {
        let fake = fake();
        let identity = AgentIdentity::generate().expect("identity");
        serve(&fake, sd_jwt(&identity, "https://idp.example/realms/rogue"));
        let vault = vault();
        let err = run_as(&fake, &vault, &identity).expect_err("refused");
        assert!(err.contains("another issuer"), "{err}");
        assert!(!err.contains("rogue"), "{err}");
        assert!(vault.list().expect("list").is_empty());
    }

    #[test]
    fn nonce_comes_from_the_nonce_endpoint_when_the_token_has_none() {
        let fake = fake();
        fake.set(
            TOKEN,
            vec![
                json!({ "access_token": "at", "id_token": id_token() }),
                json!({ "access_token": access_jwt(default_details()) }),
            ],
        );
        let err = run(&fake, &vault()).expect_err("no nonce");
        assert!(err.contains("c_nonce"), "{err}");

        fake.set(
            TOKEN,
            vec![
                json!({ "access_token": "at", "id_token": id_token() }),
                json!({ "access_token": access_jwt(default_details()) }),
            ],
        );
        fake.set(
            META,
            vec![json!({
                "credential_issuer": IDP,
                "credential_endpoint": "https://idp.example/realms/eng/credential",
                "nonce_endpoint": "https://idp.example/realms/eng/nonce",
            })],
        );
        fake.set(
            "/realms/eng/nonce",
            vec![json!({ "c_nonce": "n-from-endpoint" })],
        );
        run(&fake, &vault()).expect("issue");
        let sent = &fake.requests_to("/realms/eng/credential")[0];
        assert_eq!(proof_part(sent, 1)["nonce"], "n-from-endpoint");
        assert_eq!(fake.requests_to("/realms/eng/nonce"), [json!({})]);
    }

    fn with_issuer_doc(fake: &Fake, extra: Value) {
        let mut doc = json!({
            "credential_issuer": IDP,
            "credential_endpoint": "https://idp.example/realms/eng/credential",
        });
        doc.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        fake.set(META, vec![doc]);
    }

    #[test]
    fn a_mismatched_credential_issuer_is_refused() {
        let fake = fake();
        with_issuer_doc(
            &fake,
            json!({ "credential_issuer": "https://idp.example/realms/rogue" }),
        );
        let err = run(&fake, &vault()).expect_err("refused");
        assert!(err.contains("credential_issuer"), "{err}");
        assert!(!err.contains("rogue"), "{err}");
        assert!(fake.requests_to("/realms/eng/device").is_empty());
    }

    #[test]
    fn a_mismatched_issuer_is_refused_and_pins_nothing() {
        let fake = fake();
        fake.set(
            "/realms/eng/.well-known/openid-configuration",
            vec![json!({
                "issuer": "https://idp.example/realms/prod",
                "token_endpoint": "https://idp.example/realms/eng/token",
                "device_authorization_endpoint": "https://idp.example/realms/eng/device",
            })],
        );
        let vault = vault();
        let err = run(&fake, &vault).expect_err("refused");
        assert!(err.contains("issuer"), "{err}");
        assert!(!err.contains("prod"), "{err}");
        for issuer in [IDP, "https://idp.example/realms/prod"] {
            assert_eq!(
                vault.pinned_subject(issuer, "dev@example.com").unwrap(),
                None
            );
        }
        assert!(vault.list().expect("list").is_empty());
    }

    #[test]
    fn authorization_servers_must_list_the_idp() {
        let fake = fake();
        with_issuer_doc(
            &fake,
            json!({ "authorization_servers": ["https://idp.example/realms/other"] }),
        );
        let err = run(&fake, &vault()).expect_err("refused");
        assert!(err.contains("authorization_servers"), "{err}");
    }

    #[test]
    fn a_trailing_slash_on_the_idp_is_tolerated() {
        let fake = fake();
        let identity = AgentIdentity::generate().expect("identity");
        serve(&fake, sd_jwt(&identity, IDP));
        issue(
            &fake,
            &vault(),
            &identity,
            &IssueArgs {
                idp: "https://idp.example/realms/eng/",
                client_id: "agent-cli",
                email: "dev@example.com",
                configuration_id: "agent-admission",
            },
            NOW,
        )
        .expect("issue");
    }

    fn redeemed_code(fake: &Fake) -> bool {
        let forms = fake.requests_to(TOKEN);
        forms.last().is_some_and(|f| {
            f.as_array()
                .is_some_and(|a| a.contains(&json!(["pre-authorized_code", "pac-1"])))
        })
    }

    #[test]
    fn the_offer_reference_resolves_through_each_shape() {
        let mut inline = Url::parse("openid-credential-offer://").unwrap();
        inline
            .query_pairs_mut()
            .append_pair("credential_offer", &offer_doc().to_string());
        let mut by_ref = Url::parse("openid-credential-offer://").unwrap();
        by_ref
            .query_pairs_mut()
            .append_pair("credential_offer_uri", OFFER);
        let shapes = [
            json!({ "issuer": "https://idp.example/realms/eng/offer", "nonce": "abc" }),
            json!(by_ref.to_string()),
            json!(inline.to_string()),
            offer_doc(),
        ];
        for shape in shapes {
            let fake = fake();
            fake.set(MINT, vec![shape.clone()]);
            run(&fake, &vault()).unwrap_or_else(|err| panic!("{shape}: {err}"));
            assert!(redeemed_code(&fake), "{shape}");
        }
    }

    #[test]
    fn the_offer_is_minted_with_the_login_token_and_fetched_without_one() {
        let fake = fake();
        run(&fake, &vault()).expect("issue");
        assert_eq!(fake.requests_to(MINT), [json!("at")]);
        assert_eq!(fake.requests_to("/realms/eng/offer/abc"), [Value::Null]);
        assert_eq!(fake.requests_to(META), [Value::Null]);
    }

    #[test]
    fn the_offer_nonce_is_percent_encoded() {
        let fake = fake();
        fake.set(
            MINT,
            vec![json!({ "issuer": "https://idp.example/realms/eng/offer", "nonce": "a/b" })],
        );
        fake.set("/realms/eng/offer/a%2Fb", vec![offer_doc()]);
        run(&fake, &vault()).expect("issue");
    }

    #[test]
    fn an_offer_issuer_on_another_origin_is_refused() {
        let fake = fake();
        fake.set(
            MINT,
            vec![json!({ "issuer": "https://evil.example/offer", "nonce": "abc" })],
        );
        assert!(run(&fake, &vault()).is_err());
        assert!(fake.requests_to("/offer/abc").is_empty());
        assert_eq!(fake.requests_to(TOKEN).len(), 1);
    }

    #[test]
    fn a_credential_offer_uri_on_another_origin_is_refused() {
        let fake = fake();
        let mut uri = Url::parse("openid-credential-offer://").unwrap();
        uri.query_pairs_mut()
            .append_pair("credential_offer_uri", "https://evil.example/offer/abc");
        fake.set(MINT, vec![json!(uri.to_string())]);
        assert!(run(&fake, &vault()).is_err());
        assert!(fake.requests_to("/offer/abc").is_empty());
        assert_eq!(fake.requests_to(TOKEN).len(), 1);
    }

    #[test]
    fn an_offer_with_a_tx_code_is_refused_and_stores_nothing() {
        let fake = fake();
        fake.set(
            "/realms/eng/offer/abc",
            vec![json!({ "grants": { PRE_AUTH_GRANT: {
                "pre-authorized_code": "pac-1", "tx_code": { "length": 4 },
            } } })],
        );
        let vault = vault();
        let err = run(&fake, &vault).expect_err("refused");
        assert!(err.contains("transaction code"), "{err}");
        assert_eq!(fake.requests_to(TOKEN).len(), 1);
        assert!(fake.requests_to("/realms/eng/credential").is_empty());
        assert!(vault.list().expect("list").is_empty());
    }

    #[test]
    fn no_credential_identifiers_falls_back_to_the_configuration_id() {
        for details in [json!([]), json!([{ "type": "openid_credential" }])] {
            let fake = fake();
            fake.set(
                TOKEN,
                vec![
                    success(),
                    json!({ "access_token": access_jwt(details), "c_nonce": "n-second" }),
                ],
            );
            run(&fake, &vault()).expect("issue");
            let sent = &fake.requests_to("/realms/eng/credential")[0];
            assert_eq!(sent["credential_configuration_id"], "agent-admission");
            assert!(sent.get("credential_identifier").is_none());
        }
    }

    #[test]
    fn the_first_identifier_across_all_entries_is_used() {
        let jwt = access_jwt(json!([
            { "credential_identifiers": [] },
            { "credential_identifiers": ["second_0000", "second_0001"] },
        ]));
        assert_eq!(credential_identifier(&jwt).as_deref(), Some("second_0000"));
        assert_eq!(credential_identifier("opaque"), None);
    }

    #[test]
    fn issuer_metadata_falls_back_to_the_appended_path() {
        let doc = json!({
            "credential_issuer": IDP,
            "credential_endpoint": "https://idp.example/realms/eng/credential",
        });
        for inserted in [None, Some(json!({}))] {
            let fake = fake();
            fake.script.borrow_mut().remove(META);
            if let Some(body) = inserted {
                fake.set(META, vec![body]);
            }
            fake.set(META_APPENDED, vec![doc.clone()]);
            run(&fake, &vault()).expect("issue");
            assert_eq!(fake.requests_to(META_APPENDED).len(), 1);
        }
    }

    #[test]
    fn all_three_credential_shapes_parse() {
        let raw = sd_jwt(&AgentIdentity::generate().expect("identity"), IDP);
        for body in [
            json!({ "credential": raw }),
            json!({ "credentials": [raw] }),
            json!({ "credentials": [{ "credential": raw }] }),
        ] {
            assert_eq!(extract_credential(&body).expect("parse"), raw);
        }
        assert!(extract_credential(&json!({ "credentials": [] })).is_err());
    }
}
