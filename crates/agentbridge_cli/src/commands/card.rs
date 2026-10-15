//! What `register` advertises in its A2A agent card beyond the transport: the
//! agent's version and the OASF `discovery` extension (OASF schema version,
//! skills and domains) that runtime discovery (dir-runtime) indexes.
//!
//! Each fact is stated once, and nothing is advertised that the agent wasn't
//! given: its skills and domains come from `--skill` / `--domain` and from the
//! `--record` it runs. An agent with no skill has no `discovery` extension (the
//! OASF object requires one) and no A2A card skills.
//!
//! The configuration is set once per process, before any listener starts, and
//! read by every place that builds the card, so the served card, the
//! well-known card and the extended card always agree.

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Duration;

use a2a::AgentExtension;
use serde_json::{json, Value};

/// OASF schema server whose vocabulary skills and domains are checked against
/// and whose URIs name the card extension.
pub const DEFAULT_OASF_SCHEMA_URL: &str = "https://schema.oasf.outshift.com";

/// OASF version the `discovery` object was released in.
pub const DEFAULT_OASF_SCHEMA_VERSION: &str = "1.1.0";

const VALIDATION_TIMEOUT: Duration = Duration::from_secs(15);

/// Card settings from the command line.
#[derive(Clone, Debug, Default)]
pub struct CardOptions {
    /// OASF skill names (`--skill`).
    pub skills: Vec<String>,
    /// OASF domain names (`--domain`).
    pub domains: Vec<String>,
    /// The agent's version (`--version`); defaults to agentbridge's.
    pub version: Option<String>,
    /// URL to advertise for the `--a2a-listen` interface (`--advertise-url`),
    /// when the listen address isn't what clients connect to.
    pub advertise_url: Option<String>,
    /// OASF schema server (`--oasf-schema-url`).
    pub oasf_schema_url: String,
    /// OASF schema version (`--oasf-schema-version`).
    pub oasf_schema_version: String,
    /// Skip checking skills and domains against the OASF server.
    pub skip_validation: bool,
}

impl CardOptions {
    /// Advertise the version (unless `--version` is given), skills and domains
    /// of the `--record` the agent runs, next to the flags'. Skills and domains
    /// only when the record uses the card's OASF version: class names differ
    /// between versions, and the card states one.
    pub fn add_record(&mut self, record: &super::record::SourceRecord) {
        if self.version.is_none() && !record.version.is_empty() {
            self.version = Some(record.version.clone());
        }

        if record.schema_version != self.oasf_schema_version {
            eprintln!(
                "[agentbridge] warning: record {} uses OASF {}, the card OASF {}; \
                 its skills and domains are not advertised (pass them with --skill / --domain)",
                record.name, record.schema_version, self.oasf_schema_version
            );
            return;
        }

        let mut skills = record.skills.clone();
        skills.append(&mut self.skills);
        self.skills = skills;

        let mut domains = record.domains.clone();
        domains.append(&mut self.domains);
        self.domains = domains;
    }
}

/// The resolved card settings every card builder reads.
#[derive(Clone, Debug)]
pub struct CardConfig {
    skills: Vec<String>,
    domains: Vec<String>,
    version: String,
    advertise_url: Option<String>,
    schema_url: String,
    schema_version: String,
}

impl Default for CardConfig {
    fn default() -> Self {
        Self::from_options(&CardOptions {
            oasf_schema_url: DEFAULT_OASF_SCHEMA_URL.to_string(),
            oasf_schema_version: DEFAULT_OASF_SCHEMA_VERSION.to_string(),
            ..CardOptions::default()
        })
    }
}

static CARD_CONFIG: OnceLock<CardConfig> = OnceLock::new();

/// Set the card settings for this process. Validates skills and domains
/// against the OASF server unless validation is skipped, so `register` fails
/// before any listener starts. Call once, before serving.
pub fn configure(opts: &CardOptions) -> anyhow::Result<()> {
    let config = CardConfig::from_options(opts);
    require_skill_for_domains(&config)?;

    if config.skills.is_empty() {
        // Nothing to advertise, so nothing to validate.
    } else if opts.skip_validation {
        eprintln!(
            "[agentbridge] warning: OASF validation skipped; skills and domains are advertised unchecked"
        );
    } else {
        validate(&config)?;
    }

    CARD_CONFIG
        .set(config)
        .map_err(|_| anyhow::anyhow!("card settings were already configured"))
}

/// The OASF `discovery` object requires skills, so domains alone can't be
/// advertised.
fn require_skill_for_domains(config: &CardConfig) -> anyhow::Result<()> {
    if config.skills.is_empty() && !config.domains.is_empty() {
        anyhow::bail!(
            "--domain needs at least one --skill: the OASF discovery object requires skills"
        );
    }
    Ok(())
}

/// The settings in effect: the configured ones, or the defaults when none were
/// set (unit tests, and commands that never call [`configure`]).
pub fn config() -> CardConfig {
    CARD_CONFIG.get().cloned().unwrap_or_default()
}

impl CardConfig {
    pub(crate) fn from_options(opts: &CardOptions) -> Self {
        let mut skills: Vec<String> = Vec::new();
        for skill in &opts.skills {
            if !skills.contains(skill) {
                skills.push(skill.clone());
            }
        }

        let mut domains: Vec<String> = Vec::new();
        for domain in &opts.domains {
            if !domains.contains(domain) {
                domains.push(domain.clone());
            }
        }

        Self {
            skills,
            domains,
            version: opts
                .version
                .clone()
                .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string()),
            advertise_url: opts.advertise_url.clone().filter(|u| !u.is_empty()),
            schema_url: opts.oasf_schema_url.trim_end_matches('/').to_string(),
            schema_version: opts.oasf_schema_version.clone(),
        }
    }

    /// The agent's version, shown in its card.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The URL to advertise for the `--a2a-listen` interface, if overridden.
    pub fn advertise_url(&self) -> Option<&str> {
        self.advertise_url.as_deref()
    }

    /// The OASF `discovery` payload: schema version, skills and domains.
    pub fn discovery_payload(&self) -> Value {
        let classes = |names: &[String]| -> Vec<Value> {
            names.iter().map(|name| json!({ "name": name })).collect()
        };

        let mut payload = json!({
            "schema_version": self.schema_version,
            "skills": classes(&self.skills),
        });

        if !self.domains.is_empty() {
            payload["domains"] = Value::Array(classes(&self.domains));
        }

        payload
    }

    /// The card extensions: the OASF `discovery` extension, when the agent has
    /// a skill.
    pub fn extensions(&self) -> Vec<AgentExtension> {
        if self.skills.is_empty() {
            return Vec::new();
        }

        vec![AgentExtension {
            uri: format!(
                "{}/{}/objects/discovery",
                self.schema_url, self.schema_version
            ),
            description: Some("OASF skills and domains".to_string()),
            required: Some(false),
            params: Some(to_params(self.discovery_payload())),
        }]
    }

    fn validation_url(&self) -> String {
        format!(
            "{}/api/{}/validate/object/discovery",
            self.schema_url, self.schema_version
        )
    }
}

fn to_params(value: Value) -> HashMap<String, Value> {
    match value {
        Value::Object(map) => map.into_iter().collect(),
        _ => HashMap::new(),
    }
}

/// Check the `discovery` payload against the OASF server's validator for the
/// configured schema version.
fn validate(config: &CardConfig) -> anyhow::Result<()> {
    let url = config.validation_url();

    let client = reqwest::blocking::Client::builder()
        .timeout(VALIDATION_TIMEOUT)
        .build()?;

    let response = client
        .post(&url)
        .json(&config.discovery_payload())
        .send()
        .map_err(|e| {
            anyhow::anyhow!(
                "could not reach the OASF server to validate skills and domains ({url}): {e}.\n\
                 Under `shadictl --net-block`, allow it with `--net-allow {host}`; \
                 or fix --oasf-schema-url, or pass --skip-oasf-validation to advertise them unchecked.",
                host = net_allow_target(&config.schema_url)
            )
        })?;

    if !response.status().is_success() {
        anyhow::bail!(
            "OASF validation request failed ({url}): HTTP {}. \
             Check --oasf-schema-url and --oasf-schema-version.",
            response.status()
        );
    }

    let body: Value = response.json()?;
    let errors = validation_errors(&body).map_err(|e| {
        anyhow::anyhow!(
            "the OASF server at {url} didn't answer like an OASF validator: {e}. \
             Check --oasf-schema-url, or pass --skip-oasf-validation to advertise them unchecked."
        )
    })?;

    if errors.is_empty() {
        return Ok(());
    }

    anyhow::bail!(
        "skills or domains are not in OASF {}:\n  {}",
        config.schema_version,
        errors.join("\n  ")
    )
}

/// `host:port` of a URL, as `shadictl --net-allow` takes it.
fn net_allow_target(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("https", url));
    let authority = rest.split('/').next().unwrap_or(rest);
    if authority
        .rsplit_once(':')
        .is_some_and(|(_, port)| port.parse::<u16>().is_ok())
    {
        return authority.to_string();
    }
    let port = if scheme == "http" { 80 } else { 443 };
    format!("{authority}:{port}")
}

/// Human-readable lines for each error in an OASF validation response. A
/// response without an `errors` array and a matching `error_count` isn't a
/// validator's answer, so it doesn't count as a pass.
fn validation_errors(body: &Value) -> Result<Vec<String>, String> {
    let errors = body
        .get("errors")
        .and_then(Value::as_array)
        .ok_or("no `errors` list")?;
    let count = body
        .get("error_count")
        .and_then(Value::as_u64)
        .ok_or("no `error_count`")?;
    if count != errors.len() as u64 {
        return Err(format!(
            "`error_count` is {count} but {} errors are listed",
            errors.len()
        ));
    }

    Ok(errors
        .iter()
        .map(|e| {
            let message = e
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("invalid");
            match e.get("attribute_path").and_then(Value::as_str) {
                Some(path) => format!("{path}: {message}"),
                None => message.to_string(),
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn options() -> CardOptions {
        CardOptions {
            oasf_schema_url: DEFAULT_OASF_SCHEMA_URL.to_string(),
            oasf_schema_version: DEFAULT_OASF_SCHEMA_VERSION.to_string(),
            ..CardOptions::default()
        }
    }

    fn discovery_skills(config: &CardConfig) -> Vec<String> {
        config.discovery_payload()["skills"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["name"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn nothing_is_advertised_without_a_skill() {
        let config = CardConfig::from_options(&options());

        assert!(config.extensions().is_empty());
        assert_eq!(config.version(), env!("CARGO_PKG_VERSION"));
        assert!(config.advertise_url().is_none());
        require_skill_for_domains(&config).expect("no skill, no domain");
    }

    #[test]
    fn a_domain_without_a_skill_is_refused() {
        let err = require_skill_for_domains(&CardConfig::from_options(&CardOptions {
            domains: vec!["technology/networking/network_security".into()],
            ..options()
        }))
        .unwrap_err()
        .to_string();
        assert!(err.contains("--domain needs at least one --skill"), "{err}");
    }

    #[test]
    fn the_given_skills_are_advertised_once_each_in_order() {
        let config = CardConfig::from_options(&CardOptions {
            skills: vec![
                "software_engineering/code_debugging/error_handling".into(),
                "ai_ml_engineering/agent_orchestration/multi_agent_coordination".into(),
                "software_engineering/code_debugging/error_handling".into(),
            ],
            version: Some("2.0.0".into()),
            ..options()
        });

        assert_eq!(
            discovery_skills(&config),
            vec![
                "software_engineering/code_debugging/error_handling",
                "ai_ml_engineering/agent_orchestration/multi_agent_coordination"
            ]
        );
        assert_eq!(config.version(), "2.0.0");
    }

    fn record(schema_version: &str) -> super::super::record::SourceRecord {
        super::super::record::SourceRecord {
            cid: "bafy".into(),
            name: "code-review".into(),
            version: "1.0.0".into(),
            schema_version: schema_version.into(),
            skills: vec!["software_engineering/code_review".into()],
            domains: vec!["technology/software_engineering".into()],
        }
    }

    #[test]
    fn a_records_classes_join_the_flags_when_its_oasf_version_matches() {
        let mut opts = CardOptions {
            skills: vec!["software_engineering/code_debugging/error_handling".into()],
            ..options()
        };
        opts.add_record(&record("1.1.0"));

        let config = CardConfig::from_options(&opts);
        assert_eq!(
            discovery_skills(&config),
            vec![
                "software_engineering/code_review",
                "software_engineering/code_debugging/error_handling"
            ]
        );
        assert_eq!(
            config.discovery_payload()["domains"],
            json!([{ "name": "technology/software_engineering" }])
        );
        assert_eq!(config.version(), "1.0.0");
    }

    #[test]
    fn a_record_in_another_oasf_version_adds_nothing() {
        let mut opts = options();
        opts.add_record(&record("1.0.0"));

        assert!(opts.skills.is_empty());
        assert!(opts.domains.is_empty());
        assert_eq!(opts.version.as_deref(), Some("1.0.0"));
    }

    #[test]
    fn the_only_extension_is_discovery_with_the_versioned_object_uri() {
        let config = CardConfig::from_options(&CardOptions {
            skills: vec!["software_engineering/code_debugging/error_handling".into()],
            domains: vec!["technology/networking/network_security".into()],
            oasf_schema_url: "http://localhost:8080/".into(),
            ..options()
        });

        let extensions = config.extensions();
        assert_eq!(extensions.len(), 1);
        assert_eq!(
            extensions[0].uri,
            "http://localhost:8080/1.1.0/objects/discovery"
        );

        let params = extensions[0].params.as_ref().expect("params");
        assert_eq!(params["schema_version"], json!("1.1.0"));
        assert_eq!(
            params["domains"],
            json!([{ "name": "technology/networking/network_security" }])
        );
    }

    #[test]
    fn domains_are_left_out_when_none_are_given() {
        assert!(CardConfig::from_options(&CardOptions {
            skills: vec!["software_engineering/code_debugging/error_handling".into()],
            ..options()
        })
        .discovery_payload()
        .get("domains")
        .is_none());
    }

    #[test]
    fn net_allow_target_keeps_the_port_or_uses_the_schemes() {
        assert_eq!(
            net_allow_target("https://schema.oasf.outshift.com"),
            "schema.oasf.outshift.com:443"
        );
        assert_eq!(
            net_allow_target("http://localhost:8080/x"),
            "localhost:8080"
        );
        assert_eq!(net_allow_target("http://localhost"), "localhost:80");
    }

    /// Serve one HTTP response on a free loopback port and return its URL.
    fn serve_once(status: &str, body: &str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );

        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 8192];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(response.as_bytes());
            }
        });

        format!("http://{addr}")
    }

    fn config_for(url: String) -> CardConfig {
        CardConfig::from_options(&CardOptions {
            skills: vec!["software_engineering/code_debugging/error_handling".into()],
            oasf_schema_url: url,
            ..options()
        })
    }

    #[test]
    fn validate_accepts_a_response_without_errors() {
        let url = serve_once("200 OK", r#"{"errors":[],"error_count":0}"#);

        validate(&config_for(url)).expect("valid payload");
    }

    #[test]
    fn validate_reports_the_validators_errors() {
        let url = serve_once(
            "200 OK",
            r#"{"errors":[{"message":"Unknown \"name\" value","attribute_path":"skills[1]"}],"error_count":1}"#,
        );

        let err = validate(&config_for(url)).unwrap_err().to_string();
        assert!(err.contains("not in OASF 1.1.0"), "{err}");
        assert!(err.contains("skills[1]: Unknown \"name\" value"), "{err}");
    }

    #[test]
    fn validate_refuses_a_response_that_isnt_a_validators() {
        for body in [
            "{}",
            r#"{"error":"validation unavailable"}"#,
            r#"{"errors":[]}"#,
            r#"{"errors":[],"error_count":2}"#,
        ] {
            let url = serve_once("200 OK", body);

            let err = validate(&config_for(url)).unwrap_err().to_string();
            assert!(
                err.contains("didn't answer like an OASF validator"),
                "{body}: {err}"
            );
        }
    }

    #[test]
    fn validate_fails_on_a_non_success_status() {
        let url = serve_once("404 Not Found", "{}");

        let err = validate(&config_for(url)).unwrap_err().to_string();
        assert!(err.contains("HTTP 404"), "{err}");
    }

    #[test]
    fn validate_explains_an_unreachable_server() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let err = validate(&config_for(format!("http://{addr}")))
            .unwrap_err()
            .to_string();
        assert!(err.contains("could not reach the OASF server"), "{err}");
        assert!(err.contains(&format!("--net-allow {addr}")), "{err}");
        assert!(err.contains("--skip-oasf-validation"), "{err}");
    }

    #[test]
    fn validation_errors_are_reported_with_their_path() {
        let body = json!({
            "errors": [{ "message": "Unknown \"name\" value", "attribute_path": "skills[1]" }],
        });

        assert_eq!(
            validation_errors(&body),
            Err("no `error_count`".to_string())
        );
        let body = json!({
            "errors": [{ "message": "Unknown \"name\" value", "attribute_path": "skills[1]" }],
            "error_count": 1,
        });
        assert_eq!(
            validation_errors(&body),
            Ok(vec!["skills[1]: Unknown \"name\" value".to_string()])
        );
        assert_eq!(
            validation_errors(&json!({ "errors": [], "error_count": 0 })),
            Ok(vec![])
        );
    }
}
