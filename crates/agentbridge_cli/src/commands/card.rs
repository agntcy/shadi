//! What `register` advertises in its A2A agent card beyond the transport: the
//! agent's version, its A2A skills, and the OASF `discovery` extension (OASF
//! schema version, skills and domains) that runtime discovery (dir-runtime)
//! indexes.
//!
//! Each fact is stated once. OASF classes appear only in the `discovery`
//! extension; the card's A2A `skills` describe what agentbridge does in A2A
//! terms and are the same for every agent (the OASF record `--dir-publish`
//! pushes is built from them, and DIR search relies on their names).
//!
//! The configuration is set once per process, before any listener starts, and
//! read by every place that builds the card, so the served card, the
//! well-known card and the extended card always agree.

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Duration;

use a2a::{AgentExtension, AgentSkill};
use serde_json::{json, Value};

/// OASF schema server whose vocabulary skills and domains are checked against
/// and whose URIs name the card extension.
pub const DEFAULT_OASF_SCHEMA_URL: &str = "https://schema.oasf.outshift.com";

/// OASF version the `discovery` object was released in.
pub const DEFAULT_OASF_SCHEMA_VERSION: &str = "1.1.0";

/// Always in the `discovery` extension: every bridged agent can join
/// `coordinate` groups. An OASF 1.1.0 class.
const COORDINATION_SKILL: &str = "ai_ml_engineering/agent_orchestration/multi_agent_coordination";

/// In the `discovery` extension only when no skill is given, since they
/// describe any harness. OASF 1.1.0 classes.
const GENERIC_SKILLS: [&str; 2] = [
    "ai_ml_engineering/agent_orchestration/task_decomposition",
    "language_processing/language_generation/text_completion",
];

/// The card's A2A skills: what every agentbridge adapter offers over A2A.
/// Their ids predate OASF 1.1.0 and are kept as they are, because the record
/// `--dir-publish` pushes copies them and DIR search (e.g. the
/// dir-group-discovery demo) looks agents up by them.
const A2A_SKILLS: [(&str, &str); 3] = [
    (
        "agent_orchestration/task_decomposition",
        "Breaks down and delegates coding tasks to other coding agents.",
    ),
    (
        "agent_orchestration/agent_coordination",
        "Coordinates and hands off task context between coding agents.",
    ),
    (
        "natural_language_processing/natural_language_generation/text_completion",
        "Generates code and text completions on request.",
    ),
];

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

    if opts.skip_validation {
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

/// The settings in effect: the configured ones, or the defaults when none were
/// set (unit tests, and commands that never call [`configure`]).
pub fn config() -> CardConfig {
    CARD_CONFIG.get().cloned().unwrap_or_default()
}

impl CardConfig {
    pub(crate) fn from_options(opts: &CardOptions) -> Self {
        let mut skills = vec![COORDINATION_SKILL.to_string()];

        let extra: Vec<String> = if opts.skills.is_empty() {
            GENERIC_SKILLS.iter().map(|s| s.to_string()).collect()
        } else {
            opts.skills.clone()
        };

        for skill in extra {
            if !skills.contains(&skill) {
                skills.push(skill);
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

    /// The card's A2A skills, the same for every agentbridge adapter.
    pub fn agent_skills(&self) -> Vec<AgentSkill> {
        A2A_SKILLS
            .iter()
            .map(|(id, description)| AgentSkill {
                id: id.to_string(),
                name: id.to_string(),
                description: description.to_string(),
                tags: Vec::new(),
                examples: None,
                input_modes: None,
                output_modes: None,
                security_requirements: None,
            })
            .collect()
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

    /// The card extensions: the OASF `discovery` extension.
    pub fn extensions(&self) -> Vec<AgentExtension> {
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
                 Under `shadictl --net-block`, allow it with `--net-allow {host}:443` (or its port); \
                 or fix --oasf-schema-url, or pass --skip-oasf-validation to advertise them unchecked.",
                host = host_of(&config.schema_url)
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
    let errors = validation_errors(&body);

    if errors.is_empty() {
        return Ok(());
    }

    anyhow::bail!(
        "skills or domains are not in OASF {}:\n  {}",
        config.schema_version,
        errors.join("\n  ")
    )
}

fn host_of(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    rest.split(['/', ':']).next().unwrap_or(rest)
}

/// Human-readable lines for each error in an OASF validation response.
fn validation_errors(body: &Value) -> Vec<String> {
    body.get("errors")
        .and_then(Value::as_array)
        .map(|errors| {
            errors
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
                .collect()
        })
        .unwrap_or_default()
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
    fn defaults_put_coordination_and_the_generic_skills_in_the_extension() {
        let config = CardConfig::from_options(&options());

        assert_eq!(
            discovery_skills(&config),
            vec![COORDINATION_SKILL, GENERIC_SKILLS[0], GENERIC_SKILLS[1]]
        );
        assert_eq!(config.version(), env!("CARGO_PKG_VERSION"));
        assert!(config.advertise_url().is_none());
    }

    #[test]
    fn explicit_skills_replace_the_generic_ones_but_keep_coordination() {
        let config = CardConfig::from_options(&CardOptions {
            skills: vec![
                "software_engineering/code_debugging/error_handling".into(),
                COORDINATION_SKILL.into(),
            ],
            version: Some("2.0.0".into()),
            ..options()
        });

        assert_eq!(
            discovery_skills(&config),
            vec![
                COORDINATION_SKILL,
                "software_engineering/code_debugging/error_handling"
            ]
        );
        assert_eq!(config.version(), "2.0.0");
    }

    #[test]
    fn a2a_skills_stay_agentbridges_own_and_do_not_mirror_oasf_skills() {
        let config = CardConfig::from_options(&CardOptions {
            skills: vec!["software_engineering/code_debugging/error_handling".into()],
            ..options()
        });

        let ids: Vec<String> = config.agent_skills().into_iter().map(|s| s.id).collect();
        assert_eq!(
            ids,
            vec![
                "agent_orchestration/task_decomposition",
                "agent_orchestration/agent_coordination",
                "natural_language_processing/natural_language_generation/text_completion",
            ]
        );
    }

    #[test]
    fn the_only_extension_is_discovery_with_the_versioned_object_uri() {
        let config = CardConfig::from_options(&CardOptions {
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
        assert!(CardConfig::from_options(&options())
            .discovery_payload()
            .get("domains")
            .is_none());
    }

    #[test]
    fn host_of_strips_scheme_port_and_path() {
        assert_eq!(
            host_of("https://schema.oasf.outshift.com"),
            "schema.oasf.outshift.com"
        );
        assert_eq!(host_of("http://localhost:8080/x"), "localhost");
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
        assert!(err.contains("--net-allow 127.0.0.1:443"), "{err}");
        assert!(err.contains("--skip-oasf-validation"), "{err}");
    }

    #[test]
    fn validation_errors_are_reported_with_their_path() {
        let body = json!({
            "errors": [{ "message": "Unknown \"name\" value", "attribute_path": "skills[1]" }],
        });

        assert_eq!(
            validation_errors(&body),
            vec!["skills[1]: Unknown \"name\" value"]
        );
        assert!(validation_errors(&json!({ "errors": [] })).is_empty());
    }
}
