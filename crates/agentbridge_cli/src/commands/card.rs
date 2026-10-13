//! What `register` advertises in its A2A agent card beyond the transport:
//! OASF skills and domains, the agent's version, and the OASF `discovery` and
//! `identity` extensions that runtime discovery (dir-runtime) indexes.
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
/// and whose URIs name the card extensions.
pub const DEFAULT_OASF_SCHEMA_URL: &str = "https://schema.oasf.outshift.com";

/// OASF version the `discovery` and `identity` objects were released in.
pub const DEFAULT_OASF_SCHEMA_VERSION: &str = "1.1.0";

/// Always advertised: every bridged agent can join `coordinate` groups.
///
/// Names here are OASF 1.1.0 classes, the version the `discovery` extension is
/// validated against. The OASF record `--dir-publish` pushes keeps its own,
/// older names (`agentbridge::dir_registry`), which DIR search relies on.
const COORDINATION_SKILL: &str = "ai_ml_engineering/agent_orchestration/multi_agent_coordination";

/// Advertised only when no skill is given, since they describe any harness.
const GENERIC_SKILLS: [(&str, &str); 2] = [
    (
        "ai_ml_engineering/agent_orchestration/task_decomposition",
        "Breaks down and delegates coding tasks to other coding agents.",
    ),
    (
        "language_processing/language_generation/text_completion",
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
    /// DID of the human vouching for the agent (`--human-did`), a claim until
    /// a binding certificate is attached.
    pub human_did: Option<String>,
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
    explicit_skills: bool,
    version: String,
    human_did: Option<String>,
    agent_did: Option<String>,
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
pub fn configure(opts: &CardOptions, agent_did: Option<String>) -> anyhow::Result<()> {
    let mut config = CardConfig::from_options(opts);
    config.agent_did = agent_did;

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
    fn from_options(opts: &CardOptions) -> Self {
        let mut skills = vec![COORDINATION_SKILL.to_string()];
        let explicit_skills = !opts.skills.is_empty();

        if explicit_skills {
            for skill in &opts.skills {
                if !skills.contains(skill) {
                    skills.push(skill.clone());
                }
            }
        } else {
            skills.extend(GENERIC_SKILLS.iter().map(|(name, _)| name.to_string()));
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
            explicit_skills,
            version: opts
                .version
                .clone()
                .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string()),
            human_did: opts.human_did.clone().filter(|d| !d.is_empty()),
            agent_did: None,
            schema_url: opts.oasf_schema_url.trim_end_matches('/').to_string(),
            schema_version: opts.oasf_schema_version.clone(),
        }
    }

    /// The agent's version, shown in its card.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The card's skills: the OASF skills, each with a short description.
    pub fn agent_skills(&self) -> Vec<AgentSkill> {
        self.skills
            .iter()
            .map(|name| AgentSkill {
                id: name.clone(),
                name: name.clone(),
                description: describe(name, self.explicit_skills),
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

    /// The card extensions: `discovery` always, `identity` when the agent's DID
    /// is known.
    pub fn extensions(&self) -> Vec<AgentExtension> {
        let mut extensions = vec![AgentExtension {
            uri: self.object_uri("discovery"),
            description: Some("OASF skills and domains".to_string()),
            required: Some(false),
            params: Some(to_params(self.discovery_payload())),
        }];

        if let Some(agent_did) = &self.agent_did {
            let mut identity = json!({
                "schema_version": self.schema_version,
                "agent_did": agent_did,
            });

            if let Some(human_did) = &self.human_did {
                identity["human_did"] = json!(human_did);
            }

            extensions.push(AgentExtension {
                uri: self.object_uri("identity"),
                description: Some("Agent identity".to_string()),
                required: Some(false),
                params: Some(to_params(identity)),
            });
        }

        extensions
    }

    /// `<schema URL>/<version>/objects/<object>`, the URI dir-runtime matches.
    fn object_uri(&self, object: &str) -> String {
        format!(
            "{}/{}/objects/{object}",
            self.schema_url, self.schema_version
        )
    }
}

fn describe(name: &str, explicit: bool) -> String {
    if let Some((_, description)) = GENERIC_SKILLS.iter().find(|(n, _)| *n == name) {
        if !explicit {
            return description.to_string();
        }
    }

    if name == COORDINATION_SKILL {
        return "Coordinates and hands off task context between coding agents.".to_string();
    }

    format!("OASF skill {name}")
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
    let url = format!(
        "{}/api/{}/validate/object/discovery",
        config.schema_url, config.schema_version
    );

    let client = reqwest::blocking::Client::builder()
        .timeout(VALIDATION_TIMEOUT)
        .build()?;

    let response = client
        .post(&url)
        .json(&config.discovery_payload())
        .send()
        .map_err(|e| {
            anyhow::anyhow!(
                "could not reach the OASF server to validate skills and domains ({url}): {e}. \
                 Fix --oasf-schema-url, or pass --skip-oasf-validation to advertise them unchecked."
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

    fn options() -> CardOptions {
        CardOptions {
            oasf_schema_url: DEFAULT_OASF_SCHEMA_URL.to_string(),
            oasf_schema_version: DEFAULT_OASF_SCHEMA_VERSION.to_string(),
            ..CardOptions::default()
        }
    }

    fn skill_names(config: &CardConfig) -> Vec<String> {
        config.agent_skills().into_iter().map(|s| s.name).collect()
    }

    #[test]
    fn defaults_advertise_coordination_and_the_generic_skills() {
        let config = CardConfig::from_options(&options());

        assert_eq!(
            skill_names(&config),
            vec![
                COORDINATION_SKILL,
                "ai_ml_engineering/agent_orchestration/task_decomposition",
                "language_processing/language_generation/text_completion",
            ]
        );
        assert_eq!(config.version(), env!("CARGO_PKG_VERSION"));
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
            skill_names(&config),
            vec![
                COORDINATION_SKILL,
                "software_engineering/code_debugging/error_handling"
            ]
        );
        assert_eq!(config.version(), "2.0.0");
    }

    #[test]
    fn discovery_extension_uses_the_versioned_object_uri() {
        let config = CardConfig::from_options(&CardOptions {
            domains: vec!["technology/networking/network_security".into()],
            oasf_schema_url: "http://localhost:8080/".into(),
            ..options()
        });

        let extensions = config.extensions();
        assert_eq!(
            extensions.len(),
            1,
            "no identity extension without an agent DID"
        );
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
        assert_eq!(params["skills"][0], json!({ "name": COORDINATION_SKILL }));
    }

    #[test]
    fn identity_extension_carries_the_agent_and_human_dids() {
        let mut config = CardConfig::from_options(&CardOptions {
            human_did: Some("did:key:zHuman".into()),
            ..options()
        });
        config.agent_did = Some("did:key:zAgent".into());

        let extensions = config.extensions();
        let identity = extensions
            .iter()
            .find(|e| e.uri.ends_with("/objects/identity"))
            .expect("identity extension");
        let params = identity.params.as_ref().expect("params");

        assert_eq!(params["agent_did"], json!("did:key:zAgent"));
        assert_eq!(params["human_did"], json!("did:key:zHuman"));
    }

    #[test]
    fn domains_are_left_out_when_none_are_given() {
        let payload = CardConfig::from_options(&options()).discovery_payload();

        assert!(payload.get("domains").is_none());
    }

    #[test]
    fn validation_errors_are_reported_with_their_path() {
        let body = json!({
            "errors": [{ "message": "Unknown \"name\" value", "attribute_path": "skills[1]" }],
            "error_count": 1
        });

        assert_eq!(
            validation_errors(&body),
            vec!["skills[1]: Unknown \"name\" value"]
        );
        assert!(validation_errors(&json!({ "errors": [] })).is_empty());
    }
}
