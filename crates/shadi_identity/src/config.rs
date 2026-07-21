// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Builders for SLIM's JWT identity configs from DID material.
//!
//! - Provider: sign with an agent's Ed25519 key, `sub = did:key`, `aud = channel`.
//! - Verifier: trust the member DIDs' public keys (a JWKS) — the cryptographic
//!   allow-list. A JWT from a DID not in the set has no matching key and fails.

use std::time::Duration;

use slim_bindings::{
    ClientJwtAuth, IdentityProviderConfig, IdentityVerifierConfig, JwtAlgorithm, JwtAuth,
    JwtKeyConfig, JwtKeyData, JwtKeyFormat, JwtKeyType,
};

/// Default DID-JWT validity (kept short; the DID design relies on TTL + allow-list
/// removal for revocation).
pub const DEFAULT_TOKEN_TTL: Duration = Duration::from_secs(300);

/// Identity provider config: prove this agent's DID by signing a DID-JWT
/// (`sub = did`) with its Ed25519 private key (PKCS#8 PEM). `audience` scopes the
/// token to a channel when `Some`; `None` = identity-only (admission is the
/// verifier's allow-list). See the design note (aud binding).
pub fn did_provider_config(
    private_pem: &str,
    did: &str,
    audience: Option<&str>,
) -> IdentityProviderConfig {
    IdentityProviderConfig::Jwt {
        config: ClientJwtAuth {
            key: JwtKeyType::Encoding {
                key: JwtKeyConfig {
                    algorithm: JwtAlgorithm::EdDSA,
                    format: JwtKeyFormat::Pem,
                    key: JwtKeyData::Data {
                        value: private_pem.to_string(),
                    },
                },
            },
            audience: audience.map(|c| vec![c.to_string()]),
            // Self-issued DID-JWT: iss = sub = the agent's did:key. The verifier
            // requires an issuer claim to be present.
            issuer: Some(did.to_string()),
            subject: Some(did.to_string()),
            duration: DEFAULT_TOKEN_TTL,
        },
    }
}

/// Identity verifier config whose trusted-key set is `member_jwks` (the DID
/// allow-list). Only JWTs signed by a member DID verify; `audience` additionally
/// scopes to a channel when `Some`.
pub fn did_verifier_config(member_jwks: &str, audience: Option<&str>) -> IdentityVerifierConfig {
    IdentityVerifierConfig::Jwt {
        config: JwtAuth {
            key: JwtKeyType::Decoding {
                key: JwtKeyConfig {
                    algorithm: JwtAlgorithm::EdDSA,
                    format: JwtKeyFormat::Jwks,
                    key: JwtKeyData::Data {
                        value: member_jwks.to_string(),
                    },
                },
            },
            audience: audience.map(|c| vec![c.to_string()]),
            issuer: None,
            subject: None,
            duration: DEFAULT_TOKEN_TTL,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{jwks_from_dids, AgentIdentity};

    #[test]
    fn provider_config_sets_did_subject_and_channel_audience() {
        let id = AgentIdentity::generate().unwrap();
        let pem = id.to_pkcs8_pem().unwrap();
        let cfg = did_provider_config(&pem, &id.did(), Some("org/ns/chan"));
        match cfg {
            IdentityProviderConfig::Jwt { config } => {
                assert_eq!(config.subject.as_deref(), Some(id.did().as_str()));
                assert_eq!(config.audience, Some(vec!["org/ns/chan".to_string()]));
                match config.key {
                    JwtKeyType::Encoding { key } => {
                        assert_eq!(key.algorithm, JwtAlgorithm::EdDSA);
                        assert_eq!(key.format, JwtKeyFormat::Pem);
                        match key.key {
                            JwtKeyData::Data { value } => {
                                assert!(value.contains("BEGIN PRIVATE KEY"))
                            }
                            _ => panic!("expected inline key data"),
                        }
                    }
                    _ => panic!("expected an encoding key"),
                }
            }
            _ => panic!("expected a Jwt provider config"),
        }
    }

    #[test]
    fn verifier_config_uses_member_jwks_as_allow_list() {
        let a = AgentIdentity::generate().unwrap();
        let b = AgentIdentity::generate().unwrap();
        let jwks = jwks_from_dids([a.did().as_str(), b.did().as_str()]).unwrap();
        let cfg = did_verifier_config(&jwks, Some("org/ns/chan"));
        match cfg {
            IdentityVerifierConfig::Jwt { config } => {
                assert_eq!(config.audience, Some(vec!["org/ns/chan".to_string()]));
                match config.key {
                    JwtKeyType::Decoding { key } => {
                        assert_eq!(key.algorithm, JwtAlgorithm::EdDSA);
                        assert_eq!(key.format, JwtKeyFormat::Jwks);
                        match key.key {
                            JwtKeyData::Data { value } => {
                                assert!(value.contains(&a.did()));
                                assert!(value.contains(&b.did()));
                            }
                            _ => panic!("expected inline JWKS data"),
                        }
                    }
                    _ => panic!("expected a decoding key"),
                }
            }
            _ => panic!("expected a Jwt verifier config"),
        }
    }
}
