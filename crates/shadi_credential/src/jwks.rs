// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! The issuer keys a verifier accepts, pinned on disk and resolved by
//! `(issuer, kid)`. Offline only: a listener must verify with the IdP down.

use std::collections::HashMap;
use std::path::Path;

use ed25519_dalek::VerifyingKey;
use serde_json::Value;

use crate::sd_jwt::ed25519_from_jwk;
use crate::vault::pin_issuer;
use crate::CredentialError;

/// A real realm's JWKS is a few KiB; this bounds what a bad path can make us
/// read into memory.
pub const MAX_JWKS_BYTES: u64 = 256 * 1024;

/// A pinned key, or the reason it cannot verify. Non-Ed25519 keys stay indexed
/// so a token naming one fails as unsupported rather than unknown.
enum Entry {
    Usable(VerifyingKey),
    Unsupported,
}

/// Pinned issuer keys.
#[derive(Default)]
#[non_exhaustive]
pub struct JwksStore {
    issuers: HashMap<String, Vec<(String, Entry)>>,
}

impl JwksStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pin the keys in the JWKS document at `path` as `issuer`'s.
    pub fn add_file(&mut self, issuer: &str, path: &Path) -> Result<(), CredentialError> {
        let shown = path.display();
        let len = std::fs::metadata(path)
            .map_err(|e| CredentialError::Storage(format!("cannot read {shown}: {e}")))?
            .len();
        if len > MAX_JWKS_BYTES {
            return Err(CredentialError::Refused(format!(
                "{shown} is {len} bytes, over the {MAX_JWKS_BYTES} byte limit"
            )));
        }
        let bytes = std::fs::read(path)
            .map_err(|e| CredentialError::Storage(format!("cannot read {shown}: {e}")))?;
        let doc: Value = serde_json::from_slice(&bytes)
            .map_err(|e| CredentialError::Malformed(format!("{shown} is not JSON: {e}")))?;
        let keys = doc
            .get("keys")
            .and_then(Value::as_array)
            .ok_or_else(|| CredentialError::Malformed(format!("{shown} has no `keys` array")))?;

        let mut entries: Vec<(String, Entry)> = Vec::with_capacity(keys.len());
        for jwk in keys {
            let kid = jwk
                .get("kid")
                .and_then(Value::as_str)
                .ok_or_else(|| CredentialError::Malformed("a JWK has no `kid`".to_string()))?;
            if entries.iter().any(|(k, _)| k == kid) {
                return Err(CredentialError::Malformed(format!(
                    "`kid` {kid} appears twice in {shown}"
                )));
            }
            let field = |name| jwk.get(name).and_then(Value::as_str);
            let ed25519 = field("kty") == Some("OKP")
                && field("crv") == Some("Ed25519")
                && field("alg").is_none_or(|a| a == "EdDSA");
            // `x5c` is deliberately ignored: the chain is unvalidated, so it
            // must never become trust material here.
            let entry = if ed25519 {
                Entry::Usable(ed25519_from_jwk(jwk, &format!("jwk {kid}"))?)
            } else {
                Entry::Unsupported
            };
            entries.push((kid.to_string(), entry));
        }
        if entries.is_empty() {
            return Err(CredentialError::Refused(format!(
                "{shown} holds no keys; an issuer with no key cannot verify anything"
            )));
        }
        self.issuers.insert(pin_issuer(issuer).to_string(), entries);
        Ok(())
    }

    /// The key to verify a token from `issuer` carrying header `kid` with.
    pub fn key(&self, issuer: &str, kid: Option<&str>) -> Result<VerifyingKey, CredentialError> {
        let issuer = pin_issuer(issuer);
        let entries = self
            .issuers
            .get(issuer)
            .ok_or_else(|| CredentialError::Refused(format!("issuer {issuer} is not pinned")))?;
        let entry = match kid {
            Some(kid) => entries
                .iter()
                .find(|(k, _)| k == kid)
                .map(|(_, e)| e)
                .ok_or_else(|| {
                    CredentialError::Refused(format!("issuer {issuer} has no key with kid {kid}"))
                })?,
            None => match entries.as_slice() {
                [(_, only)] => only,
                _ => {
                    return Err(CredentialError::Refused(format!(
                        "token names no kid and issuer {issuer} has several keys"
                    )))
                }
            },
        };
        match entry {
            Entry::Usable(key) => Ok(*key),
            Entry::Unsupported => Err(CredentialError::Refused(format!(
                "unsupported key type for issuer {issuer}: only OKP/Ed25519 (EdDSA) verifies"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use ed25519_dalek::SigningKey;
    use serde_json::json;

    const ISS: &str = "https://idp.example/realms/eng";

    fn key(seed: u8) -> VerifyingKey {
        VerifyingKey::from(&SigningKey::from_bytes(&[seed; 32]))
    }

    fn okp(kid: &str, seed: u8) -> Value {
        json!({"kty":"OKP","crv":"Ed25519","kid":kid,"alg":"EdDSA",
               "x": URL_SAFE_NO_PAD.encode(key(seed).as_bytes())})
    }

    fn store_with(keys: Value) -> Result<JwksStore, CredentialError> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jwks.json");
        std::fs::write(&path, json!({ "keys": keys }).to_string()).unwrap();
        let mut store = JwksStore::new();
        store.add_file(ISS, &path)?;
        Ok(store)
    }

    fn err(r: Result<impl Sized, CredentialError>) -> String {
        match r {
            Ok(_) => panic!("expected an error"),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn a_key_resolves_by_kid_with_the_bytes_written() {
        let store = store_with(json!([okp("a", 1)])).unwrap();
        assert_eq!(store.key(ISS, Some("a")).unwrap(), key(1));
    }

    #[test]
    fn unknown_issuer_and_unknown_kid_differ() {
        let store = store_with(json!([okp("a", 1)])).unwrap();
        let issuer = err(store.key("https://other.example", Some("a")));
        let kid = err(store.key(ISS, Some("zzz")));
        assert!(issuer.contains("not pinned"), "{issuer}");
        assert!(kid.contains("no key with kid"), "{kid}");
    }

    #[test]
    fn other_key_types_load_and_refuse_at_lookup() {
        let store = store_with(json!([
            {"kty":"RSA","kid":"rsa","n":"AQAB","e":"AQAB","alg":"RS256","x5c":["AAAA"]},
            {"kty":"EC","crv":"P-256","kid":"ec","x":"AA","y":"AA"},
            {"kty":"OKP","crv":"Ed25519","kid":"wrong-alg","alg":"RS256","x":"!!"},
            okp("ed", 2),
        ]))
        .unwrap();
        assert_eq!(store.key(ISS, Some("ed")).unwrap(), key(2));
        for kid in ["rsa", "ec", "wrong-alg"] {
            let e = err(store.key(ISS, Some(kid)));
            assert!(e.contains("unsupported key type"), "{kid}: {e}");
        }
    }

    #[test]
    fn a_malformed_ed25519_entry_is_refused_at_load() {
        for x in ["!!not-base64!!", "AAAA"] {
            let jwk = json!({"kty":"OKP","crv":"Ed25519","kid":"a","x":x});
            assert!(store_with(json!([jwk])).is_err(), "{x}");
        }
        // y = 2 has no matching x on the curve
        let mut off_curve = [0u8; 32];
        off_curve[0] = 2;
        let jwk = json!({"kty":"OKP","crv":"Ed25519","kid":"a",
                         "x": URL_SAFE_NO_PAD.encode(off_curve)});
        assert!(store_with(json!([jwk])).is_err());
    }

    #[test]
    fn an_absent_kid_resolves_only_against_a_single_key() {
        let one = store_with(json!([okp("a", 1)])).unwrap();
        assert_eq!(one.key(ISS, None).unwrap(), key(1));
        let two = store_with(json!([okp("a", 1), okp("b", 2)])).unwrap();
        assert!(two.key(ISS, None).is_err());
    }

    #[test]
    fn a_duplicate_kid_is_refused_at_load() {
        assert!(store_with(json!([okp("a", 1), okp("a", 2)])).is_err());
    }

    #[test]
    fn no_keys_is_refused_at_load() {
        assert!(store_with(json!([])).is_err());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jwks.json");
        std::fs::write(&path, "{}").unwrap();
        assert!(JwksStore::new().add_file(ISS, &path).is_err());
    }

    #[test]
    fn a_trailing_slash_does_not_matter_either_way() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jwks.json");
        std::fs::write(&path, json!({"keys":[okp("a", 1)]}).to_string()).unwrap();
        let mut slashed = JwksStore::new();
        slashed.add_file(&format!("{ISS}/"), &path).unwrap();
        assert!(slashed.key(ISS, Some("a")).is_ok());
        let mut bare = JwksStore::new();
        bare.add_file(ISS, &path).unwrap();
        assert!(bare.key(&format!("{ISS}/"), Some("a")).is_ok());
    }

    #[test]
    fn a_file_over_the_cap_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jwks.json");
        std::fs::write(&path, vec![b' '; MAX_JWKS_BYTES as usize + 1]).unwrap();
        let e = err(JwksStore::new().add_file(ISS, &path));
        assert!(e.contains("byte limit"), "{e}");
    }

    #[test]
    fn a_missing_or_non_json_file_is_a_clear_error() {
        let dir = tempfile::tempdir().unwrap();
        let missing = err(JwksStore::new().add_file(ISS, &dir.path().join("nope.json")));
        assert!(missing.contains("cannot read"), "{missing}");
        let path = dir.path().join("jwks.json");
        std::fs::write(&path, "not json").unwrap();
        let bad = err(JwksStore::new().add_file(ISS, &path));
        assert!(bad.contains("not JSON"), "{bad}");
    }
}
