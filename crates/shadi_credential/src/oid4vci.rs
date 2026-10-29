// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Pure OID4VCI pieces: origin pinning, the proof JWT and ID-token checks.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value};
use shadi_identity::AgentIdentity;
use url::{Host, Origin, Url};

use crate::sd_jwt::decode_json;
use crate::CredentialError;

fn refused(msg: impl Into<String>) -> CredentialError {
    CredentialError::Refused(msg.into())
}

/// The origin every IdP-supplied URL is pinned to.
#[derive(Debug, Clone)]
pub struct IdpOrigin(Origin);

impl IdpOrigin {
    /// Accept `https`, or `http` only on a loopback host.
    pub fn new(idp: &str) -> Result<Self, CredentialError> {
        let url = Url::parse(idp).map_err(|_| refused("IdP URL is not a valid URL"))?;
        let loopback = match url.host() {
            Some(Host::Domain(d)) => d == "localhost",
            Some(Host::Ipv4(ip)) => ip.is_loopback(),
            Some(Host::Ipv6(ip)) => ip.is_loopback(),
            None => false,
        };
        match url.scheme() {
            "https" => {}
            "http" if loopback => {}
            "http" => return Err(refused("IdP must use https unless it is loopback")),
            _ => return Err(refused("IdP URL must be http or https")),
        }
        Ok(Self(url.origin()))
    }

    /// Return the parsed URL when it is on the pinned origin.
    pub fn check(&self, url: &str) -> Result<Url, CredentialError> {
        let parsed = Url::parse(url).map_err(|_| refused("IdP-supplied URL is not a valid URL"))?;
        let origin = parsed.origin();
        if origin != self.0 {
            return Err(refused(format!(
                "IdP-supplied URL origin {} does not match {}",
                origin.ascii_serialization(),
                self.0.ascii_serialization()
            )));
        }
        Ok(parsed)
    }
}

/// Build the OID4VCI proof-of-possession JWT, with a `kid`-less JWK in the header.
pub fn proof_jwt(
    identity: &AgentIdentity,
    client_id: &str,
    audience: &str,
    nonce: &str,
    now: i64,
) -> String {
    let header = json!({
        "alg": "EdDSA",
        "typ": "openid4vci-proof+jwt",
        "jwk": {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode(identity.verifying_key_bytes()),
        },
    });
    let payload = json!({ "iss": client_id, "aud": audience, "iat": now, "nonce": nonce });
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(payload.to_string())
    );
    let sig = identity.sign_bytes(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig))
}

/// Who authenticated, as read from the ID token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdTokenClaims {
    pub subject: String,
    pub email: String,
}

/// Check the ID token claims. Errors never carry token content.
pub fn check_id_token(
    id_token: &str,
    issuer: &str,
    client_id: &str,
    expected_email: &str,
    now: i64,
) -> Result<IdTokenClaims, CredentialError> {
    let parts: Vec<&str> = id_token.split('.').collect();
    if parts.len() != 3 {
        return Err(CredentialError::Malformed(
            "ID token is not three dot-separated segments".into(),
        ));
    }
    // The signature is not checked here.
    let claims = decode_json(parts[1], "ID token payload")?;

    if claims.get("iss").and_then(Value::as_str) != Some(issuer) {
        return Err(refused("ID token iss does not match the issuer"));
    }
    match claims.get("exp").and_then(Value::as_i64) {
        Some(exp) if exp > now => {}
        Some(_) => return Err(refused("ID token has expired")),
        None => return Err(refused("ID token has no exp")),
    }
    let azp = claims.get("azp");
    let azp_ok = azp.is_some_and(|azp| azp.as_str() == Some(client_id));
    let aud_ok = match claims.get("aud") {
        Some(Value::String(a)) => a == client_id,
        // A token for several audiences must say which party it was issued to.
        Some(Value::Array(a)) => {
            a.iter().any(|v| v.as_str() == Some(client_id)) && (a.len() == 1 || azp_ok)
        }
        _ => false,
    };
    if !aud_ok {
        return Err(refused("ID token aud is not trusted for the client id"));
    }
    if azp.is_some() && !azp_ok {
        return Err(refused("ID token azp is not the client id"));
    }
    if claims.get("email_verified") != Some(&Value::Bool(true)) {
        return Err(refused("ID token email is not verified"));
    }
    let email = match claims.get("email").and_then(Value::as_str) {
        Some(e) if e.eq_ignore_ascii_case(expected_email) => e,
        Some(_) => {
            return Err(refused(format!(
                "ID token email is not the expected {expected_email}"
            )))
        }
        None => return Err(refused("ID token has no email")),
    };
    let subject = match claims.get("sub").and_then(Value::as_str) {
        Some(s) if !s.is_empty() => s,
        _ => return Err(refused("ID token has no sub")),
    };
    Ok(IdTokenClaims {
        subject: subject.to_string(),
        email: email.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier};

    fn origin(s: &str) -> IdpOrigin {
        IdpOrigin::new(s).unwrap()
    }

    #[test]
    fn origin_accepts_https_and_loopback_http() {
        assert!(IdpOrigin::new("https://idp.example.com").is_ok());
        assert!(IdpOrigin::new("http://127.0.0.1:8080").is_ok());
        assert!(IdpOrigin::new("http://localhost:8080").is_ok());
    }

    #[test]
    fn origin_refuses_remote_http_and_other_schemes() {
        assert!(matches!(
            IdpOrigin::new("http://idp.example.com"),
            Err(CredentialError::Refused(_))
        ));
        assert!(matches!(
            IdpOrigin::new("ftp://idp.example.com"),
            Err(CredentialError::Refused(_))
        ));
    }

    #[test]
    fn check_accepts_same_origin() {
        let o = origin("https://idp.example.com");
        assert!(o.check("https://idp.example.com/other/path").is_ok());
        assert!(o.check("https://idp.example.com:443/x").is_ok());
        assert!(origin("https://idp.example.com:443")
            .check("https://idp.example.com/x")
            .is_ok());
    }

    #[test]
    fn check_refuses_other_origins() {
        let o = origin("https://idp.example.com");
        for bad in [
            "https://evil.example.com/x",
            "https://idp.example.com:8443/x",
            "http://idp.example.com/x",
        ] {
            assert!(
                matches!(o.check(bad), Err(CredentialError::Refused(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn check_error_omits_path() {
        let err = origin("https://idp.example.com")
            .check("https://evil.example.com/offer/SECRET-NONCE")
            .unwrap_err()
            .to_string();
        assert!(!err.contains("SECRET-NONCE"));
        assert!(!err.contains("/offer"));
    }

    #[test]
    fn proof_jwt_shape_and_signature() {
        let id = AgentIdentity::generate().unwrap();
        let jwt = proof_jwt(&id, "client", "https://issuer", "n-1", 1_700_000_000);
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);

        let header = decode_json(parts[0], "header").unwrap();
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(header["typ"], "openid4vci-proof+jwt");
        let jwk = header["jwk"].as_object().unwrap();
        assert!(!jwk.contains_key("kid"));
        assert_eq!(jwk["kty"], "OKP");
        assert_eq!(jwk["crv"], "Ed25519");
        let x = URL_SAFE_NO_PAD.decode(jwk["x"].as_str().unwrap()).unwrap();
        assert_eq!(x, id.verifying_key_bytes());

        let payload = decode_json(parts[1], "payload").unwrap();
        assert_eq!(payload["iss"], "client");
        assert_eq!(payload["aud"], "https://issuer");
        assert_eq!(payload["nonce"], "n-1");
        assert_eq!(payload["iat"], 1_700_000_000);

        let sig = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        let sig = Signature::from_slice(&sig).unwrap();
        let input = format!("{}.{}", parts[0], parts[1]);
        id.verifying_key().verify(input.as_bytes(), &sig).unwrap();
    }

    const ISS: &str = "https://idp.example.com";
    const CLIENT: &str = "shadi";
    const EMAIL: &str = "dev@example.com";
    const NOW: i64 = 1_000;

    fn good() -> Value {
        json!({
            "iss": ISS, "exp": NOW + 60, "aud": CLIENT, "email_verified": true,
            "email": EMAIL, "sub": "user-1",
        })
    }

    fn token(claims: &Value) -> String {
        format!(
            "{}.{}.sig",
            URL_SAFE_NO_PAD.encode("{}"),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        )
    }

    fn run(claims: &Value) -> Result<IdTokenClaims, CredentialError> {
        check_id_token(&token(claims), ISS, CLIENT, EMAIL, NOW)
    }

    fn without(key: &str) -> Value {
        let mut c = good();
        c.as_object_mut().unwrap().remove(key);
        c
    }

    fn with(key: &str, value: Value) -> Value {
        let mut c = good();
        c[key] = value;
        c
    }

    fn assert_refused(claims: &Value) {
        let err = run(claims).unwrap_err();
        assert!(matches!(err, CredentialError::Refused(_)), "{err}");
    }

    #[test]
    fn id_token_passes() {
        let c = run(&good()).unwrap();
        assert_eq!(c.subject, "user-1");
        assert_eq!(c.email, EMAIL);
    }

    #[test]
    fn id_token_wrong_iss() {
        assert_refused(&with("iss", json!("https://other")));
    }

    #[test]
    fn id_token_expired_or_no_exp() {
        assert_refused(&with("exp", json!(NOW)));
        assert_refused(&without("exp"));
    }

    #[test]
    fn id_token_aud_forms() {
        let multi = with("aud", json!([CLIENT, "other"]));
        assert_refused(&multi);
        assert!(run(&with("azp", json!(CLIENT))).is_ok());
        let mut ok = multi.clone();
        ok["azp"] = json!(CLIENT);
        assert!(run(&ok).is_ok());
        ok["azp"] = json!("other");
        assert_refused(&ok);
        assert_refused(&with("aud", json!(["other"])));
        let mut other = with("aud", json!(["other", "third"]));
        other["azp"] = json!(CLIENT);
        assert_refused(&other);
        assert!(run(&with("aud", json!([CLIENT]))).is_ok());
        assert_refused(&with("azp", json!(7)));
        assert_refused(&with("aud", json!("other")));
        assert_refused(&without("aud"));
    }

    #[test]
    fn id_token_azp() {
        assert!(run(&with("azp", json!(CLIENT))).is_ok());
        assert_refused(&with("azp", json!("other")));
    }

    #[test]
    fn id_token_email_verified() {
        assert_refused(&without("email_verified"));
        assert_refused(&with("email_verified", json!(false)));
        assert_refused(&with("email_verified", json!("true")));
    }

    #[test]
    fn id_token_email_mismatch_names_only_expected() {
        let err = run(&with("email", json!("attacker@evil.example")))
            .unwrap_err()
            .to_string();
        assert!(err.contains(EMAIL));
        assert!(!err.contains("attacker"));
        assert_refused(&without("email"));
    }

    #[test]
    fn id_token_email_is_case_insensitive() {
        let c = run(&with("email", json!("DEV@Example.com"))).unwrap();
        assert_eq!(c.email, "DEV@Example.com");
    }

    #[test]
    fn id_token_needs_sub() {
        assert_refused(&without("sub"));
        assert_refused(&with("sub", json!("")));
    }

    #[test]
    fn id_token_errors_hide_claims() {
        let err = run(&with("iss", json!("https://secret-issuer")))
            .unwrap_err()
            .to_string();
        assert!(!err.contains("secret-issuer"));
    }

    #[test]
    fn id_token_needs_three_segments() {
        assert!(matches!(
            check_id_token("a.b", ISS, CLIENT, EMAIL, NOW),
            Err(CredentialError::Malformed(_))
        ));
    }
}
