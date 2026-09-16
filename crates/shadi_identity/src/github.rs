// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! The `did:key`s a GitHub account publishes.
//!
//! GitHub serves `https://github.com/<login>.keys` — every SSH public key on
//! the account, unauthenticated. Each `ssh-ed25519` entry is the same 32 bytes
//! a SHADI `did:key` encodes, so the listing *is* an attestation: GitHub
//! authenticated the human who uploaded it. [`GithubAnchor`] reads it.
//!
//! [`GithubAnchor`]: crate::trust_anchor::GithubAnchor

use crate::{encode_did_key, IdentityError};

/// GitHub's own limit on a login. The character set is the load-bearing half:
/// a login arrives from an unauthenticated peer hint and goes into a URL path.
const MAX_LOGIN_LEN: usize = 39;

/// Rejects anything that could escape the URL path — `../`, a query, a host.
fn is_github_login(login: &str) -> bool {
    !login.is_empty()
        && login.len() <= MAX_LOGIN_LEN
        && login
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// Every `did:key` derivable from the Ed25519 SSH keys `login` publishes.
///
/// `token` is optional — `.keys` is public — but pass one whenever you have
/// it: unauthenticated `api.github.com` allows 60 requests/hour against 5,000
/// authenticated, and admission depends on this call succeeding.
///
/// Returns every key, not the first. Picking one is fine when *deriving* a DID
/// and wrong when *verifying* one: an account with three keys would fail to
/// resolve for two of them.
///
/// GPG keys are not consulted. That path needs `sequoia-openpgp` and a token,
/// and `.keys` covers the accounts SHADI onboards; add it here if an account
/// publishes only a GPG key.
pub fn published_dids(login: &str, token: Option<&str>) -> Result<Vec<String>, IdentityError> {
    if !is_github_login(login) {
        return Err(IdentityError::Config(format!(
            "{login:?} is not a GitHub login"
        )));
    }
    let listing = fetch_ssh_keys(login, token)?;
    let dids = crate::ssh::all_ed25519_in_authorized_keys(&listing)
        .iter()
        .map(encode_did_key)
        .collect::<Vec<_>>();
    if dids.is_empty() {
        return Err(IdentityError::Config(format!(
            "github user {login} publishes no ssh-ed25519 key"
        )));
    }
    Ok(dids)
}

#[cfg(not(test))]
fn fetch_ssh_keys(login: &str, token: Option<&str>) -> Result<String, IdentityError> {
    let url = format!("https://github.com/{login}.keys");
    let mut request = reqwest::blocking::Client::builder()
        .timeout(crate::oidc::HTTP_TIMEOUT)
        .build()
        .map_err(|e| IdentityError::Config(format!("failed to build HTTP client: {e}")))?
        .get(&url)
        .header(reqwest::header::USER_AGENT, "shadi-identity");
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    request
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .and_then(reqwest::blocking::Response::text)
        .map_err(|e| IdentityError::Config(format!("GitHub request {url} failed: {e}")))
}

#[cfg(test)]
fn fetch_ssh_keys(_login: &str, _token: Option<&str>) -> Result<String, IdentityError> {
    test_seam::listing()
}

/// Canned listing for tests, mirroring `shadictl`'s own GitHub seam. No HTTP
/// mocking crate exists in this workspace and the anchor tests do not need one.
///
/// The seam is process-global, so [`TestKeys`] serialises access and clears it
/// on drop — two test modules read it and `cargo test` runs them in parallel.
#[cfg(test)]
pub(crate) mod test_seam {
    use std::sync::{Mutex, MutexGuard};

    use crate::IdentityError;

    static LISTING: Mutex<Option<String>> = Mutex::new(None);
    static SERIAL: Mutex<()> = Mutex::new(());

    pub(crate) struct TestKeys(#[allow(dead_code)] MutexGuard<'static, ()>);

    impl TestKeys {
        pub(crate) fn set(listing: &str) -> Self {
            let guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
            *LISTING.lock().unwrap() = Some(listing.to_string());
            Self(guard)
        }

        /// One `ssh-ed25519` `authorized_keys` line for `id`'s public key.
        pub(crate) fn ssh_line(id: &crate::AgentIdentity) -> String {
            use base64::Engine as _;
            let mut blob = Vec::new();
            for field in [b"ssh-ed25519".as_slice(), id.verifying_key_bytes().as_slice()] {
                blob.extend_from_slice(&(field.len() as u32).to_be_bytes());
                blob.extend_from_slice(field);
            }
            format!(
                "ssh-ed25519 {} test@shadi\n",
                base64::engine::general_purpose::STANDARD.encode(&blob)
            )
        }
    }

    impl Drop for TestKeys {
        fn drop(&mut self) {
            *LISTING.lock().unwrap() = None;
        }
    }

    pub(super) fn listing() -> Result<String, IdentityError> {
        LISTING
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| IdentityError::Config("test github listing not set".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A login is attacker-supplied (it arrives as a peer's principal hint),
    /// so it must never reach the URL unchecked.
    #[test]
    fn rejects_logins_that_are_not_logins() {
        for bad in [
            "",
            "a/../../etc/passwd",
            "alice?x=1",
            "alice.keys",
            "alice@corp.com",
            "alice bob",
            &"a".repeat(MAX_LOGIN_LEN + 1),
        ] {
            assert!(
                published_dids(bad, None).is_err(),
                "must reject login {bad:?}"
            );
        }
        assert!(is_github_login("alice-1"));
    }

    #[test]
    fn collects_every_published_ed25519_key() {
        let a = crate::AgentIdentity::generate().unwrap();
        let b = crate::AgentIdentity::generate().unwrap();
        let _keys = test_seam::TestKeys::set(&format!(
            "ssh-rsa AAAAB3NzaC1yc2EAAAA not-ed25519\n# a comment\n{}{}",
            test_seam::TestKeys::ssh_line(&a),
            test_seam::TestKeys::ssh_line(&b)
        ));
        let dids = published_dids("alice", None).unwrap();
        assert_eq!(dids, vec![a.did(), b.did()], "both keys must resolve");
    }

    #[test]
    fn account_without_an_ed25519_key_is_an_error() {
        let _keys = test_seam::TestKeys::set("ssh-rsa AAAAB3NzaC1yc2EAAAA only-rsa\n");
        assert!(published_dids("alice", None).is_err());
    }
}
