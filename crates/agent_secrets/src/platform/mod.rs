// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(target_os = "macos"))]
mod noop;
#[cfg(feature = "onepassword")]
pub mod onepassword;

use crate::SecretStore;

pub fn default_store() -> Box<dyn SecretStore> {
    #[cfg(feature = "onepassword")]
    {
        if let Ok(backend) = std::env::var("SHADI_SECRET_BACKEND") {
            if backend.eq_ignore_ascii_case("onepassword") {
                return Box::new(onepassword::OnePasswordStore::new(None, None));
            }
        }
    }

    platform_store()
}

#[cfg(target_os = "macos")]
fn platform_store() -> Box<dyn SecretStore> {
    Box::new(macos::MacosKeychainStore::new("agent_secrets"))
}

#[cfg(not(target_os = "macos"))]
fn platform_store() -> Box<dyn SecretStore> {
    Box::new(noop::NoopSecretStore::new())
}
