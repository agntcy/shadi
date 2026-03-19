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

#[cfg(test)]
pub(crate) fn selected_backend_for_tests() -> &'static str {
    #[cfg(feature = "onepassword")]
    {
        if let Ok(backend) = std::env::var("SHADI_SECRET_BACKEND") {
            if backend.eq_ignore_ascii_case("onepassword") {
                return "onepassword";
            }
        }
    }

    "platform"
}

#[cfg(target_os = "macos")]
fn platform_store() -> Box<dyn SecretStore> {
    Box::new(macos::MacosKeychainStore::new("agent_secrets"))
}

#[cfg(not(target_os = "macos"))]
fn platform_store() -> Box<dyn SecretStore> {
    Box::new(noop::NoopSecretStore::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn selected_backend_defaults_to_platform() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        std::env::remove_var("SHADI_SECRET_BACKEND");
        assert_eq!(selected_backend_for_tests(), "platform");
    }

    #[test]
    fn default_store_constructs_platform_backend() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        std::env::remove_var("SHADI_SECRET_BACKEND");
        let _store = default_store();
    }

    #[cfg(feature = "onepassword")]
    #[test]
    fn selected_backend_ignores_other_values() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        std::env::set_var("SHADI_SECRET_BACKEND", "noop");
        assert_eq!(selected_backend_for_tests(), "platform");
        std::env::remove_var("SHADI_SECRET_BACKEND");
    }
}
