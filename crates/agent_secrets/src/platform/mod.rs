// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(target_os = "macos"))]
mod noop;

use crate::SecretStore;

#[cfg(target_os = "macos")]
pub fn default_store() -> Box<dyn SecretStore> {
    Box::new(macos::MacosKeychainStore::new("agent_secrets"))
}

#[cfg(not(target_os = "macos"))]
pub fn default_store() -> Box<dyn SecretStore> {
    Box::new(noop::NoopSecretStore::new())
}
