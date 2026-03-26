// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformSandboxProfile {
    Compatibility,
    Minimal,
}

#[derive(Debug, Clone)]
pub struct SandboxPolicy {
    allow_read: Vec<PathBuf>,
    allow_write: Vec<PathBuf>,
    net_allow: Vec<String>,
    net_block: bool,
    platform_profile: PlatformSandboxProfile,
    allow_local_unix_sockets: bool,
}

impl SandboxPolicy {
    pub fn new() -> Self {
        Self {
            allow_read: Vec::new(),
            allow_write: Vec::new(),
            net_allow: Vec::new(),
            net_block: false,
            platform_profile: PlatformSandboxProfile::Compatibility,
            allow_local_unix_sockets: false,
        }
    }

    pub fn allow_read_path(mut self, path: impl AsRef<Path>) -> Self {
        self.allow_read.push(path.as_ref().to_path_buf());
        self
    }

    pub fn allow_write_path(mut self, path: impl AsRef<Path>) -> Self {
        self.allow_write.push(path.as_ref().to_path_buf());
        self
    }

    pub fn block_network(mut self, value: bool) -> Self {
        self.net_block = value;
        self
    }

    pub fn allow_network_destination(mut self, destination: impl Into<String>) -> Self {
        self.net_allow.push(destination.into());
        self
    }

    pub fn with_network_destinations(mut self, destinations: Vec<String>) -> Self {
        self.net_allow = destinations;
        self
    }

    pub fn use_minimal_platform_profile(mut self) -> Self {
        self.platform_profile = PlatformSandboxProfile::Minimal;
        self
    }

    pub fn allow_local_unix_sockets(mut self) -> Self {
        self.allow_local_unix_sockets = true;
        self
    }

    pub fn allow_read(&self) -> &[PathBuf] {
        &self.allow_read
    }

    pub fn allow_write(&self) -> &[PathBuf] {
        &self.allow_write
    }

    pub fn net_blocked(&self) -> bool {
        self.net_block
    }

    pub fn net_allow(&self) -> &[String] {
        &self.net_allow
    }

    pub fn platform_profile(&self) -> PlatformSandboxProfile {
        self.platform_profile
    }

    pub fn local_unix_sockets_allowed(&self) -> bool {
        self.allow_local_unix_sockets
    }
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_root() -> String {
        std::env::var("SHADI_TMP_DIR").unwrap_or_else(|_| "./.tmp".to_string())
    }

    #[test]
    fn policy_collects_paths_and_network_flag() {
        let tmp_dir = tmp_root();
        let policy = SandboxPolicy::new()
            .allow_read_path(&tmp_dir)
            .allow_write_path(&tmp_dir)
            .block_network(true);

        assert!(policy.allow_read().iter().any(|p| p == Path::new(&tmp_dir)));
        assert!(policy.allow_write().iter().any(|p| p == Path::new(&tmp_dir)));
        assert!(policy.net_blocked());
        assert_eq!(policy.platform_profile(), PlatformSandboxProfile::Compatibility);
    }

    #[test]
    fn policy_can_collect_network_destinations() {
        let policy = SandboxPolicy::new()
            .allow_network_destination("1.1.1.1:80")
            .allow_network_destination("api.github.com");

        assert_eq!(policy.net_allow(), &["1.1.1.1:80".to_string(), "api.github.com".to_string()]);
    }

    #[test]
    fn policy_can_replace_network_destinations() {
        let policy = SandboxPolicy::new()
            .allow_network_destination("1.1.1.1:80")
            .with_network_destinations(vec!["2.2.2.2:443".to_string()]);

        assert_eq!(policy.net_allow(), &["2.2.2.2:443".to_string()]);
    }

    #[test]
    fn policy_can_switch_to_minimal_platform_profile() {
        let policy = SandboxPolicy::new().use_minimal_platform_profile();
        assert_eq!(policy.platform_profile(), PlatformSandboxProfile::Minimal);
    }

    #[test]
    fn policy_can_allow_local_unix_sockets() {
        let policy = SandboxPolicy::new().allow_local_unix_sockets();
        assert!(policy.local_unix_sockets_allowed());
    }
}
