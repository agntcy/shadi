// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct SandboxPolicy {
    allow_read: Vec<PathBuf>,
    allow_write: Vec<PathBuf>,
    net_block: bool,
}

impl SandboxPolicy {
    pub fn new() -> Self {
        Self {
            allow_read: Vec::new(),
            allow_write: Vec::new(),
            net_block: false,
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

    pub fn allow_read(&self) -> &[PathBuf] {
        &self.allow_read
    }

    pub fn allow_write(&self) -> &[PathBuf] {
        &self.allow_write
    }

    pub fn net_blocked(&self) -> bool {
        self.net_block
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
    }
}
