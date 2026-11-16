// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::process::Command;

use crate::{SandboxError, SandboxPolicy, SandboxedChild};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
pub(crate) mod macos;
#[cfg(target_os = "windows")]
pub(crate) mod windows;

/// Every directory the backend lets a sandboxed program write: the caller's
/// grants it keeps, and the ones it adds itself, such as macOS's per-user
/// temp dirs.
pub(crate) fn write_roots(policy: &SandboxPolicy) -> Vec<std::path::PathBuf> {
    #[cfg(target_os = "linux")]
    {
        let mut roots = linux::granted_write_paths(policy);
        roots.extend(linux::implicit_write_paths(policy));
        roots
    }

    #[cfg(target_os = "macos")]
    {
        let mut roots = policy.allow_write().to_vec();
        roots.extend(macos::implicit_write_paths(policy));
        roots
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        policy.allow_write().to_vec()
    }
}

/// Whether `--deny` takes write away from `path` even inside a write root.
/// Seatbelt checks the deny first; Landlock can only drop whole grants, which
/// `write_roots` already does.
pub(crate) fn write_denied(policy: &SandboxPolicy, path: &std::path::Path) -> bool {
    #[cfg(target_os = "macos")]
    {
        policy.path_is_denied(path)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (policy, path);
        false
    }
}

pub fn spawn_sandboxed(command: &mut Command, policy: &SandboxPolicy) -> Result<SandboxedChild, SandboxError> {
    #[cfg(target_os = "linux")]
    {
        linux::spawn_sandboxed(command, policy)
    }

    #[cfg(target_os = "macos")]
    {
        macos::spawn_sandboxed(command, policy)
    }

    #[cfg(target_os = "windows")]
    {
        windows::spawn_sandboxed(command, policy)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = command;
        let _ = policy;
        Err(SandboxError::NotSupported)
    }
}
