// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::process::Command;

use crate::{SandboxError, SandboxPolicy, SandboxedChild};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

pub fn spawn_sandboxed(command: &mut Command, policy: &SandboxPolicy) -> Result<SandboxedChild, SandboxError> {
    #[cfg(target_os = "macos")]
    {
        macos::spawn_sandboxed(command, policy)
    }

    #[cfg(target_os = "windows")]
    {
        windows::spawn_sandboxed(command, policy)
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = command;
        let _ = policy;
        Err(SandboxError::NotSupported)
    }
}
