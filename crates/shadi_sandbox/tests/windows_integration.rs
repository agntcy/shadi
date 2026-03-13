// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

#[cfg(target_os = "windows")]
mod windows_integration {
    use std::process::Command;

    use shadi_sandbox::{spawn_sandboxed, SandboxPolicy};

    #[test]
    fn appcontainer_smoke_test() {
        let enabled = std::env::var("SHADI_WINDOWS_INTEGRATION")
            .map(|value| {
                let normalized = value.trim().to_ascii_lowercase();
                matches!(normalized.as_str(), "1" | "true" | "yes" | "on")
            })
            .unwrap_or(false);

        if !enabled {
            return;
        }

        let policy = SandboxPolicy::new().block_network(false);
        let mut command = Command::new("cmd");
        command.args(["/C", "echo", "shadi"]);

        let mut child = spawn_sandboxed(&mut command, &policy)
            .expect("sandboxed command should start");
        let status = child.wait().expect("wait should succeed");
        assert!(status.success());
    }
}
