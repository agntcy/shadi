// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

#[cfg(target_os = "windows")]
mod windows_integration {
    use std::process::Command;

    use shadi_sandbox::{spawn_sandboxed, SandboxPolicy};

    #[test]
    fn appcontainer_smoke_test() {
        if std::env::var("SHADI_WINDOWS_INTEGRATION").is_err() {
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
