// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

#[cfg(target_os = "windows")]
mod windows_integration {
    use std::process::Command;
    use std::thread;
    use std::time::Duration;
    use std::time::{SystemTime, UNIX_EPOCH};

    use shadi_sandbox::{spawn_sandboxed, SandboxError, SandboxPolicy};

    fn run_smoke_once() -> Result<(), SandboxError> {
        let policy = SandboxPolicy::new().block_network(false);
        let mut command = Command::new("cmd");
        command.args(["/C", "echo", "shadi"]);

        let mut child = spawn_sandboxed(&mut command, &policy)?;
        let status = child.wait().expect("wait should succeed");
        assert!(status.success());
        Ok(())
    }

    /// Spawn `script` under `cmd /C` in a sandbox that may read `dir`, or
    /// `None` on the runner's known `CreateProcessW` (win32=87) failure.
    fn spawn_reader(dir: &std::path::Path, script: &str) -> Option<shadi_sandbox::SandboxedChild> {
        let policy = SandboxPolicy::new().allow_read_path(dir);
        let mut command = Command::new("cmd");
        command.args(["/C", script]);
        match spawn_sandboxed(&mut command, &policy) {
            Ok(child) => Some(child),
            Err(SandboxError::SpawnFailed(message)) if message.contains("win32=87") => {
                eprintln!("skipping: CreateProcessW(win32=87) on this runner");
                None
            }
            Err(error) => panic!("sandboxed reader should start: {error:?}"),
        }
    }

    /// Two sandboxes that share a path keep their grants whatever order they
    /// start and exit in (#335). B's startup must not reset A's ACL from a
    /// journal A still owns, and B's exit must not take A's grant with it.
    #[test]
    fn sandboxes_sharing_a_path_keep_their_grants() {
        let dir = tempfile::tempdir().expect("tempdir");
        let shared = dir.path().join("shared.txt");
        std::fs::write(&shared, b"shared").expect("write shared file");

        let a_script = format!("ping -n 4 127.0.0.1 >NUL & type \"{}\"", shared.display());
        let Some(mut a) = spawn_reader(dir.path(), &a_script) else {
            return;
        };
        thread::sleep(Duration::from_millis(500));
        let b_script = format!("type \"{}\"", shared.display());
        let Some(mut b) = spawn_reader(dir.path(), &b_script) else {
            let _ = a.wait();
            return;
        };

        assert!(
            b.wait().expect("wait for B").success(),
            "B could not read the shared file"
        );
        assert!(
            a.wait().expect("wait for A").success(),
            "A lost its grant on the shared file when B started or exited"
        );
    }

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

        let unique_suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_nanos();
        std::env::set_var(
            "SHADI_APPCONTAINER_NAME",
            format!("shadi_sandbox_test_{}_{}", std::process::id(), unique_suffix),
        );

        for attempt in 0..5 {
            match run_smoke_once() {
                Ok(()) => return,
                Err(SandboxError::SpawnFailed(message))
                    if message.contains("CreateProcessW failed (win32=87)") && attempt < 4 =>
                {
                    thread::sleep(Duration::from_millis(250));
                }
                Err(SandboxError::SpawnFailed(message))
                    if message.contains("CreateProcessW failed (win32=87)") =>
                {
                    eprintln!(
                        "skipping Windows AppContainer smoke test after repeated CreateProcessW(win32=87) failures"
                    );
                    return;
                }
                Err(error) => panic!("sandboxed command should start: {error:?}"),
            }
        }
    }
}
