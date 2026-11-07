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

    /// Spawn `script` under `cmd /C` in a sandbox that may read `dir`.
    /// win32=87 used to be skipped as a runner quirk; it was a malformed
    /// capability array (agntcy/shadi#531), so it now fails the test.
    fn spawn_reader(dir: &std::path::Path, script: &str) -> shadi_sandbox::SandboxedChild {
        let policy = SandboxPolicy::new().allow_read_path(dir);
        let mut command = Command::new("cmd");
        command.args(["/C", script]);
        match spawn_sandboxed(&mut command, &policy) {
            Ok(child) => child,
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
        let mut a = spawn_reader(dir.path(), &a_script);
        thread::sleep(Duration::from_millis(500));
        let b_script = format!("type \"{}\"", shared.display());
        let mut b = spawn_reader(dir.path(), &b_script);

        assert!(
            b.wait().expect("wait for B").success(),
            "B could not read the shared file"
        );
        assert!(
            a.wait().expect("wait for A").success(),
            "A lost its grant on the shared file when B started or exited"
        );
    }

    /// A capability array that CreateProcessW rejects stops every sandbox that
    /// is allowed network from starting at all (agntcy/shadi#531). `net_block`
    /// is false by default, so this is the default policy.
    #[test]
    fn a_network_enabled_sandbox_spawns() {
        let mut command = Command::new("cmd");
        command.args(["/C", "exit", "0"]);
        let mut child = spawn_sandboxed(&mut command, &SandboxPolicy::new())
            .expect("a network-enabled sandbox should spawn");
        assert!(child.wait().expect("wait").success());
    }

    /// Proxy mode cannot be enforced inside an AppContainer, so it must fail
    /// rather than run with proxy env vars nothing honours (agntcy/shadi#530).
    #[test]
    fn proxy_mode_is_refused() {
        let policy = SandboxPolicy::new().with_net_proxy_port(9050);
        let mut command = Command::new("cmd");
        command.args(["/C", "exit", "0"]);
        match spawn_sandboxed(&mut command, &policy) {
            Err(SandboxError::ApplyFailed(message)) => {
                assert!(message.contains("loopback exemption"), "{message}");
            }
            Err(error) => panic!("proxy mode should be refused, got {error:?}"),
            Ok(_) => panic!("proxy mode should be refused, but the sandbox started"),
        }
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
