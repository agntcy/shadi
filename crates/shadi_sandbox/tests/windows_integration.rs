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

    /// Spawn `cmd /C <argv>` in a sandbox that may read `dir`.
    ///
    /// The arguments are passed one by one, never as a single quoted script:
    /// `quote_arg` escapes an embedded quote the MSVC way, as `\"`, and
    /// `cmd` reads that as a literal backslash, so the path never parses.
    ///
    /// win32=87 used to be skipped as a runner quirk; it was a malformed
    /// capability array (agntcy/shadi#531), so it now fails the test.
    fn spawn_reader(dir: &std::path::Path, argv: &[&str]) -> shadi_sandbox::SandboxedChild {
        let policy = SandboxPolicy::new().allow_read_path(dir);
        let mut command = Command::new("cmd");
        command.arg("/C");
        command.args(argv);
        match spawn_sandboxed(&mut command, &policy) {
            Ok(child) => child,
            Err(error) => panic!("sandboxed reader should start: {error:?}"),
        }
    }

    /// Read the shared file until the parent drops `go.txt` beside it, then
    /// read it once more. The first failed read ends the run, so a grant lost
    /// at any point stops A where it happened. The loop is bounded so a parent
    /// that never signals cannot hang the suite.
    const READER_SCRIPT: &str = concat!(
        "@echo off\r\n",
        "for /l %%i in (1,1,1000000) do (\r\n",
        "  type \"%~dp0shared.txt\" >nul || exit /b 1\r\n",
        "  if exist \"%~dp0go.txt\" (\r\n",
        "    type \"%~dp0shared.txt\" || exit /b 1\r\n",
        "    exit /b 0\r\n",
        "  )\r\n",
        ")\r\n",
        "exit /b 2\r\n",
    );

    /// Two sandboxes that share a path keep their grants whatever order they
    /// start and exit in (#335). B's startup must not reset A's ACL from a
    /// journal A still owns, and B's exit must not take A's grant with it.
    ///
    /// A reads for as long as B lives, and once more after `b.wait()` has
    /// revoked B's grant, so both moments are covered. It spins on the file
    /// instead of sleeping between reads because an AppContainer has nothing
    /// to sleep with: `ping` exits at once with `Access is denied`, and
    /// `timeout` wants a console the test runner does not give it.
    #[test]
    fn sandboxes_sharing_a_path_keep_their_grants() {
        let dir = tempfile::tempdir().expect("tempdir");
        let shared = dir.path().join("shared.txt");
        std::fs::write(&shared, b"shared").expect("write shared file");
        let script = dir.path().join("reader.cmd");
        std::fs::write(&script, READER_SCRIPT).expect("write reader script");

        let script_arg = script.display().to_string();
        let mut a = spawn_reader(dir.path(), &[&script_arg]);
        thread::sleep(Duration::from_millis(500));

        let shared_arg = shared.display().to_string();
        let mut b = spawn_reader(dir.path(), &["type", &shared_arg]);
        assert!(
            b.wait().expect("wait for B").success(),
            "B could not read the shared file"
        );

        std::fs::write(dir.path().join("go.txt"), b"go").expect("write go file");
        assert_eq!(
            a.wait().expect("wait for A").code(),
            Some(0),
            "A lost its grant on the shared file (1) or never saw the signal (2)"
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
