// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Shared subprocess-tracking helper for `CliAdapter` implementations.
//!
//! Every adapter that shells out to a CLI tool via `std::process::Command`
//! (Claude Code, Copilot, Codex, ...) needs the same thing: know the PID of
//! whatever child is currently running so `CliAdapter::kill_in_flight` can
//! reach it during shutdown, instead of leaving it orphaned when the
//! listener process exits out from under it. `TrackedSubprocess` is that
//! logic, written once, so each adapter wires it in with one field and a
//! one-line `kill_in_flight` override instead of duplicating PID-tracking
//! per adapter.

use std::io;
use std::process::{Command, Output};
use std::sync::Mutex;

/// Tracks the PID of a subprocess for as long as it's running, so it can be
/// killed on demand from anywhere holding a reference to this struct.
#[derive(Default)]
pub struct TrackedSubprocess {
    active_pid: Mutex<Option<u32>>,
}

impl TrackedSubprocess {
    pub fn new() -> Self {
        Self::default()
    }

    /// Spawn `cmd`, remember its PID for the duration of the call, run it to
    /// completion, and return its output — same shape as `Command::output()`,
    /// but with the child's PID reachable via `kill()` while it's running.
    pub fn output(&self, cmd: &mut Command) -> io::Result<Output> {
        let child = cmd.spawn()?;

        if let Ok(mut active) = self.active_pid.lock() {
            *active = Some(child.id());
        }

        let result = child.wait_with_output();

        if let Ok(mut active) = self.active_pid.lock() {
            *active = None;
        }

        result
    }

    /// Best-effort: terminate whatever child is currently tracked, if any. A
    /// no-op if nothing is running right now.
    pub fn kill(&self) {
        let pid = match self.active_pid.lock() {
            Ok(active) => *active,
            Err(_) => None,
        };
        if let Some(pid) = pid {
            terminate(pid);
        }
    }
}

/// SIGTERM, so the child still gets to run its own shutdown path.
#[cfg(unix)]
fn terminate(pid: u32) {
    // SAFETY: `pid` is a plain integer recorded from `Child::id()` moments
    // ago; passing it to `kill(2)` cannot violate memory safety even if the
    // process has since exited (that just makes the call a harmless no-op,
    // reported as ESRCH).
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGTERM);
    }
}

/// Windows has no signals reachable from another process, so the equivalent
/// is `TerminateProcess` — abrupt, with no shutdown path for the child.
#[cfg(windows)]
fn terminate(pid: u32) {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

    // SAFETY: `OpenProcess` returns null rather than a bogus handle when the
    // process has already exited, which is what the check below covers; the
    // handle is used only while open and closed exactly once.
    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if !handle.is_null() {
            TerminateProcess(handle, 1);
            CloseHandle(handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exits successfully straight away.
    fn exits_now() -> Command {
        if cfg!(windows) {
            let mut cmd = Command::new("cmd");
            cmd.args(["/C", "exit", "0"]);
            cmd
        } else {
            Command::new("true")
        }
    }

    /// Stays alive long enough to be killed out from under the test.
    fn stays_alive() -> Command {
        if cfg!(windows) {
            let mut cmd = Command::new("ping");
            cmd.args(["-n", "31", "127.0.0.1"]);
            cmd
        } else {
            let mut cmd = Command::new("sleep");
            cmd.arg("30");
            cmd
        }
    }

    #[test]
    fn output_runs_command_and_clears_pid_after() {
        let tracked = TrackedSubprocess::new();
        let mut cmd = exits_now();
        let output = tracked.output(&mut cmd).expect("spawn should succeed");
        assert!(output.status.success());
        assert!(tracked.active_pid.lock().unwrap().is_none());
    }

    #[test]
    fn kill_on_idle_tracker_is_a_harmless_no_op() {
        let tracked = TrackedSubprocess::new();
        tracked.kill(); // must not panic
    }

    #[test]
    fn kill_terminates_a_running_child() {
        let tracked = TrackedSubprocess::new();
        let mut child = stays_alive().spawn().expect("spawn long-running child");
        let pid = child.id();
        if let Ok(mut active) = tracked.active_pid.lock() {
            *active = Some(pid);
        }
        tracked.kill();
        let status = child.wait().expect("wait after kill");
        assert!(!status.success());
    }
}
