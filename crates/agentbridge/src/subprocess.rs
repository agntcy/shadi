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

use std::collections::HashSet;
use std::io;
use std::process::{Command, Output};
use std::sync::Mutex;

/// Tracks the PIDs of subprocesses for as long as they are running, so they
/// can be killed on demand from anywhere holding a reference to this struct.
///
/// A set rather than one slot: the adapter is shared across concurrent A2A
/// tasks, so a second child would otherwise displace the first, and whichever
/// finished first would clear the slot for the one still running.
#[derive(Default)]
pub struct TrackedSubprocess {
    active_pids: Mutex<HashSet<u32>>,
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
        let pid = child.id();

        if let Ok(mut active) = self.active_pids.lock() {
            active.insert(pid);
        }

        let result = child.wait_with_output();

        if let Ok(mut active) = self.active_pids.lock() {
            active.remove(&pid);
        }

        result
    }

    /// Best-effort: terminate every child currently tracked. A no-op if
    /// nothing is running right now.
    pub fn kill(&self) {
        let pids: Vec<u32> = match self.active_pids.lock() {
            Ok(active) => active.iter().copied().collect(),
            Err(_) => Vec::new(),
        };
        for pid in pids {
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
    use std::sync::Arc;

    /// Exits successfully straight away.
    #[cfg(unix)]
    fn exits_now() -> Command {
        Command::new("true")
    }

    #[cfg(windows)]
    fn exits_now() -> Command {
        let mut cmd = Command::new("cmd");
        cmd.args(["/C", "exit", "0"]);
        cmd
    }

    /// Stays alive long enough to be killed out from under the test.
    #[cfg(unix)]
    fn stays_alive() -> Command {
        let mut cmd = Command::new("sleep");
        cmd.arg("30");
        cmd
    }

    #[cfg(windows)]
    fn stays_alive() -> Command {
        let mut cmd = Command::new("ping");
        cmd.args(["-n", "31", "127.0.0.1"]);
        cmd
    }

    #[test]
    fn output_runs_command_and_clears_pid_after() {
        let tracked = TrackedSubprocess::new();
        let mut cmd = exits_now();
        let output = tracked.output(&mut cmd).expect("spawn should succeed");
        assert!(output.status.success());
        assert!(tracked.active_pids.lock().unwrap().is_empty());
    }

    #[test]
    fn output_surfaces_spawn_failure_without_stranding_a_pid() {
        let tracked = TrackedSubprocess::new();
        let mut cmd = Command::new("agentbridge-no-such-binary");
        assert!(tracked.output(&mut cmd).is_err());
        assert!(tracked.active_pids.lock().unwrap().is_empty());
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
        tracked
            .active_pids
            .lock()
            .expect("fresh tracker is not poisoned")
            .insert(pid);
        tracked.kill();
        let status = child.wait().expect("wait after kill");
        assert!(!status.success());
    }

    #[test]
    fn kill_terminates_every_concurrent_child() {
        // The adapter is shared across concurrent A2A tasks. With one pid slot
        // the second child displaced the first, so shutdown reached only one of
        // them and the other outlived the listener.
        let tracked = TrackedSubprocess::new();
        let mut first = stays_alive().spawn().expect("spawn first child");
        let mut second = stays_alive().spawn().expect("spawn second child");
        {
            let mut active = tracked
                .active_pids
                .lock()
                .expect("fresh tracker is not poisoned");
            active.insert(first.id());
            active.insert(second.id());
        }

        tracked.kill();

        assert!(
            !first.wait().expect("wait on first").success(),
            "first child survived shutdown"
        );
        assert!(
            !second.wait().expect("wait on second").success(),
            "second child survived shutdown"
        );
    }

    #[test]
    fn a_running_child_is_still_tracked_while_another_finishes() {
        // Clearing the slot on completion used to drop the pid of whichever
        // child was still running.
        let tracked = Arc::new(TrackedSubprocess::new());
        let mut long_lived = stays_alive().spawn().expect("spawn long-running child");
        tracked
            .active_pids
            .lock()
            .expect("fresh tracker is not poisoned")
            .insert(long_lived.id());

        let mut quick = exits_now();
        tracked.output(&mut quick).expect("short command runs");

        assert!(
            tracked
                .active_pids
                .lock()
                .expect("not poisoned")
                .contains(&long_lived.id()),
            "a finished child cleared the pid of one still running"
        );
        tracked.kill();
        let _ = long_lived.wait();
    }

    #[test]
    fn a_poisoned_tracker_still_runs_and_still_shuts_down() {
        let tracked = Arc::new(TrackedSubprocess::new());
        let poisoner = Arc::clone(&tracked);
        let _ = std::thread::spawn(move || {
            let _held = poisoner.active_pids.lock().unwrap();
            panic!("poison the tracker's lock");
        })
        .join();
        assert!(
            tracked.active_pids.lock().is_err(),
            "lock should be poisoned"
        );

        // Both paths skip the pid bookkeeping rather than propagating the
        // poison: the command still runs, and shutdown still returns.
        let mut cmd = exits_now();
        let output = tracked.output(&mut cmd).expect("command still runs");
        assert!(output.status.success());
        tracked.kill();
    }
}
