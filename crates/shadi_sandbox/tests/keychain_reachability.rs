// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

#![cfg(all(target_os = "macos", not(feature = "coverage")))]

use std::process::{Command, Stdio};

use shadi_sandbox::{spawn_sandboxed, SandboxPolicy};

const SERVICE: &str = "shadi-keychain-reachability-probe";
const ACCOUNT: &str = "probe";
const SECRET: &str = "sentinel-value";

fn enabled() -> bool {
    std::env::var("SHADI_KEYCHAIN_TESTS").as_deref() == Ok("1")
}

fn add_item() {
    let _ = Command::new("/usr/bin/security")
        .args(["delete-generic-password", "-s", SERVICE, "-a", ACCOUNT])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let status = Command::new("/usr/bin/security")
        .args([
            "add-generic-password", "-s", SERVICE, "-a", ACCOUNT, "-w", SECRET, "-A",
        ])
        .status()
        .expect("add keychain item");
    assert!(status.success(), "could not create the probe item");
}

fn remove_item() {
    let _ = Command::new("/usr/bin/security")
        .args(["delete-generic-password", "-s", SERVICE, "-a", ACCOUNT])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn read_unsandboxed() -> bool {
    Command::new("/usr/bin/security")
        .args(["find-generic-password", "-s", SERVICE, "-a", ACCOUNT, "-w"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn runs_at_all(policy: &SandboxPolicy) -> bool {
    let mut cmd = Command::new("/usr/bin/security");
    cmd.arg("help").stdout(Stdio::null()).stderr(Stdio::null());
    match spawn_sandboxed(&mut cmd, policy) {
        Ok(mut child) => child.wait().is_ok(),
        Err(_) => false,
    }
}

fn read_under(policy: &SandboxPolicy) -> bool {
    let mut cmd = Command::new("/usr/bin/security");
    cmd.args(["find-generic-password", "-s", SERVICE, "-a", ACCOUNT, "-w"])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    match spawn_sandboxed(&mut cmd, policy) {
        Ok(mut child) => child.wait().map(|s| s.success()).unwrap_or(false),
        Err(_) => false,
    }
}

#[test]
fn which_profiles_can_reach_the_keychain() {
    if !enabled() {
        eprintln!("set SHADI_KEYCHAIN_TESTS=1 to run; it writes a probe item to the login keychain");
        return;
    }

    add_item();
    let baseline = read_unsandboxed();
    let compatibility = read_under(&SandboxPolicy::new());
    let minimal_policy = SandboxPolicy::new().use_minimal_platform_profile();
    let minimal = read_under(&minimal_policy);
    let minimal_runs = runs_at_all(&minimal_policy);
    remove_item();

    eprintln!("  unsandboxed:   {baseline}");
    eprintln!("  compatibility: {compatibility}");
    eprintln!("  minimal:       {minimal}");
    eprintln!("  minimal runs the binary at all: {minimal_runs}");

    assert!(baseline, "the probe item must be readable unsandboxed, or the run proves nothing");
    assert!(
        minimal_runs,
        "the binary did not run under minimal, so its failure to read proves nothing"
    );
    assert!(!minimal, "a minimal-profile child read an agent_secrets-style keychain item");
}
