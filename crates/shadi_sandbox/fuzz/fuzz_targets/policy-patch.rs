#![no_main]

use libfuzzer_sys::fuzz_target;
use shadi_sandbox::{
    apply_policy_patch, extract_host, ControlMessage, PatchAxisStatus, PatchState,
    CONTROL_LINE_MAX_BYTES,
};

// Mirrors handle_patch after the control socket has already accepted a line.
// Same-UID peers can write that socket, so apply_policy_patch must not panic
// and must not leak a URL scheme into the live allowlist.
fuzz_target!(|data: &[u8]| {
    if data.len() > CONTROL_LINE_MAX_BYTES {
        return;
    }
    let Ok(line) = std::str::from_utf8(data) else {
        return;
    };

    for dest in line.split(|c: char| c.is_ascii_whitespace() || c == ',') {
        if dest.is_empty() {
            continue;
        }
        let host = extract_host(dest);
        assert!(
            !host.contains("://"),
            "extract_host({dest:?}) = {host:?} still contains a scheme"
        );
    }

    let Ok(msg) = serde_json::from_str::<ControlMessage>(line) else {
        return;
    };
    let ControlMessage::Patch(patch) = msg else {
        return;
    };

    let mut without_proxy = PatchState::default();
    let result = apply_policy_patch(&mut without_proxy, &patch);
    if !patch.add_read.is_empty() || !patch.add_write.is_empty() || !patch.add_allow.is_empty() {
        assert_eq!(without_proxy.staged_read.len(), patch.add_read.len());
        assert_eq!(without_proxy.staged_write.len(), patch.add_write.len());
        assert_eq!(without_proxy.staged_allow.len(), patch.add_allow.len());
        assert_eq!(result.filesystem, PatchAxisStatus::PendingRestart);
    }
    if !patch.add_net_allow.is_empty() || !patch.remove_net_allow.is_empty() {
        assert_eq!(result.network, PatchAxisStatus::Rejected);
        assert!(without_proxy.net_allow.is_empty());
    }
    for host in &without_proxy.net_allow {
        assert!(!host.contains("://"), "net_allow leaked scheme: {host}");
    }

    let mut with_proxy = PatchState {
        has_live_proxy: true,
        ..Default::default()
    };
    let _ = apply_policy_patch(&mut with_proxy, &patch);
    for host in &with_proxy.net_allow {
        assert!(!host.contains("://"), "proxy net_allow leaked scheme: {host}");
    }
    assert_eq!(with_proxy.staged_read.len(), without_proxy.staged_read.len());
});
