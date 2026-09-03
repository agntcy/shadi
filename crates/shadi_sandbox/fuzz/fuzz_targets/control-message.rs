#![no_main]

use libfuzzer_sys::fuzz_target;
use shadi_sandbox::ControlMessage;

// Mirrors what shadictl's control-socket listener does with each line it
// reads from a connected peer (crates/shadictl/src/policy_watch.rs,
// handle_stream): parse it as JSON into a ControlMessage. The socket is
// owner-only (0o600), but any process running as the same user can write to
// it, so this boundary must reject a malformed or adversarial line rather
// than panic the listener thread out from under a running sandbox.
fuzz_target!(|data: &[u8]| {
    let Ok(line) = std::str::from_utf8(data) else {
        return;
    };
    let _ = serde_json::from_str::<ControlMessage>(line);
});
