#![no_main]

use libfuzzer_sys::fuzz_target;

use agentbridge::adapters::generic_stdio::{read_response, STDIO_LINE_MAX_BYTES};

// Every byte here comes from a subprocess agentbridge spawned but does not
// control: `GenericStdioAdapter::spawn` runs whatever binary the operator
// named, and its stdout is parsed as newline-delimited JSON. A harness that
// crashes mid-write, emits binary, or never sends a newline at all must
// produce an error rather than panic the caller or grow the read buffer
// without bound.
fuzz_target!(|data: &[u8]| {
    let mut reader = data;
    let Ok(response) = read_response(&mut reader) else {
        return;
    };

    // A decoded response came from a line the cap admitted, so the bytes it
    // consumed are bounded even though the subprocess chose them.
    let consumed = data.len() - reader.len();
    assert!(
        consumed <= STDIO_LINE_MAX_BYTES,
        "read_response accepted {consumed} bytes, past the {STDIO_LINE_MAX_BYTES}-byte cap"
    );

    // `ok: false` is the protocol's error carrier; the adapter reads `error`
    // only on that branch, so it must stay optional rather than panic.
    if !response.ok {
        let _ = response.error.unwrap_or_default();
    }
});
