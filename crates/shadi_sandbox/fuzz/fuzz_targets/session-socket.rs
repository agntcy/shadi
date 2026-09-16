#![no_main]

use std::path::PathBuf;

use libfuzzer_sys::fuzz_target;
use shadi_sandbox::control;

// resolve_session_socket takes either a session name or a socket path from a
// caller — `--session <name>`, or a path from the desktop panel. A value that
// looks like a path is used verbatim, which is the caller naming a socket
// explicitly; anything else is a name and must land inside socket_dir() under
// a sanitised filename. The name branch is the one that must not be able to
// escape: `..`, a separator or a NUL in a session name cannot become a path.
fuzz_target!(|data: &[u8]| {
    let Ok(raw) = std::str::from_utf8(data) else {
        return;
    };

    let resolved = control::resolve_session_socket(raw);

    // The verbatim branch: the caller supplied a path, and it is theirs.
    if resolved == PathBuf::from(raw) {
        return;
    }

    // Otherwise this went through the name branch, so it must sit directly in
    // the socket directory.
    assert_eq!(
        resolved.parent(),
        Some(control::socket_dir().as_path()),
        "a session name resolved outside the socket directory: {resolved:?}"
    );

    let file = resolved
        .file_name()
        .and_then(|f| f.to_str())
        .expect("named socket has a UTF-8 file name");
    let inner = file
        .strip_prefix("shadi-ctl-")
        .and_then(|f| f.strip_suffix(".sock"))
        .unwrap_or_else(|| panic!("unexpected socket file name {file:?}"));

    // sanitize_session_name's contract: only these characters survive, so no
    // separator, dot or NUL can reach the path, and `..` cannot be spelled.
    assert!(
        inner
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "unsanitised characters reached the socket name: {inner:?}"
    );
    assert!(
        inner.chars().count() <= 48,
        "socket name was not truncated: {} chars",
        inner.chars().count()
    );
    assert_eq!(
        resolved.components().count(),
        control::socket_dir().components().count() + 1,
        "a session name added a path component: {resolved:?}"
    );
});
