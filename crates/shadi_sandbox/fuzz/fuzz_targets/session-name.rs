#![no_main]

use libfuzzer_sys::fuzz_target;
use shadi_sandbox::control;

// A session name can come from a caller-supplied string — the desktop panel's
// launch form, or `--session <name>` on the command line. named_socket_path
// turns it into a filesystem path underneath socket_dir(), and the only
// thing standing between an arbitrary name and a path-traversal escape is
// sanitize_session_name's character filter. This checks that invariant
// holds for every input, not just the ones in the unit tests.
fuzz_target!(|data: &[u8]| {
    let Ok(name) = std::str::from_utf8(data) else {
        return;
    };

    let slug = control::sanitize_session_name(name);
    assert!(
        slug.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "sanitize_session_name({name:?}) = {slug:?}, which has a character outside [A-Za-z0-9_-]"
    );
    assert!(
        slug.chars().count() <= 48,
        "sanitize_session_name({name:?}) = {slug:?}, longer than the 48-char cap"
    );

    let path = control::named_socket_path(name);
    assert_eq!(
        path.parent(),
        Some(control::socket_dir().as_path()),
        "named_socket_path({name:?}) = {path:?}, which escaped socket_dir()"
    );
});
