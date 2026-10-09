#![no_main]

use libfuzzer_sys::fuzz_target;
use shadi_sandbox::{parse_http_proxy_request, NetAllowlist};

// Parses an HTTP proxy request head (CONNECT or an absolute URI). A parsed
// destination is a bare host the empty allowlist denies, and a forwarded head
// is one request that closes the connection and carries no proxy credentials
// or second Host header.
fuzz_target!(|data: &[u8]| {
    let Ok(request) = parse_http_proxy_request(data) else {
        return;
    };
    assert!(!request.host.is_empty(), "empty host from {data:?}");
    assert!(
        !request.host.contains(['/', '@', ' ', '\r', '\n']),
        "host {:?} is not a bare host",
        request.host
    );
    assert!(!NetAllowlist::new(vec![]).is_allowed(&request.host, request.port));

    let Some(forward) = request.forward else {
        return;
    };
    let forward = String::from_utf8(forward).expect("forwarded head is UTF-8");
    assert!(
        forward.ends_with("\r\nConnection: close\r\n\r\n"),
        "{forward:?}"
    );
    let header_names: Vec<String> = forward
        .trim_end_matches("\r\n\r\n")
        .split("\r\n")
        .skip(1)
        .map(|line| line.split(':').next().unwrap_or("").to_ascii_lowercase())
        .collect();
    assert_eq!(
        header_names.iter().filter(|n| *n == "host").count(),
        1,
        "{forward:?}"
    );
    assert_eq!(
        header_names.iter().filter(|n| *n == "connection").count(),
        1,
        "{forward:?}"
    );
    assert!(
        !header_names.iter().any(|n| n.starts_with("proxy-")),
        "proxy header forwarded: {forward:?}"
    );
});
