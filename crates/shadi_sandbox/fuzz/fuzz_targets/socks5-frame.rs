#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use shadi_sandbox::{parse_socks5_connect, NetAllowlist};

// Parses SOCKS5 greeting + CONNECT from wire bytes and matches the host
// against a fuzzed allowlist. Does not call is_ip_allowed (that does DNS).
// Empty allowlist must stay deny-all. Domain allocations are capped by the
// RFC 1928 1-byte length prefix (255).
fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    let parsed = parse_socks5_connect(&mut cursor);

    let patterns: Vec<String> = data
        .split(|&b| b == b'\n' || b == b',')
        .filter(|chunk| !chunk.is_empty() && chunk.len() <= 255)
        .filter_map(|chunk| std::str::from_utf8(chunk).ok())
        .filter(|s| !s.contains('\0'))
        .take(16)
        .map(|s| s.to_string())
        .collect();

    let empty = NetAllowlist::new(vec![]);
    let allowlist = NetAllowlist::new(patterns.clone());

    if let Ok(request) = parsed {
        if !request.is_resolved_ip {
            assert!(
                request.host.len() <= 255,
                "domain host exceeded SOCKS5 length prefix: {}",
                request.host.len()
            );
        }
        assert!(
            !empty.is_allowed(&request.host),
            "empty allowlist accepted {}",
            request.host
        );
        let _ = allowlist.is_allowed(&request.host);
    }

    for host in patterns.iter().chain(std::iter::once(&"evil.example".to_string())) {
        assert!(
            !empty.is_allowed(host),
            "empty allowlist accepted {host}"
        );
        let _ = allowlist.is_allowed(host);
    }
});
