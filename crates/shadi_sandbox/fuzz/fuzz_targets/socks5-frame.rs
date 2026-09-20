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

        // Matching is documented as case-insensitive, so the same host in a
        // different case cannot produce a different verdict. Both the host and
        // the patterns are folded, so flipping either side must agree.
        let flipped: String = host
            .chars()
            .map(|c| {
                if c.is_ascii_lowercase() {
                    c.to_ascii_uppercase()
                } else {
                    c.to_ascii_lowercase()
                }
            })
            .collect();
        assert_eq!(
            allowlist.is_allowed(host),
            allowlist.is_allowed(&flipped),
            "case changed the verdict for {host:?} vs {flipped:?}"
        );
    }

    // is_ip_allowed resolves any allowlisted hostname to compare against the
    // incoming IP, so the patterns here are restricted to the shapes it never
    // resolves — literal IPs, `*`, and `*.` wildcards — to keep the target off
    // the network. The resolving branch needs a stubbed resolver and is not
    // covered here.
    let ip_safe: Vec<String> = patterns
        .iter()
        .filter(|p| {
            let t = p.trim();
            t == "*" || t.starts_with("*.") || t.parse::<std::net::IpAddr>().is_ok()
        })
        .cloned()
        .collect();
    let ip_list = NetAllowlist::new(ip_safe.clone());
    let wide_open = ip_safe.iter().any(|p| p.trim() == "*");

    for candidate in ["127.0.0.1", "::1", "10.0.0.1", "not-an-ip"] {
        assert!(
            !empty.is_ip_allowed(candidate),
            "empty allowlist accepted ip {candidate}"
        );
        let verdict = ip_list.is_ip_allowed(candidate);
        if wide_open {
            // `*` short-circuits before the IP is parsed, so even a
            // non-address is allowed by it.
            assert!(verdict, "`*` did not allow {candidate}");
        } else if candidate == "not-an-ip" && !ip_safe.iter().any(|p| p.trim() == candidate) {
            assert!(
                !verdict,
                "an unparsable address was allowed without a matching pattern"
            );
        }
    }
});
