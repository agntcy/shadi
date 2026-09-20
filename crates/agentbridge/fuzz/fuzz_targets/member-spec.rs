#![no_main]

use libfuzzer_sys::fuzz_target;

use agentbridge::member_source::{parse_member_spec, DirLookupOptions};

// `--members <spec>` reaches this parser straight from the command line and
// from `/slim invite-from` in the shell, so the string is operator-supplied
// and frequently pasted. Parsing must reject anything it does not fully
// understand: a spec that survives becomes a group member, and an empty name
// or DID would put an unaddressable entry into the invite list.
fuzz_target!(|data: &[u8]| {
    let Ok(spec) = std::str::from_utf8(data) else {
        return;
    };

    let dir = DirLookupOptions {
        server_addr: "127.0.0.1:0".to_string(),
        gh_token: None,
        limit: 1,
    };

    let Ok(source) = parse_member_spec(spec, &dir) else {
        return;
    };

    let prefix = ["skill:", "did:", "explicit:"]
        .into_iter()
        .find(|p| spec.starts_with(p));
    assert!(
        prefix.is_some(),
        "parse_member_spec accepted {spec:?}, which names none of the three source kinds"
    );

    // Only ExplicitListSource::resolve is pure; the directory-backed sources
    // would shell out to dirctl, so they stay unresolved here.
    if prefix == Some("explicit:") {
        let members = source
            .resolve()
            .expect("an explicit list resolves to the entries it parsed");
        for member in members {
            assert!(
                !member.name.is_empty(),
                "explicit spec {spec:?} produced a member with no name"
            );
            assert!(
                !member.did.is_empty(),
                "explicit spec {spec:?} produced a member with no DID"
            );
        }
    }
});
