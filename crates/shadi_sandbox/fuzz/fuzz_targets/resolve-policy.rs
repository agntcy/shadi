#![no_main]

use std::path::PathBuf;
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use shadi_sandbox::{describe_policy, resolve_policy, PolicyFileValues, PolicyOverrides};

// resolve_policy layers profile defaults, a policy file and per-run overrides.
// The two path sources have opposite contracts: file-policy paths are lenient
// so a cross-platform preset resolves on every OS, while override paths name
// what this specific run asked for, so a missing one is an error.
//
// Paths come from a fixture directory rather than from the fuzzed bytes:
// canonicalisation reads the real filesystem, and arbitrary absolute paths
// would make a finding depend on whatever happens to exist on the host.
fn fixture() -> &'static PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = std::env::temp_dir().join("shadi-fuzz-resolve-policy");
        let _ = std::fs::create_dir_all(dir.join("present"));
        dir
    })
}

fuzz_target!(|data: &[u8]| {
    let dir = fixture();
    let present = dir.join("present");
    if !present.exists() {
        return; // fixture unavailable; nothing to assert against
    }
    let absent = dir.join("no-such-entry-for-fuzzing");

    let flags = data.first().copied().unwrap_or(0);
    let override_has_missing = flags & 1 != 0;

    // Strings the file policy layer sees, including tilde forms so expansion
    // is exercised. None of these may turn into an error.
    let file_paths: Vec<String> = data
        .split(|&b| b == b'\n')
        .filter(|c| !c.is_empty() && c.len() <= 512)
        .filter_map(|c| std::str::from_utf8(c).ok())
        .map(|s| s.to_string())
        .take(32)
        .chain([
            present.to_string_lossy().into_owned(),
            "~/definitely-not-here".to_string(),
            "~".to_string(),
            "/nonexistent/for/fuzzing".to_string(),
        ])
        .collect();

    let file_policy = PolicyFileValues {
        allow: file_paths.clone(),
        read: file_paths.clone(),
        write: file_paths.clone(),
        net_block: match flags & 6 {
            0 => None,
            2 => Some(true),
            _ => Some(false),
        },
        net_allow: file_paths.iter().take(4).cloned().collect(),
        allow_command: file_paths.iter().take(4).cloned().collect(),
        block_command: file_paths.iter().take(4).cloned().collect(),
        deny: file_paths.clone(),
    };

    let mut override_paths: Vec<PathBuf> = vec![present.clone()];
    if override_has_missing {
        override_paths.push(absent.clone());
    }

    let overrides = PolicyOverrides {
        profile: None,
        allow: override_paths.clone(),
        read: override_paths.clone(),
        write: override_paths.clone(),
        net_block: flags & 8 != 0,
        net_allow: file_policy.net_allow.clone(),
        allow_command: file_policy.allow_command.clone(),
        deny: vec![present.clone()],
    };

    match resolve_policy(&overrides, &file_policy) {
        Ok(resolved) => {
            assert!(
                !override_has_missing,
                "a missing override path resolved instead of erroring"
            );
            let described =
                describe_policy(&resolved.policy, &resolved.blocked, &resolved.allow);
            // remember_deny always records the raw path, and the canonical one
            // too when it resolves, so a non-empty deny list cannot vanish.
            assert!(
                !described.deny.is_empty(),
                "deny paths did not reach the description"
            );
            // deny records the raw path beside the canonical one, so a tilde
            // surviving there is the contract rather than a bug; read, write
            // and allow are canonicalised and cannot keep one.
            for path in described
                .read
                .iter()
                .chain(described.write.iter())
                .chain(described.allow.iter())
            {
                // Only a leading home reference should have been rewritten;
                // `~user` is not one and is left alone on purpose.
                assert!(
                    path != "~" && !path.starts_with("~/"),
                    "an unexpanded home reference reached the resolved policy: {path}"
                );
            }
        }
        Err(message) => {
            assert!(
                override_has_missing,
                "only a missing override path may fail, got: {message}"
            );
        }
    }
});
