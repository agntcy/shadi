#![no_main]

use std::path::PathBuf;

use libfuzzer_sys::fuzz_target;
use shadi_sandbox::{SandboxError, SandboxPolicy};

// Builds a Seatbelt profile from fuzzed paths. sandbox_init is not called;
// the harness checks that generated S-expressions stay valid UTF-8 without
// NUL, and that a quote in a path is escaped.
fuzz_target!(|data: &[u8]| {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = data;
        return;
    }

    #[cfg(target_os = "macos")]
    {
        let mut policy = SandboxPolicy::new();
        for chunk in data.split(|&b| b == b'\n').take(16) {
            if chunk.is_empty() || chunk.len() > 4096 {
                continue;
            }
            let Ok(s) = std::str::from_utf8(chunk) else {
                continue;
            };
            if s.contains('\0') {
                continue;
            }
            let path = PathBuf::from(s);
            policy = policy.allow_read_path(&path).allow_write_path(&path);
        }

        match shadi_sandbox::seatbelt_profile_text(&policy) {
            Ok(profile) => {
                assert!(
                    !profile.as_bytes().contains(&0),
                    "Seatbelt profile contained a NUL"
                );
                for path in policy.allow_read() {
                    let Some(raw) = path.to_str() else {
                        continue;
                    };
                    if raw.contains('"') {
                        assert!(
                            profile.contains("\\\""),
                            "path {raw:?} contained a quote that was not escaped"
                        );
                    }
                }
            }
            Err(SandboxError::InvalidConfig) => {}
            Err(err) => panic!("unexpected seatbelt error: {err}"),
        }
    }
});
