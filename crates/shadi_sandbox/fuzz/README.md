# Fuzz targets

Each target mirrors a real boundary in `shadi_sandbox` rather than
fuzzing for its own sake:

- **`control-message`** — parses arbitrary bytes as JSON into a
  `ControlMessage`, the same operation `shadictl`'s control-socket listener
  (`crates/shadictl/src/policy_watch.rs`, `handle_stream`) performs on every
  line a connected peer sends. The socket is owner-only (`0o600`), but any
  process running as the same user can write to it, so this parse must
  reject malformed input rather than panic the listener thread out from
  under a running sandbox.

- **`session-name`** — checks that `sanitize_session_name` and
  `named_socket_path` hold their safety invariant for every input, not just
  the cases in the unit tests: a session name can come from a caller (the
  desktop panel's launch form, `--session <name>`), and the only thing
  standing between an arbitrary name and a path-traversal escape out of
  `socket_dir()` is that sanitizer.

- **`policy-patch`** — applies a deserialized `ControlMessage::Patch` to
  `apply_policy_patch` (the same path `handle_patch` uses after parse).
  Asserts `extract_host` never leaks a `://` scheme and that filesystem
  staging lengths match the patch. The control socket also rejects any
  line larger than `CONTROL_LINE_MAX_BYTES` (64 KiB).

- **`seatbelt-profile`** — builds a Seatbelt profile from fuzzed paths
  (macOS only) and asserts the generated S-expression has no NUL and
  escapes quotes. `sandbox_init` is not called.

- **`socks5-frame`** — parses SOCKS5 greeting + CONNECT (`parse_socks5_connect`)
  and checks `NetAllowlist::is_allowed`. Empty allowlist stays deny-all.
  Domain allocations stay within the RFC 1928 255-byte prefix.
  `is_ip_allowed` is not called (it does real DNS).

- **`resolve-policy`** — layers `PolicyFileValues` over `PolicyOverrides` and
  calls `resolve_policy` / `describe_policy`. File-policy paths are lenient and
  must never fail; override paths name what the run asked for, so a missing one
  must be an error. Paths come from a fixture directory, not from the fuzzed
  bytes: canonicalisation reads the real filesystem and arbitrary absolute
  paths would make a finding depend on the host.

- **`session-socket`** — `resolve_session_socket` takes either a session name
  or an explicit socket path. A path-like value is used verbatim, which is the
  caller naming a socket; anything else is a name and must land directly in
  `socket_dir()` under a sanitised filename. The target asserts the name branch
  cannot add a path component or carry an unsanitised character.

## Running

```sh
cargo install cargo-fuzz
rustup toolchain install nightly
cargo +nightly fuzz run control-message
cargo +nightly fuzz run session-name
cargo +nightly fuzz run policy-patch
cargo +nightly fuzz run seatbelt-profile
cargo +nightly fuzz run socks5-frame
cargo +nightly fuzz run resolve-policy
cargo +nightly fuzz run session-socket
```

Pass the checked-in seeds so a run starts from legal input rather than noise,
and bound it the way CI does:

```sh
mkdir -p corpus/socks5-frame
cargo +nightly fuzz run socks5-frame corpus/socks5-frame seeds/socks5-frame \
  -- -max_total_time=60 -rss_limit_mb=2048 -print_final_stats=1
```

`seeds/` is committed and read-only to the fuzzer; `corpus/` is the growing
working set and is gitignored.

`fuzz.yml` runs every target on each pull request touching this crate, 60
seconds apiece, and five minutes apiece on the nightly schedule. A crashing
input is uploaded as a build artifact. `seatbelt-profile` runs on macOS there:
the profile builder is behind `cfg(target_os = "macos")` and the target returns
immediately anywhere else.

The original `control-message` and `session-name` targets ran clean for
30 seconds (~7.3-7.8M executions each) with no crash before they were
committed.
