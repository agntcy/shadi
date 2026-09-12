# Fuzz targets

Two targets, each mirroring a real boundary in `shadi_sandbox` rather than
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

## Running

```sh
cargo install cargo-fuzz
rustup toolchain install nightly
cargo +nightly fuzz run control-message
cargo +nightly fuzz run session-name
cargo +nightly fuzz run policy-patch
```

Both ran clean for 30 seconds (~7.3-7.8M executions each) with no crash
before this was committed.
