# Fuzz targets

- **`stdio-response`** — feeds arbitrary bytes to `read_response`, the reader
  behind every `GenericStdioAdapter` call. A subprocess that emits binary,
  dies mid-line, or never sends a newline must produce an error rather than a
  panic, and must not be buffered past `STDIO_LINE_MAX_BYTES` (64 KiB).
- **`member-spec`** — feeds arbitrary strings to `parse_member_spec`, which
  backs `--members` and `/slim invite-from`. Only `skill:`, `did:` and
  `explicit:` specs may parse, and an accepted `explicit:` spec may not yield
  a member with an empty name or DID.

## Running

```sh
cargo install cargo-fuzz
rustup toolchain install nightly
cargo +nightly fuzz run stdio-response
```

With the checked-in seeds, bounded as CI runs it:

```sh
mkdir -p corpus/member-spec
cargo +nightly fuzz run member-spec corpus/member-spec seeds/member-spec \
  -- -max_total_time=60 -rss_limit_mb=2048 -print_final_stats=1
```

`Cargo.lock` pins `agntcy-slim-persistence` to 0.1.0. 0.1.1 moved to
`mls-rs-core` 0.27 while `agntcy-slim-mls` 0.3.10 still builds against 0.26,
and the two copies of `GroupStateStorage` do not unify.
