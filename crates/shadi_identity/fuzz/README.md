# Fuzz targets

- **`did-proof`** — feeds arbitrary bytes to `looks_like_did_proof` and
  `unwrap_signed_message`. Malformed envelopes must return an error.
  Payloads above `DID_PROOF_PAYLOAD_MAX_BYTES` (1 MiB) and header lines
  above `DID_PROOF_HEADER_MAX_BYTES` (1 KiB) are rejected.

## Running

```sh
cargo install cargo-fuzz
rustup toolchain install nightly
cargo +nightly fuzz run did-proof
```

With the checked-in seeds, bounded as CI runs it:

```sh
mkdir -p corpus/did-proof
cargo +nightly fuzz run did-proof corpus/did-proof seeds/did-proof \
  -- -max_total_time=60 -rss_limit_mb=2048 -print_final_stats=1
```

`seeds/signed-envelope.bin` is a real envelope from `wrap_signed_message`, so
the fuzzer mutates around a valid signature rather than hunting for one.
