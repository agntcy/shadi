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
