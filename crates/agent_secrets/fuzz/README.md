# Fuzz targets

- **`secret-mapping`** — feeds arbitrary `NAME=VALUE` arguments to
  `parse_name_mappings`, which backs shadictl's repeated `--trusted-secret`
  and `--trusted-secret-fd-env` flags. Each accepted argument must land in
  the map under its own name, and a duplicate name must be rejected rather
  than resolved to the last value.

## Running

```sh
cargo install cargo-fuzz
rustup toolchain install nightly
cargo +nightly fuzz run secret-mapping
```

With the checked-in seeds, bounded as CI runs it:

```sh
mkdir -p corpus/secret-mapping
cargo +nightly fuzz run secret-mapping corpus/secret-mapping seeds/secret-mapping \
  -- -max_total_time=60 -rss_limit_mb=2048 -print_final_stats=1
```
