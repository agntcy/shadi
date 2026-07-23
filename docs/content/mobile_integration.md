# Mobile Integration

**Status: planned, not yet implemented.** There is no Swift/Kotlin binding
layer, FFI crate, or mobile build target in the repository today — the Rust
core is only exposed via the [Python bindings](api_integration.md) and the
`shadictl` CLI.

The intent is to eventually expose the same core (secrets, encrypted memory,
sandboxed execution) to Swift and Kotlin through a thin FFI layer, delegating
credential storage to each platform's OS keystore. If you're interested in
this work, open an issue on [GitHub](https://github.com/agntcy/shadi) or
raise it in the [community](community.md) channels.
