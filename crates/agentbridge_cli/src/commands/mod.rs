pub mod coordinate;
pub mod delegate;
pub mod handoff;
pub mod list;
pub mod register;

/// The well-known SLIM shared secret used as a clap default for local demos.
///
/// It is compiled into the binary and therefore provides NO real
/// authentication — anyone can read it from the source. It exists only so the
/// loopback demo scripts work without extra setup. Real deployments MUST set
/// `SLIM_SHARED_SECRET` (or `--slim-shared-secret`) to a private value.
pub const DEFAULT_SLIM_SHARED_SECRET: &str = "my_shared_secret_for_testing_purposes_only";

/// Emit a security warning when the built-in demo secret is in use.
///
/// The default secret is only safe for a loopback/local demo. When it is used
/// with a non-loopback SLIM endpoint, any peer that knows the (public) default
/// can connect and — via a registered adapter — drive local CLI-tool
/// execution, so we warn loudly on stderr.
pub fn warn_if_default_secret(shared_secret: &str, endpoint: &str) {
    if shared_secret != DEFAULT_SLIM_SHARED_SECRET {
        return;
    }
    if endpoint_is_loopback(endpoint) {
        eprintln!(
            "⚠️  Using the built-in demo SLIM shared secret (SLIM_SHARED_SECRET is unset). \
             This is fine for the loopback demo on {endpoint}, but set a private \
             SLIM_SHARED_SECRET before exposing the node."
        );
    } else {
        eprintln!(
            "⚠️  SECURITY: using the built-in demo SLIM shared secret with non-loopback \
             endpoint {endpoint}."
        );
        eprintln!(
            "    The default secret is public, so any peer can connect and drive local \
             CLI-tool execution. Set SLIM_SHARED_SECRET (or --slim-shared-secret) to a \
             private value."
        );
    }
}

/// Best-effort check whether a SLIM endpoint refers to the local loopback.
fn endpoint_is_loopback(endpoint: &str) -> bool {
    // Drop an optional scheme (e.g. "http://host:port") then isolate the host.
    let authority = endpoint.rsplit('/').next().unwrap_or(endpoint);
    let host = authority
        .rsplitn(2, ':')
        .last()
        .unwrap_or(authority)
        .trim_matches(|c| c == '[' || c == ']');
    matches!(host, "::1" | "localhost") || host.starts_with("127.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_detection() {
        assert!(endpoint_is_loopback("127.0.0.1:47357"));
        assert!(endpoint_is_loopback("localhost:8080"));
        assert!(endpoint_is_loopback("[::1]:47357"));
        assert!(!endpoint_is_loopback("10.0.0.5:47357"));
        assert!(!endpoint_is_loopback("slim.example.com:443"));
    }
}
