#[cfg(unix)]
include!("../test_support/trusted_secret_unix.rs");

#[cfg(not(unix))]
fn main() {
    panic!("shadictl-test-trusted-secret-helper is only supported on Unix");
}