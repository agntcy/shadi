#[cfg(target_os = "windows")]
include!("../test_support/windows_direct_secret.rs");

#[cfg(not(target_os = "windows"))]
fn main() {
    panic!("shadictl-test-windows-direct-helper is only supported on Windows");
}