#[cfg(target_os = "macos")]
include!("../test_support/agent_tool_usage_macos.rs");

#[cfg(not(target_os = "macos"))]
fn main() {
    panic!("shadictl-test-agent-helper is only supported on macOS");
}