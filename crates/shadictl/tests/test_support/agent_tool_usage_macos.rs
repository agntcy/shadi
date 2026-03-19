use std::env;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::Command;

fn read_secret(endpoint: &str) -> Result<Vec<u8>, String> {
    let mut stream = UnixStream::connect(endpoint).map_err(|err| err.to_string())?;
    let nonce = env::var("TOOL_SECRET_FD_NONCE").map_err(|err| err.to_string())?;
    stream
        .write_all(nonce.as_bytes())
        .map_err(|err| err.to_string())?;
    let mut payload = Vec::new();
    stream.read_to_end(&mut payload).map_err(|err| err.to_string())?;
    Ok(payload)
}

fn main() {
    let mut args = env::args().skip(1);
    let mode = args.next().expect("mode");

    match mode.as_str() {
        "agent-spawn-tool" => {
            let parent_report = args.next().expect("parent report");
            let child_program = args.next().expect("child program");
            let child_report = args.next().expect("child report");
            let agent_token = env::var("AGENT_TOKEN").ok();
            let tool_secret = env::var("TOOL_SECRET").ok();
            let tool_fd_present = env::var("TOOL_SECRET_FD").is_ok();
            let tool_nonce_present = env::var("TOOL_SECRET_FD_NONCE").is_ok();

            fs::write(
                &parent_report,
                format!(
                    "agent_token={}\ntool_secret_present={}\ntool_fd_present={}\ntool_nonce_present={}\n",
                    agent_token.as_deref().unwrap_or(""),
                    tool_secret.is_some(),
                    tool_fd_present,
                    tool_nonce_present,
                ),
            )
            .expect("write parent report");

            let status = Command::new(child_program)
                .arg("tool-consume-secret")
                .arg(&child_report)
                .status()
                .expect("spawn child tool");
            std::process::exit(status.code().unwrap_or(1));
        }
        "tool-consume-secret" => {
            let output_path = args.next().expect("output path");
            let endpoint = env::var("TOOL_SECRET_FD").expect("tool secret endpoint");
            match read_secret(&endpoint) {
                Ok(payload) if !payload.is_empty() => {
                    fs::write(output_path, payload).expect("write secret payload");
                    std::process::exit(0);
                }
                Ok(_) => {
                    fs::write(output_path, b"closed").expect("write closed marker");
                    std::process::exit(12);
                }
                Err(err) => {
                    fs::write(output_path, err).expect("write error marker");
                    std::process::exit(13);
                }
            }
        }
        "direct-consume-secret" => {
            let output_path = args.next().expect("output path");
            let agent_token = env::var("AGENT_TOKEN").ok();
            let tool_secret = env::var("TOOL_SECRET").ok();
            let tool_fd_present = env::var("TOOL_SECRET_FD").is_ok();
            let tool_nonce_present = env::var("TOOL_SECRET_FD_NONCE").is_ok();
            let endpoint = env::var("TOOL_SECRET_FD").expect("tool secret endpoint");
            let payload = read_secret(&endpoint).expect("read direct secret");

            fs::write(
                output_path,
                format!(
                    "agent_token={}\ntool_secret_present={}\ntool_fd_present={}\ntool_nonce_present={}\nsecret_payload={}\n",
                    agent_token.as_deref().unwrap_or(""),
                    tool_secret.is_some(),
                    tool_fd_present,
                    tool_nonce_present,
                    String::from_utf8_lossy(&payload),
                ),
            )
            .expect("write direct report");
        }
        other => panic!("unexpected mode {other}"),
    }
}