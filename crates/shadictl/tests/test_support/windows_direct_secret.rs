use std::env;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::os::windows::io::{FromRawHandle, RawHandle};

fn read_secret() -> Result<Vec<u8>, String> {
    let raw_handle = env::var("TOOL_SECRET_FD")
        .map_err(|err| err.to_string())?
        .parse::<usize>()
        .map_err(|err| err.to_string())?;
    let mut file = unsafe { File::from_raw_handle(raw_handle as RawHandle) };
    let mut payload = Vec::new();
    file.read_to_end(&mut payload).map_err(|err| err.to_string())?;
    Ok(payload)
}

fn main() {
    let mut args = env::args().skip(1);
    let mode = args.next().expect("mode");
    match mode.as_str() {
        "direct-consume-secret" => {
            let output_path = args.next().expect("output path");
            let agent_token = env::var("AGENT_TOKEN").ok();
            let tool_secret = env::var("TOOL_SECRET").ok();
            let tool_fd_present = env::var("TOOL_SECRET_FD").is_ok();
            let protocol = env::var("SHADI_TRUSTED_SECRET_PROTOCOL").unwrap_or_default();
            let payload = read_secret().expect("read direct secret");
            fs::write(
                output_path,
                format!(
                    "agent_token={}\ntool_secret_present={}\ntool_fd_present={}\nprotocol={}\nsecret_payload={}\n",
                    agent_token.as_deref().unwrap_or(""),
                    tool_secret.is_some(),
                    tool_fd_present,
                    protocol,
                    String::from_utf8_lossy(&payload),
                ),
            )
            .expect("write direct report");
        }
        other => panic!("unexpected mode {other}"),
    }
}