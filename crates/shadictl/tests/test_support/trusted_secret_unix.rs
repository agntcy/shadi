use std::env;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::Duration;

const PROTOCOL_ENV: &str = "SHADI_TRUSTED_SECRET_PROTOCOL";
const PROTOCOL_VALUE: &str = "pid-path-fetch-v3";

fn require_protocol() {
    let value = env::var(PROTOCOL_ENV).expect("protocol env");
    assert_eq!(value, PROTOCOL_VALUE);
}

fn token_endpoint() -> String {
    env::var("TOKEN_FD").expect("token endpoint")
}

fn read_secret(endpoint: &str) -> std::io::Result<Vec<u8>> {
    let mut stream = UnixStream::connect(endpoint)?;
    let nonce = env::var("TOKEN_FD_NONCE")
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::NotFound, err.to_string()))?;
    stream.write_all(nonce.as_bytes())?;
    let mut data = Vec::new();
    stream.read_to_end(&mut data)?;
    Ok(data)
}

fn main() {
    let mut args = env::args().skip(1);
    let mode = args.next().expect("mode");

    match mode.as_str() {
        "read-secret" => {
            require_protocol();
            let output = args.next().expect("output path");
            match read_secret(&token_endpoint()) {
                Ok(data) => {
                    fs::write(output, data).expect("write secret output");
                }
                Err(_) => {
                    std::process::exit(12);
                }
            }
        }
        "spawn-child" => {
            require_protocol();
            let child = args.next().expect("child path");
            let output = args.next().expect("output path");
            let status = Command::new(child)
                .arg("read-secret")
                .arg(output)
                .status()
                .expect("spawn child helper");
            std::process::exit(status.code().unwrap_or(1));
        }
        "spawn-child-without-nonce" => {
            require_protocol();
            let child = args.next().expect("child path");
            let output = args.next().expect("output path");
            let status = Command::new(child)
                .arg("read-secret")
                .arg(output)
                .env_remove("TOKEN_FD_NONCE")
                .status()
                .expect("spawn child helper");
            std::process::exit(status.code().unwrap_or(1));
        }
        "spawn-child-after-delay" => {
            require_protocol();
            let child = args.next().expect("child path");
            let output = args.next().expect("output path");
            let delay_ms = args
                .next()
                .expect("delay ms")
                .parse::<u64>()
                .expect("parse delay ms");
            std::thread::sleep(Duration::from_millis(delay_ms));
            let status = Command::new(child)
                .arg("read-secret")
                .arg(output)
                .status()
                .expect("spawn child helper");
            std::process::exit(status.code().unwrap_or(1));
        }
        "spawn-child-probe-after-delay" => {
            require_protocol();
            let child = args.next().expect("child path");
            let output = args.next().expect("output path");
            let delay_ms = args
                .next()
                .expect("delay ms")
                .parse::<u64>()
                .expect("parse delay ms");
            std::thread::sleep(Duration::from_millis(delay_ms));
            let status = Command::new(child)
                .arg("probe-secret")
                .arg(output)
                .status()
                .expect("spawn child helper");
            std::process::exit(status.code().unwrap_or(1));
        }
        "probe-secret" => {
            require_protocol();
            let output = args.next().expect("output path");
            match read_secret(&token_endpoint()) {
                Ok(data) if !data.is_empty() => {
                    fs::write(output, b"open").expect("write probe status");
                    std::process::exit(0);
                }
                Ok(_) => {
                    fs::write(output, b"closed").expect("write probe status");
                    std::process::exit(12);
                }
                Err(err) => {
                    fs::write(output, err.to_string()).expect("write probe status");
                    std::process::exit(13);
                }
            }
        }
        "consume-and-exec" => {
            require_protocol();
            let secret_output = args.next().expect("secret output path");
            let status_output = args.next().expect("status output path");
            let checker = args.next().expect("checker path");
            let data = read_secret(&token_endpoint()).expect("read trusted secret");
            fs::write(&secret_output, data).expect("write secret output");

            let err = Command::new(checker)
                .arg("check-secret-unavailable")
                .arg(status_output)
                .exec();
            panic!("exec failed: {}", err);
        }
        "check-secret-unavailable" => {
            require_protocol();
            let status_output = args.next().expect("status output path");
            let endpoint = token_endpoint();
            match read_secret(&endpoint) {
                Ok(data) => {
                    fs::write(status_output, format!("open:{}", data.len()))
                        .expect("write status");
                    std::process::exit(1);
                }
                Err(_) => {
                    fs::write(status_output, b"closed").expect("write status");
                    std::process::exit(0);
                }
            }
        }
        other => panic!("unknown mode {}", other),
    }
}