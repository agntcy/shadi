// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::io::{self, BufRead, Write};
use std::time::Duration;

use crate::{NativeSlimBootstrap, NativeSlimSession};

const DEFAULT_GROUP_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeArgs {
    pub bootstrap: NativeSlimBootstrap,
    pub payload_type: Option<String>,
    pub allow_empty: bool,
}

pub fn bridge_usage() -> &'static str {
    "Usage: slim-stdio-bridge (--channel NAME | --destination NAME) [--timeout SECONDS] [--payload-type TYPE] [--allow-empty]\n\nReads UTF-8 lines from stdin and publishes each line as one SLIM message.\n\nModes:\n  --channel NAME        Wait for SHADI to invite this bridge into the named group session.\n  --destination NAME    Create a point-to-point session to the named destination.\n\nOptions:\n  --timeout SECONDS     Group join timeout in seconds. Use 0 to wait indefinitely.\n  --payload-type TYPE   Optional SLIM payload type attached to every published line.\n  --allow-empty         Forward empty input lines instead of skipping them.\n\nEnvironment:\n  SLIM_ENDPOINT, SLIM_SHARED_SECRET, SHADI_SLIM_SHARED_SECRET_KEY\n  SHADI_SLIM_LOCAL_NAME, SHADI_AGENT_ID\n  SLIM_TLS_CERT, SLIM_TLS_KEY, SLIM_TLS_CA, SHADI_TMP_DIR"
}

pub fn parse_bridge_args(args: &[String]) -> Result<BridgeArgs, String> {
    let mut channel = None;
    let mut destination = None;
    let mut timeout = Some(DEFAULT_GROUP_TIMEOUT);
    let mut timeout_was_set = false;
    let mut payload_type = None;
    let mut allow_empty = false;

    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--channel" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--channel requires a value".to_string())?;
                channel = Some(value.clone());
                index += 2;
            }
            "--destination" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--destination requires a value".to_string())?;
                destination = Some(value.clone());
                index += 2;
            }
            "--timeout" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--timeout requires a value".to_string())?;
                let seconds = value
                    .parse::<u64>()
                    .map_err(|_| format!("invalid timeout value: {}", value))?;
                timeout = if seconds == 0 {
                    None
                } else {
                    Some(Duration::from_secs(seconds))
                };
                timeout_was_set = true;
                index += 2;
            }
            "--payload-type" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--payload-type requires a value".to_string())?;
                payload_type = Some(value.clone());
                index += 2;
            }
            "--allow-empty" => {
                allow_empty = true;
                index += 1;
            }
            other => {
                return Err(format!("unknown argument: {}", other));
            }
        }
    }

    match (channel, destination) {
        (Some(channel), None) => Ok(BridgeArgs {
            bootstrap: NativeSlimBootstrap::GroupJoin { channel, timeout },
            payload_type,
            allow_empty,
        }),
        (None, Some(destination)) => {
            if timeout_was_set {
                return Err("--timeout is only valid with --channel".to_string());
            }
            Ok(BridgeArgs {
                bootstrap: NativeSlimBootstrap::PointToPoint { destination },
                payload_type,
                allow_empty,
            })
        }
        (Some(_), Some(_)) => Err("use either --channel or --destination, not both".to_string()),
        (None, None) => Err("one of --channel or --destination is required".to_string()),
    }
}

pub fn run_stdio_bridge(args: BridgeArgs) -> Result<(), String> {
    let session = NativeSlimSession::from_env(args.bootstrap.clone())?;
    let session_id = session.session_id()?;

    let mut stderr = io::stderr().lock();
    writeln!(
        stderr,
        "connected SLIM stdio bridge as {} to {} {} session {}",
        session.local_name(),
        args.bootstrap.description(),
        session.target(),
        session_id
    )
    .map_err(io_error)?;

    let published = pump_reader(io::stdin().lock(), args.allow_empty, |line| {
        session.publish_bytes(line.into_bytes(), args.payload_type.clone())
    })?;

    writeln!(stderr, "published {} SLIM messages", published).map_err(io_error)?;
    Ok(())
}

fn pump_reader<R, F>(mut reader: R, allow_empty: bool, mut publish: F) -> Result<usize, String>
where
    R: BufRead,
    F: FnMut(String) -> Result<(), String>,
{
    let mut published = 0_usize;
    let mut line = String::new();
    loop {
        line.clear();
        let bytes = reader.read_line(&mut line).map_err(io_error)?;
        if bytes == 0 {
            return Ok(published);
        }

        while matches!(line.chars().last(), Some('\n' | '\r')) {
            line.pop();
        }

        if line.is_empty() && !allow_empty {
            continue;
        }

        publish(line.clone())?;
        published += 1;
    }
}

fn io_error(err: io::Error) -> String {
    err.to_string()
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn given_channel_args_when_parsed_then_group_mode_is_selected() {
        let args = vec!["--channel".to_string(), "agntcy/shadi/secops-room".to_string()];

        let parsed = parse_bridge_args(&args).expect("parse args");
        match parsed.bootstrap {
            NativeSlimBootstrap::GroupJoin { channel, timeout } => {
                assert_eq!(channel, "agntcy/shadi/secops-room");
                assert_eq!(timeout, Some(DEFAULT_GROUP_TIMEOUT));
            }
            other => panic!("unexpected bootstrap: {:?}", other),
        }
    }

    #[test]
    fn given_destination_args_when_parsed_then_point_to_point_mode_is_selected() {
        let args = vec!["--destination".to_string(), "agntcy/shadi/avatar".to_string()];

        let parsed = parse_bridge_args(&args).expect("parse args");
        match parsed.bootstrap {
            NativeSlimBootstrap::PointToPoint { destination } => {
                assert_eq!(destination, "agntcy/shadi/avatar");
            }
            other => panic!("unexpected bootstrap: {:?}", other),
        }
    }

    #[test]
    fn given_zero_timeout_when_parsed_then_group_join_waits_indefinitely() {
        let args = vec![
            "--channel".to_string(),
            "agntcy/shadi/secops-room".to_string(),
            "--timeout".to_string(),
            "0".to_string(),
        ];

        let parsed = parse_bridge_args(&args).expect("parse args");
        match parsed.bootstrap {
            NativeSlimBootstrap::GroupJoin { timeout, .. } => {
                assert_eq!(timeout, None);
            }
            other => panic!("unexpected bootstrap: {:?}", other),
        }
    }

    #[test]
    fn given_both_targets_when_parsed_then_it_is_rejected() {
        let args = vec![
            "--channel".to_string(),
            "agntcy/shadi/secops-room".to_string(),
            "--destination".to_string(),
            "agntcy/shadi/avatar".to_string(),
        ];

        let err = parse_bridge_args(&args).expect_err("target conflict");
        assert!(err.contains("either --channel or --destination"));
    }

    #[test]
    fn given_reader_with_blank_lines_when_pumping_then_empty_lines_are_skipped_by_default() {
        let reader = Cursor::new("alpha\n\n beta\n");
        let mut published = Vec::new();

        let count = pump_reader(reader, false, |line| {
            published.push(line);
            Ok(())
        })
        .expect("pump reader");

        assert_eq!(count, 2);
        assert_eq!(published, vec!["alpha".to_string(), " beta".to_string()]);
    }

    #[test]
    fn given_reader_with_blank_lines_when_allow_empty_then_they_are_forwarded() {
        let reader = Cursor::new("alpha\n\n");
        let mut published = Vec::new();

        let count = pump_reader(reader, true, |line| {
            published.push(line);
            Ok(())
        })
        .expect("pump reader");

        assert_eq!(count, 2);
        assert_eq!(published, vec!["alpha".to_string(), "".to_string()]);
    }
}