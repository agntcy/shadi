// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::process::ExitCode;

use agent_transport_slim::{bridge_usage, parse_bridge_args, run_stdio_bridge};

fn main() -> ExitCode {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.iter().any(|arg| arg == "-h" || arg == "--help") {
        println!("{}", bridge_usage());
        return ExitCode::SUCCESS;
    }

    let parsed = match parse_bridge_args(&args) {
        Ok(parsed) => parsed,
        Err(err) => {
            eprintln!("error: {}\n\n{}", err, bridge_usage());
            return ExitCode::from(2);
        }
    };

    match run_stdio_bridge(parsed) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {}", err);
            ExitCode::from(1)
        }
    }
}