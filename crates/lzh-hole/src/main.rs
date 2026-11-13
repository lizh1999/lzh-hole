//! Thin CLI entry point. All protocol, persistence and runtime work lives in
//! their respective crates.

mod args;
mod pairing;

use std::process::ExitCode;

use args::{Cli, Command};
use clap::Parser;
use lzh_hole_control::ControlError;
use lzh_hole_service::DaemonError;
use lzh_hole_store::PairingError;

#[derive(Debug, thiserror::Error)]
enum AppError {
    #[error(transparent)]
    Pairing(#[from] PairingError),
    #[error(transparent)]
    Daemon(#[from] DaemonError),
    #[error(transparent)]
    Control(#[from] ControlError),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = (|| -> Result<ExitCode, AppError> {
        Ok(match cli.command {
            Command::Init(args) => pairing::init(&args)?,
            Command::Pair { action } => pairing::run(action)?,
            Command::Daemon(args) => lzh_hole_service::run(args.config, args.allow_tun)?,
            Command::Doctor(args) => {
                let response = lzh_hole_service::doctor(&args.socket)?;
                let failed = matches!(response, lzh_hole_control::ControlResponse::Error { .. });
                println!("{}", lzh_hole_control::response_json(&response)?);
                if failed {
                    ExitCode::from(2)
                } else {
                    ExitCode::SUCCESS
                }
            }
        })
    })();
    match result {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(1)
        }
    }
}
