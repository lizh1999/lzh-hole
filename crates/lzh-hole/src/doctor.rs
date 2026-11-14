//! Local preflight and ordinary read-only daemon diagnostics.
use std::process::ExitCode;

use crate::{AppError, args::ControlArgs};

pub(crate) fn run(args: &ControlArgs) -> Result<ExitCode, AppError> {
    if args.preflight {
        let config = args.config.as_deref().ok_or(AppError::Preflight)?;
        // Never print deserialization errors from private pairing material.
        let report =
            lzh_hole_service::install_preflight(config).map_err(|_| AppError::Preflight)?;
        println!("{}", serde_json::to_string(&report)?);
        return Ok(ExitCode::SUCCESS);
    }
    let socket = args.socket.as_deref().ok_or(AppError::Preflight)?;
    let response = lzh_hole_service::doctor(socket)?;
    let failed = matches!(response, lzh_hole_control::ControlResponse::Error { .. });
    println!("{}", lzh_hole_control::response_json(&response)?);
    Ok(if failed {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    })
}
