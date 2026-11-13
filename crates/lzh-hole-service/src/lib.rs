//! Resident service configuration, lifecycle and component orchestration.

#![allow(unsafe_code)]

mod config;
mod daemon;

pub use config::{
    ConfigError, LanConfig, NtfyConfig as FileNtfyConfig, ResolvedConfig, ServiceConfig,
};
pub use daemon::{DaemonError, doctor, run};
