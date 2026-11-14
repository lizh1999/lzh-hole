//! Resident service configuration, lifecycle and component orchestration.

#![allow(unsafe_code)]

mod config;
mod daemon;
mod preflight;

pub use preflight::{InstallPreflight, install_preflight};

pub use config::{
    ConfigError, LanConfig, NtfyConfig as FileNtfyConfig, ResolvedConfig, ServiceConfig,
};
pub use daemon::{DaemonError, doctor, run};
