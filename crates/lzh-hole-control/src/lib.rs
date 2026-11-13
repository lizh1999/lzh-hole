//! Private, bounded Unix-socket doctor control plane.

#![allow(unsafe_code)]

mod client;
mod dto;
mod error;
mod server;

pub use client::{doctor, response_json};
pub use dto::*;
pub use error::ControlError;
pub use server::{
    COMMAND_CHANNEL_CAPACITY, ControlConfig, ControlServer, MAX_CONTROL_CLIENTS,
    MAX_CONTROL_LINE_BYTES, ServiceCommand,
};
