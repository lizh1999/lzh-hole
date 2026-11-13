//! Bounded doctor client. Exactly one request is sent per connection.

use std::path::Path;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::net::UnixStream;
use tokio::time::timeout;
use tokio_util::codec::{Framed, LinesCodec};

use crate::dto::{ControlRequest, ControlResponse};
use crate::error::{ControlError, io};
use crate::server::MAX_CONTROL_LINE_BYTES;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(20);

/// Request fresh doctor observations over a private Unix socket.
pub async fn doctor(socket_path: &Path) -> Result<ControlResponse, ControlError> {
    let stream = timeout(CONNECT_TIMEOUT, UnixStream::connect(socket_path))
        .await
        .map_err(|_| ControlError::Timeout("Unix socket connect"))?
        .map_err(|error| io(socket_path, error))?;
    let mut framed = Framed::new(
        stream,
        LinesCodec::new_with_max_length(MAX_CONTROL_LINE_BYTES),
    );
    let line = serde_json::to_string(&ControlRequest::Doctor)
        .map_err(|error| ControlError::Protocol(error.to_string()))?;
    timeout(REQUEST_TIMEOUT, framed.send(line))
        .await
        .map_err(|_| ControlError::Timeout("request write"))?
        .map_err(|error| ControlError::Protocol(error.to_string()))?;
    let response = timeout(RESPONSE_TIMEOUT, framed.next())
        .await
        .map_err(|_| ControlError::Timeout("response read"))?
        .ok_or_else(|| ControlError::Protocol("server closed without a response".to_owned()))?
        .map_err(|error| ControlError::Protocol(error.to_string()))?;
    let response: ControlResponse = serde_json::from_str(&response)
        .map_err(|error| ControlError::Protocol(error.to_string()))?;
    if !matches!(
        response,
        ControlResponse::Doctor { .. } | ControlResponse::Error { .. }
    ) {
        return Err(ControlError::Protocol(
            "response does not match the doctor request".to_owned(),
        ));
    }
    Ok(response)
}

/// Serialize a doctor response for the thin CLI presentation layer.
pub fn response_json(response: &ControlResponse) -> Result<String, ControlError> {
    serde_json::to_string_pretty(response)
        .map_err(|error| ControlError::Protocol(error.to_string()))
}
