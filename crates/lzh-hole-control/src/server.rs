//! Unix socket ownership, peer UID authorization and bounded doctor dispatch.

use std::ffi::CString;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use lzh_hole_store::ensure_private_dir;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Semaphore, mpsc, oneshot, watch};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_util::codec::{Framed, LinesCodec};

use crate::dto::{ControlErrorCode, ControlRequest, ControlResponse, DoctorReport};
use crate::error::{ControlError, io};

/// Maximum encoded request or response line, excluding the newline.
///
/// Sized for a saturated doctor response: `MAX_PEERS_IN_SNAPSHOT` peers each
/// carrying `MAX_CANDIDATES_PER_PEER` candidates plus full component detail.
/// `dto::tests::a_saturated_snapshot_fits_one_control_line` pins the invariant
/// against a deliberately adversarial snapshot (every string at its documented
/// maximum), which measures 71022 bytes. Lowering this without lowering those
/// bounds fails the build rather than silently degrading `doctor` into a
/// generic internal error.
pub const MAX_CONTROL_LINE_BYTES: usize = 128 * 1024;
/// Maximum number of doctor operations waiting for the service owner.
pub const COMMAND_CHANNEL_CAPACITY: usize = 16;
/// Maximum concurrent local control connections.
pub const MAX_CONTROL_CLIENTS: usize = 32;
/// macOS `sockaddr_un.sun_path` has 104 bytes including the trailing NUL.
pub const MAX_CONTROL_SOCKET_PATH_BYTES: usize = 103;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_DETAIL_BYTES: usize = 512;

/// Socket settings supplied by service configuration, not a service DTO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlConfig {
    /// Unix socket inside a dedicated private directory.
    pub socket_path: PathBuf,
    /// UID allowed to use doctor; root is always allowed as well.
    pub management_uid: u32,
}

impl ControlConfig {
    /// Validate path shape without performing network or privileged operations.
    pub fn new(socket_path: PathBuf, management_uid: u32) -> Result<Self, ControlError> {
        if !socket_path.is_absolute()
            || socket_path == Path::new("/")
            || socket_path.file_name().is_none()
            || socket_path.parent() == Some(Path::new("/"))
        {
            return Err(ControlError::Invalid(
                "control socket must name a socket inside a dedicated absolute directory"
                    .to_owned(),
            ));
        }
        if socket_path
            .as_os_str()
            .as_encoded_bytes()
            .split(|byte| *byte == b'/')
            .any(|component| component == b"." || component == b"..")
        {
            return Err(ControlError::Invalid(
                "control socket must not contain '.' or '..' components".to_owned(),
            ));
        }
        if socket_path.as_os_str().as_encoded_bytes().len() > MAX_CONTROL_SOCKET_PATH_BYTES {
            return Err(ControlError::Invalid(format!(
                "control socket exceeds {MAX_CONTROL_SOCKET_PATH_BYTES} bytes on macOS"
            )));
        }
        Ok(Self {
            socket_path,
            management_uid,
        })
    }
}

/// Doctor command executed by the resident service owner.
pub enum ServiceCommand {
    /// Perform actual bounded checks and return a fresh doctor report.
    Doctor {
        /// Completion channel. Error text must be non-secret.
        reply: oneshot::Sender<Result<DoctorReport, String>>,
    },
}

fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

fn chown_nofollow(path: &Path, uid: u32) -> Result<(), ControlError> {
    let cpath = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| ControlError::Invalid("control path contains NUL".to_owned()))?;
    // SAFETY: cpath is valid and gid -1 leaves the group unchanged.
    if unsafe { libc::lchown(cpath.as_ptr(), uid, libc::gid_t::MAX) } != 0 {
        return Err(io(path, std::io::Error::last_os_error()));
    }
    Ok(())
}

fn ensure_control_directory(path: &Path, owner_uid: u32) -> Result<(), ControlError> {
    let euid = effective_uid();
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            ensure_private_dir(path).map_err(|error| ControlError::UnsafeDirectory {
                path: path.to_path_buf(),
                detail: error.to_string(),
            })?;
            std::fs::symlink_metadata(path).map_err(|error| io(path, error))?
        }
        Err(error) => return Err(io(path, error)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ControlError::UnsafeDirectory {
            path: path.to_path_buf(),
            detail: "not a real directory; symlinks are refused".to_owned(),
        });
    }
    if metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(ControlError::UnsafeDirectory {
            path: path.to_path_buf(),
            detail: format!(
                "mode {:#o} must be changed to 0700 by the administrator before use",
                metadata.permissions().mode() & 0o777
            ),
        });
    }
    if metadata.uid() != owner_uid {
        if euid != 0 {
            return Err(ControlError::UnsafeDirectory {
                path: path.to_path_buf(),
                detail: format!("owned by uid {}, expected {owner_uid}", metadata.uid()),
            });
        }
        chown_nofollow(path, owner_uid)?;
    }
    let verified = std::fs::symlink_metadata(path).map_err(|error| io(path, error))?;
    if verified.uid() != owner_uid
        || verified.permissions().mode() & 0o777 != 0o700
        || verified.file_type().is_symlink()
        || !verified.is_dir()
    {
        return Err(ControlError::UnsafeDirectory {
            path: path.to_path_buf(),
            detail: "ownership/mode verification failed".to_owned(),
        });
    }
    Ok(())
}

/// Identity of the one socket inode created by this server.
struct SocketGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl SocketGuard {
    fn capture(path: &Path) -> Result<Self, ControlError> {
        let metadata = std::fs::symlink_metadata(path).map_err(|error| io(path, error))?;
        if !metadata.file_type().is_socket() {
            return Err(ControlError::Invalid(format!(
                "{}: newly bound path is not a Unix socket",
                path.display()
            )));
        }
        Ok(Self {
            path: path.to_path_buf(),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let Ok(metadata) = std::fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Bound control server. Dropping it removes only its own unchanged socket inode.
pub struct ControlServer {
    listener: UnixListener,
    socket: SocketGuard,
    management_uid: u32,
    commands: mpsc::Sender<ServiceCommand>,
}

impl ControlServer {
    /// Bind without deleting any pre-existing path.
    pub fn bind(
        config: &ControlConfig,
        commands: mpsc::Sender<ServiceCommand>,
    ) -> Result<Self, ControlError> {
        let euid = effective_uid();
        if euid != 0 && config.management_uid != euid {
            return Err(ControlError::Invalid(format!(
                "non-root daemon uid {euid} cannot provide a socket to uid {}",
                config.management_uid
            )));
        }
        let owner_uid = if euid == 0 {
            config.management_uid
        } else {
            euid
        };
        let path = &config.socket_path;
        let parent = path
            .parent()
            .ok_or_else(|| ControlError::Invalid("control socket has no parent".to_owned()))?;
        ensure_control_directory(parent, owner_uid)?;
        if std::fs::symlink_metadata(path).is_ok() {
            return Err(ControlError::AlreadyExists(path.clone()));
        }

        let listener = UnixListener::bind(path).map_err(|error| io(path, error))?;
        let socket = SocketGuard::capture(path)?;
        if euid == 0 {
            chown_nofollow(path, owner_uid)?;
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| io(path, error))?;
        let metadata = std::fs::symlink_metadata(path).map_err(|error| io(path, error))?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != owner_uid
            || metadata.permissions().mode() & 0o777 != 0o600
        {
            return Err(ControlError::Invalid(format!(
                "{}: socket ownership/mode verification failed",
                path.display()
            )));
        }
        Ok(Self {
            listener,
            socket,
            management_uid: config.management_uid,
            commands,
        })
    }

    /// Serve until `shutdown` becomes true or its sender is dropped.
    pub async fn serve(self, mut shutdown: watch::Receiver<bool>) -> Result<(), ControlError> {
        let permits = Arc::new(Semaphore::new(MAX_CONTROL_CLIENTS));
        let mut clients = JoinSet::new();
        loop {
            if *shutdown.borrow() {
                break;
            }
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                accepted = self.listener.accept() => {
                    let (stream, _) = accepted.map_err(|error| io(&self.socket.path, error))?;
                    let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                        continue;
                    };
                    let management_uid = self.management_uid;
                    let commands = self.commands.clone();
                    clients.spawn(async move {
                        let _permit = permit;
                        let _ = handle_connection(stream, management_uid, commands).await;
                    });
                }
                Some(_) = clients.join_next(), if !clients.is_empty() => {}
            }
        }
        clients.abort_all();
        while clients.join_next().await.is_some() {}
        Ok(())
    }
}

fn uid_allowed(peer_uid: u32, management_uid: u32) -> bool {
    peer_uid == 0 || peer_uid == management_uid
}

fn error_response(code: ControlErrorCode, message: impl Into<String>) -> ControlResponse {
    ControlResponse::Error {
        code,
        message: bounded_detail(message.into()),
    }
}

fn bounded_detail(mut detail: String) -> String {
    if detail.len() > MAX_DETAIL_BYTES {
        let mut end = MAX_DETAIL_BYTES;
        while !detail.is_char_boundary(end) {
            end -= 1;
        }
        detail.truncate(end);
        detail.push('…');
    }
    detail
}

async fn send_response(
    framed: &mut Framed<UnixStream, LinesCodec>,
    response: ControlResponse,
) -> Result<(), ControlError> {
    let mut line = serde_json::to_string(&response)
        .map_err(|error| ControlError::Protocol(error.to_string()))?;
    if line.len() > MAX_CONTROL_LINE_BYTES {
        line = serde_json::to_string(&error_response(
            ControlErrorCode::Internal,
            "response exceeded the bounded line size",
        ))
        .map_err(|error| ControlError::Protocol(error.to_string()))?;
    }
    framed
        .send(line)
        .await
        .map_err(|error| ControlError::Protocol(error.to_string()))
}

async fn handle_connection(
    stream: UnixStream,
    management_uid: u32,
    commands: mpsc::Sender<ServiceCommand>,
) -> Result<(), ControlError> {
    let peer_uid = stream
        .peer_cred()
        .map_err(|error| ControlError::Protocol(format!("peer_cred: {error}")))?
        .uid();
    let mut framed = Framed::new(
        stream,
        LinesCodec::new_with_max_length(MAX_CONTROL_LINE_BYTES),
    );
    if !uid_allowed(peer_uid, management_uid) {
        return send_response(
            &mut framed,
            error_response(ControlErrorCode::Unauthorized, "uid is not authorized"),
        )
        .await;
    }
    let line = match timeout(REQUEST_TIMEOUT, framed.next()).await {
        Ok(Some(Ok(line))) => line,
        Ok(Some(Err(_))) => {
            return send_response(
                &mut framed,
                error_response(
                    ControlErrorCode::BadRequest,
                    "request is not bounded UTF-8 line JSON",
                ),
            )
            .await;
        }
        Ok(None) => return Ok(()),
        Err(_) => {
            return send_response(
                &mut framed,
                error_response(ControlErrorCode::Timeout, "request read timed out"),
            )
            .await;
        }
    };
    let request = match serde_json::from_str::<ControlRequest>(&line) {
        Ok(request) => request,
        Err(_) => {
            return send_response(
                &mut framed,
                error_response(
                    ControlErrorCode::BadRequest,
                    "expected exactly one doctor JSON request",
                ),
            )
            .await;
        }
    };
    let ControlRequest::Doctor = request;
    let (reply, receiver) = oneshot::channel();
    if commands.try_send(ServiceCommand::Doctor { reply }).is_err() {
        return send_response(
            &mut framed,
            error_response(
                ControlErrorCode::Unavailable,
                "doctor command queue is full or the service is stopping",
            ),
        )
        .await;
    }
    let response = match timeout(COMMAND_TIMEOUT, receiver).await {
        Ok(Ok(Ok(report))) => ControlResponse::Doctor {
            report: Box::new(report),
        },
        Ok(Ok(Err(detail))) => error_response(ControlErrorCode::Rejected, detail),
        Ok(Err(_)) => error_response(
            ControlErrorCode::Unavailable,
            "service owner dropped the command reply",
        ),
        Err(_) => error_response(
            ControlErrorCode::Timeout,
            "service command exceeded its bounded wait",
        ),
    };
    send_response(&mut framed, response).await
}

#[cfg(test)]
mod tests;
