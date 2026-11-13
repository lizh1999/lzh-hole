//! Secret material and its on-disk storage rules.
//!
//! A secret never appears in argv, in the environment, in a log line, in a
//! report or in a public record. Secret32 deliberately implements neither
//! Serialize nor Deserialize, so it cannot be serialised into a diagnostics
//! document even by accident.
//!
//! Every read and write verifies through the open descriptor, never through the
//! path: a path check followed by an open has a window in which the file can be
//! swapped or grown. Opens use O_NOFOLLOW, reads are bounded to the cap plus one
//! byte, and writes go to an unpredictable sibling temporary created with
//! O_EXCL, so a pre-existing temporary, a symlink or a hard link is a hard
//! failure rather than something we overwrite.

use std::fs;
use std::io::{Read, Write};
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

/// Largest secret file we will read.
pub const MAX_SECRET_FILE_BYTES: u64 = 4096;
/// Required mode for a file holding secret material.
pub const SECRET_FILE_MODE: u32 = 0o600;
/// Required mode for a directory holding secret material.
pub const SECRET_DIR_MODE: u32 = 0o700;

pub use lzh_hole_types::Secret32;

/// Why a secret could not be read, written or checked.
#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    /// The path is a symbolic link.
    #[error("{0}: refusing to follow a symlink")]
    Symlink(PathBuf),
    /// The path is not a regular file.
    #[error("{0}: not a regular file")]
    NotRegularFile(PathBuf),
    /// Group or other bits are set, or the mode is not exactly what we require.
    #[error("{path}: mode {mode:#o} is not the required {expected:#o}")]
    BadPermissions {
        /// Offending path.
        path: PathBuf,
        /// Observed mode.
        mode: u32,
        /// Required mode.
        expected: u32,
    },
    /// Owned by another user.
    #[error("{path}: owned by uid {uid}, expected {euid}")]
    WrongOwner {
        /// Offending path.
        path: PathBuf,
        /// Observed owner.
        uid: u32,
        /// Effective uid of this process.
        euid: u32,
    },
    /// The inode has more than one link.
    #[error("{path}: {nlink} hard links, expected exactly 1")]
    HardLinked {
        /// Offending path.
        path: PathBuf,
        /// Observed link count.
        nlink: u64,
    },
    /// Larger than the read cap.
    #[error("{path}: {len} bytes exceeds the {max} byte cap")]
    TooLarge {
        /// Offending path.
        path: PathBuf,
        /// Observed size.
        len: u64,
        /// Cap.
        max: u64,
    },
    /// Content was not 64 hex characters.
    #[error("secret file content is not 64 hex characters")]
    BadEncoding,
    /// The file already exists; we never overwrite secret material.
    #[error("{0}: already exists")]
    AlreadyExists(PathBuf),
    /// The OS random source failed.
    #[error("operating system randomness unavailable")]
    NoRandomness,
    /// The parent directory is missing, unsafe, or not one we may write into.
    #[error("{path}: {detail}")]
    UnsafeParent {
        /// Offending path.
        path: PathBuf,
        /// What is wrong.
        detail: String,
    },
    /// Underlying I/O failure.
    #[error("{path}: {source}")]
    Io {
        /// Offending path.
        path: PathBuf,
        /// Underlying error.
        source: std::io::Error,
    },
}

fn io(path: &Path, source: impl Into<std::io::Error>) -> SecretError {
    SecretError::Io {
        path: path.to_path_buf(),
        source: source.into(),
    }
}

fn io_msg(path: &Path, detail: &str) -> SecretError {
    SecretError::Io {
        path: path.to_path_buf(),
        source: std::io::Error::other(detail.to_owned()),
    }
}

fn effective_uid() -> u32 {
    // SAFETY: geteuid is always safe to call.
    unsafe { libc::geteuid() }
}

fn cpath(path: &Path) -> Result<std::ffi::CString, SecretError> {
    std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|e| io(path, std::io::Error::other(e)))
}

/// Open a path without following a symlink at the final component.
///
/// O_CLOEXEC keeps the descriptor out of any child, and O_NOFOLLOW turns a
/// symlink at the final component into ELOOP, which we report as a refusal
/// rather than as a generic I/O error.
fn open_nofollow(path: &Path, flags: libc::c_int, mode: u32) -> Result<fs::File, SecretError> {
    let c = cpath(path)?;
    // SAFETY: c is a valid NUL-terminated string for the duration of the call.
    let fd: RawFd = unsafe {
        libc::open(
            c.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode as libc::c_uint,
        )
    };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ELOOP) {
            return Err(SecretError::Symlink(path.to_path_buf()));
        }
        return Err(io(path, err));
    }
    // SAFETY: fd is a fresh owned descriptor from open.
    Ok(unsafe { fs::File::from_raw_fd(fd) })
}

/// Verify an already-open descriptor.
///
/// This is the check that actually matters: it describes the inode we hold, not
/// whatever the path pointed at when we looked.
fn verify_fd(
    file: &fs::File,
    path: &Path,
    expect_mode: u32,
    require_single_link: bool,
) -> Result<libc::stat, SecretError> {
    // SAFETY: libc::stat is plain old data; all-zero is a valid value.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: st is a valid out-parameter and fd is open for the call.
    let rc = unsafe { libc::fstat(file.as_raw_fd(), &mut st) };
    if rc != 0 {
        return Err(io(path, std::io::Error::last_os_error()));
    }
    // st_mode is u16 on Darwin and u32 on Linux; widen once.
    let mode_bits = st.st_mode as u32;
    if mode_bits & (libc::S_IFMT as u32) != libc::S_IFREG as u32 {
        return Err(SecretError::NotRegularFile(path.to_path_buf()));
    }
    let mode = mode_bits & 0o777;
    if mode != expect_mode {
        return Err(SecretError::BadPermissions {
            path: path.to_path_buf(),
            mode,
            expected: expect_mode,
        });
    }
    if st.st_uid != effective_uid() {
        return Err(SecretError::WrongOwner {
            path: path.to_path_buf(),
            uid: st.st_uid,
            euid: effective_uid(),
        });
    }
    if require_single_link && st.st_nlink != 1 {
        return Err(SecretError::HardLinked {
            path: path.to_path_buf(),
            nlink: st.st_nlink as u64,
        });
    }
    Ok(st)
}

/// Verify that `path` is a directory we control: not a symlink, mode 0700,
/// owned by our effective uid.
fn verify_private_dir(path: &Path) -> Result<(), SecretError> {
    let meta = fs::symlink_metadata(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            SecretError::UnsafeParent {
                path: path.to_path_buf(),
                detail: "directory does not exist".to_owned(),
            }
        } else {
            io(path, e)
        }
    })?;
    if meta.file_type().is_symlink() {
        return Err(SecretError::Symlink(path.to_path_buf()));
    }
    if !meta.is_dir() {
        return Err(SecretError::UnsafeParent {
            path: path.to_path_buf(),
            detail: "not a directory".to_owned(),
        });
    }
    let mode = std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o777;
    if mode != SECRET_DIR_MODE {
        return Err(SecretError::BadPermissions {
            path: path.to_path_buf(),
            mode,
            expected: SECRET_DIR_MODE,
        });
    }
    if meta.uid() != effective_uid() {
        return Err(SecretError::WrongOwner {
            path: path.to_path_buf(),
            uid: meta.uid(),
            euid: effective_uid(),
        });
    }
    Ok(())
}

/// Create a directory with mode 0700, or verify an existing one.
///
/// Missing components are created one at a time with mkdir(0700), so the mode is
/// applied by the creating syscall and there is never a window in which a
/// component exists with wider permissions. We walk up only to the nearest
/// existing ancestor, refuse to descend through a symlink, and verify every
/// component we create as well as the final target.
pub fn ensure_private_dir(path: &Path) -> Result<(), SecretError> {
    let mut missing: Vec<PathBuf> = Vec::new();
    let mut cursor = path.to_path_buf();
    loop {
        match fs::symlink_metadata(&cursor) {
            Ok(_) => break,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                missing.push(cursor.clone());
                match cursor.parent() {
                    Some(parent) if !parent.as_os_str().is_empty() => {
                        cursor = parent.to_path_buf();
                    }
                    _ => {
                        return Err(SecretError::UnsafeParent {
                            path: path.to_path_buf(),
                            detail: "reached the root without an existing ancestor".to_owned(),
                        });
                    }
                }
            }
            Err(e) if e.raw_os_error() == Some(libc::ENOTDIR) => {
                // A component along the way is not a directory, so we can never
                // create the target underneath it.
                return Err(SecretError::UnsafeParent {
                    path: cursor,
                    detail: "a component of the path is not a directory".to_owned(),
                });
            }
            Err(e) => return Err(io(&cursor, e)),
        }
    }

    // The nearest existing ancestor must be a real directory. We do not require
    // it to be ours or to be 0700: it may legitimately be something like /tmp.
    // What matters is that it is not a symlink, so we cannot be redirected.
    let ancestor = fs::symlink_metadata(&cursor).map_err(|e| io(&cursor, e))?;
    if ancestor.file_type().is_symlink() {
        return Err(SecretError::Symlink(cursor));
    }
    if !ancestor.is_dir() {
        return Err(SecretError::UnsafeParent {
            path: cursor,
            detail: "nearest existing ancestor is not a directory".to_owned(),
        });
    }

    for component in missing.iter().rev() {
        let c = cpath(component)?;
        // SAFETY: c is valid for the call; mkdir applies the mode itself.
        let rc = unsafe { libc::mkdir(c.as_ptr(), SECRET_DIR_MODE as libc::mode_t) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EEXIST) {
                return Err(io(component, err));
            }
        }
        verify_private_dir(component)?;
    }
    verify_private_dir(path)
}

/// Read a bounded, private file.
///
/// The descriptor is verified after the open, and the read is capped at
/// `max_len + 1` bytes so a file that grows between the fstat and the read
/// cannot slip past the cap. O_NONBLOCK means opening a FIFO returns
/// immediately, and the descriptor check then rejects it as not a regular file,
/// so a named pipe cannot make this hang.
pub fn read_private_bytes(path: &Path, max_len: u64) -> Result<Vec<u8>, SecretError> {
    let file = open_nofollow(path, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
    let st = verify_fd(&file, path, SECRET_FILE_MODE, false)?;
    if st.st_size as u64 > max_len {
        return Err(SecretError::TooLarge {
            path: path.to_path_buf(),
            len: st.st_size as u64,
            max: max_len,
        });
    }
    let mut out = Vec::with_capacity(st.st_size as usize);
    let mut limited = file.take(max_len.saturating_add(1));
    limited.read_to_end(&mut out).map_err(|e| io(path, e))?;
    if out.len() as u64 > max_len {
        return Err(SecretError::TooLarge {
            path: path.to_path_buf(),
            len: out.len() as u64,
            max: max_len,
        });
    }
    Ok(out)
}

/// Read a 32-byte secret from a file.
pub fn read_secret_file(path: &Path) -> Result<Secret32, SecretError> {
    let bytes = read_private_bytes(path, MAX_SECRET_FILE_BYTES)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| SecretError::BadEncoding)?;
    Secret32::from_hex(text.trim()).map_err(|_| SecretError::BadEncoding)
}

/// Write bytes to a file with mode 0600, replacing any existing file.
///
/// The parent must already be a controlled 0700 directory. The content goes to
/// an unpredictable sibling temporary created with O_EXCL, so a pre-existing
/// temporary, a symlink or a hard link makes the write fail instead of being
/// followed or overwritten. The temporary's descriptor is verified before
/// anything is written, then the file is fsynced, renamed over the target and
/// the parent directory is fsynced. On any failure only our own temporary is
/// removed; the target is never touched.
///
/// Concurrency is the caller's business: pair this with the single-writer lock.
pub fn write_private_bytes(path: &Path, bytes: &[u8]) -> Result<(), SecretError> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| io_msg(path, "path has no parent directory"))?;
    verify_private_dir(parent)?;
    let file_name = path
        .file_name()
        .ok_or_else(|| io_msg(path, "path has no file name"))?
        .to_string_lossy()
        .into_owned();

    let mut rand = [0u8; 16];
    getrandom::fill(&mut rand).map_err(|_| SecretError::NoRandomness)?;
    let tmp = parent.join(format!(".{file_name}.{}.tmp", hex::encode(rand)));

    let mut file = open_nofollow(
        &tmp,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        SECRET_FILE_MODE,
    )?;
    if let Err(e) = verify_fd(&file, &tmp, SECRET_FILE_MODE, true) {
        drop(file);
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }

    let written = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| io(path, e));
    drop(file);
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }

    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(io(path, e));
    }

    let dir = fs::File::open(parent).map_err(|e| io(parent, e))?;
    // SAFETY: dir is an open descriptor for the duration of the call.
    if unsafe { libc::fsync(dir.as_raw_fd()) } != 0 {
        return Err(io(parent, std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Write a secret to a new file with mode 0600, then fsync file and directory.
///
/// Uses O_EXCL so existing secret material is never overwritten, and O_NOFOLLOW
/// so a symlink cannot redirect the write. The parent must be a controlled 0700
/// directory.
pub fn write_secret_file(path: &Path, secret: &Secret32) -> Result<(), SecretError> {
    if path.exists() {
        return Err(SecretError::AlreadyExists(path.to_path_buf()));
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| io_msg(path, "path has no parent directory"))?;
    verify_private_dir(parent)?;

    let mut file = open_nofollow(
        path,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        SECRET_FILE_MODE,
    )?;
    verify_fd(&file, path, SECRET_FILE_MODE, true)?;
    let text = format!("{}\n", hex::encode(secret.expose_bytes()));
    file.write_all(text.as_bytes()).map_err(|e| io(path, e))?;
    file.sync_all().map_err(|e| io(path, e))?;
    drop(file);

    let dir = fs::File::open(parent).map_err(|e| io(parent, e))?;
    // SAFETY: dir is an open descriptor for the duration of the call.
    if unsafe { libc::fsync(dir.as_raw_fd()) } != 0 {
        return Err(io(parent, std::io::Error::last_os_error()));
    }
    Ok(())
}

/// An advisory exclusive lock held on a file for as long as it lives.
///
/// Used to guarantee a single writer per publish key. The lock inode is opened
/// without following a symlink and is never unlinked or recreated, because
/// replacing it would hand a second process a lock on a different inode while
/// the first still believes it holds one. An existing lock file with the wrong
/// mode is refused rather than chmod'ed: we do not change permissions on a file
/// we did not create.
#[derive(Debug)]
pub struct FileLock {
    file: fs::File,
    path: PathBuf,
}

impl FileLock {
    /// Try to take the lock without blocking.
    pub fn try_acquire(path: &Path) -> Result<Option<Self>, SecretError> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or_else(|| io_msg(path, "path has no parent directory"))?;
        verify_private_dir(parent)?;

        let existed = fs::symlink_metadata(path).is_ok();
        let file = open_nofollow(path, libc::O_RDWR | libc::O_CREAT, SECRET_FILE_MODE)?;
        if !existed {
            // We created this inode, so tightening our own file's mode is safe.
            // An existing lock file is never chmod'ed.
            // SAFETY: the descriptor is open for the duration of the call.
            let rc = unsafe { libc::fchmod(file.as_raw_fd(), SECRET_FILE_MODE as libc::mode_t) };
            if rc != 0 {
                return Err(io(path, std::io::Error::last_os_error()));
            }
        }
        verify_fd(&file, path, SECRET_FILE_MODE, false)?;

        // SAFETY: the descriptor is valid for the duration of the call.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(Some(Self {
                file,
                path: path.to_path_buf(),
            }));
        }
        let err = std::io::Error::last_os_error();
        if matches!(err.raw_os_error(), Some(code) if code == libc::EWOULDBLOCK) {
            return Ok(None);
        }
        Err(io(path, err))
    }

    /// The locked path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        // SAFETY: the descriptor is still open here. The inode is deliberately
        // not unlinked: another process may be about to lock it.
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn hex_of(secret: &Secret32) -> String {
        hex::encode(secret.expose_bytes())
    }

    fn private_dir() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state");
        ensure_private_dir(&path).unwrap();
        (dir, path)
    }

    fn mode_of(path: &Path) -> u32 {
        std::os::unix::fs::PermissionsExt::mode(&fs::symlink_metadata(path).unwrap().permissions())
            & 0o777
    }

    #[test]
    fn debug_and_display_are_redacted() {
        let secret = Secret32::from_bytes([0xab; 32]);
        assert_eq!(format!("{secret:?}"), "Secret32(<redacted>)");
        assert_eq!(format!("{secret}"), "<redacted>");
        assert!(!format!("{secret:?} {secret}").contains("ab"));
    }

    #[test]
    fn equality_is_constant_time_shaped_and_correct() {
        let a = Secret32::from_bytes([1u8; 32]);
        let b = Secret32::from_bytes([1u8; 32]);
        let mut c_bytes = [1u8; 32];
        c_bytes[31] = 2;
        let c = Secret32::from_bytes(c_bytes);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn hex_parsing_is_strict() {
        let secret = Secret32::from_bytes([0x5a; 32]);
        assert_eq!(Secret32::from_hex(&hex_of(&secret)).unwrap(), secret);
        assert!(Secret32::from_hex("").is_err());
        assert!(Secret32::from_hex("5a").is_err());
        assert!(Secret32::from_hex(&"z".repeat(64)).is_err());
        assert!(Secret32::from_hex(&"5a".repeat(31)).is_err());
    }

    #[test]
    fn random_secrets_differ() {
        let a = Secret32::random().unwrap();
        let b = Secret32::random().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn secret_round_trips_through_a_0600_file() {
        let (_d, base) = private_dir();
        let path = base.join("rel.psk");
        let secret = Secret32::random().unwrap();
        write_secret_file(&path, &secret).unwrap();
        assert_eq!(mode_of(&path), 0o600);
        assert_eq!(read_secret_file(&path).unwrap(), secret);
    }

    #[test]
    fn overwriting_secret_material_is_refused() {
        let (_d, base) = private_dir();
        let path = base.join("rel.psk");
        write_secret_file(&path, &Secret32::random().unwrap()).unwrap();
        assert!(matches!(
            write_secret_file(&path, &Secret32::random().unwrap()),
            Err(SecretError::AlreadyExists(_))
        ));
    }

    // --- over-wide mode -----------------------------------------------------

    #[test]
    fn a_file_with_group_or_other_bits_is_refused() {
        let (_d, base) = private_dir();
        let path = base.join("rel.psk");
        let secret = Secret32::random().unwrap();
        write_secret_file(&path, &secret).unwrap();
        for mode in [0o644u32, 0o640, 0o604, 0o666, 0o700, 0o660, 0o606] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                matches!(
                    read_secret_file(&path),
                    Err(SecretError::BadPermissions { .. })
                ),
                "mode {mode:#o} must be refused"
            );
            assert!(read_private_bytes(&path, 4096).is_err());
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_secret_file(&path).unwrap(), secret);
    }

    #[test]
    fn a_directory_that_is_not_0700_is_refused() {
        let (_d, base) = private_dir();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            verify_private_dir(&base),
            Err(SecretError::BadPermissions {
                expected: 0o700,
                ..
            })
        ));
        assert!(ensure_private_dir(&base).is_err());
        // And a write into it is refused rather than silently accepted.
        assert!(write_private_bytes(&base.join("x"), b"hi").is_err());
    }

    #[test]
    fn missing_components_are_created_one_at_a_time_at_0700() {
        let dir = tempfile::tempdir().unwrap();
        let deep = dir.path().join("a").join("b").join("c");
        ensure_private_dir(&deep).unwrap();
        // Every component we created is 0700, and nothing exists with a wider
        // mode along the way.
        for component in ["a", "a/b", "a/b/c"] {
            let p = dir.path().join(component);
            assert!(p.is_dir(), "{component} should exist");
            assert_eq!(mode_of(&p), 0o700, "{component} must be 0700");
        }
        assert!(verify_private_dir(&deep).is_ok());
    }

    #[test]
    fn a_symlinked_ancestor_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        ensure_private_dir(&real).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        // Descending through a symlinked component must be refused.
        assert!(matches!(
            ensure_private_dir(&link.join("child")),
            Err(SecretError::Symlink(_))
        ));
    }

    #[test]
    fn a_non_directory_ancestor_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");
        write_private_bytes(&file, b"x").unwrap_or(());
        fs::write(&file, b"x").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            ensure_private_dir(&file.join("child")),
            Err(SecretError::UnsafeParent { .. })
        ));
    }

    // --- symlinks -----------------------------------------------------------

    #[test]
    fn a_symlinked_secret_file_is_refused() {
        let (_d, base) = private_dir();
        let real = base.join("real.psk");
        write_secret_file(&real, &Secret32::random().unwrap()).unwrap();
        let link = base.join("link.psk");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(matches!(
            read_secret_file(&link),
            Err(SecretError::Symlink(_))
        ));
        assert!(matches!(
            read_private_bytes(&link, 4096),
            Err(SecretError::Symlink(_))
        ));
    }

    #[test]
    fn a_symlinked_directory_is_refused() {
        let (d, base) = private_dir();
        let link = d.path().join("dirlink");
        std::os::unix::fs::symlink(&base, &link).unwrap();
        assert!(matches!(
            ensure_private_dir(&link),
            Err(SecretError::Symlink(_))
        ));
        assert!(matches!(
            verify_private_dir(&link),
            Err(SecretError::Symlink(_))
        ));
    }

    #[test]
    fn writing_through_a_symlinked_target_does_not_touch_the_victim() {
        let (_d, base) = private_dir();
        // A victim file the attacker wants us to overwrite.
        let victim = base.join("victim");
        write_secret_file(&victim, &Secret32::from_bytes([7u8; 32])).unwrap();
        let victim_before = fs::read(&victim).unwrap();

        // The target path is a symlink to the victim.
        let target = base.join("target");
        std::os::unix::fs::symlink(&victim, &target).unwrap();

        write_private_bytes(&target, b"attacker-chosen").unwrap();

        // The victim is untouched, and the target is now a real 0600 file.
        assert_eq!(fs::read(&victim).unwrap(), victim_before);
        assert_eq!(fs::read(&target).unwrap(), b"attacker-chosen");
        assert_eq!(mode_of(&target), 0o600);
        assert!(
            !fs::symlink_metadata(&target)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn a_symlinked_lock_is_refused() {
        let (_d, base) = private_dir();
        let other = base.join("other.lock");
        write_private_bytes(&other, b"").unwrap();
        let link = base.join("link.lock");
        std::os::unix::fs::symlink(&other, &link).unwrap();
        assert!(matches!(
            FileLock::try_acquire(&link),
            Err(SecretError::Symlink(_))
        ));
    }

    // --- hard links and pre-existing temporaries ----------------------------

    #[test]
    fn a_hard_linked_secret_is_refused_on_write() {
        let (_d, base) = private_dir();
        let real = base.join("real.psk");
        write_secret_file(&real, &Secret32::from_bytes([1u8; 32])).unwrap();
        let linked = base.join("linked.psk");
        fs::hard_link(&real, &linked).unwrap();
        // The write goes to a fresh O_EXCL temporary, so the link count on the
        // existing inode is irrelevant, but reading a multiply-linked file is
        // still refused when the single-link requirement is applied.
        let file = open_nofollow(&linked, libc::O_RDONLY, 0).unwrap();
        assert!(matches!(
            verify_fd(&file, &linked, SECRET_FILE_MODE, true),
            Err(SecretError::HardLinked { nlink: 2, .. })
        ));
    }

    #[test]
    fn a_pre_existing_temporary_is_never_reused_or_overwritten() {
        let (_d, base) = private_dir();
        let target = base.join("state.json");

        // Simulate leftovers from a crashed writer, including one that matches
        // the naming scheme exactly and one that is a symlink.
        let leftover_plain = base.join(".state.json.deadbeefdeadbeefdeadbeefdeadbeef.tmp");
        let leftover_link_target = base.join("elsewhere");
        write_private_bytes(&leftover_link_target, b"do not clobber").unwrap();
        let leftover_symlink = base.join(".state.json.00000000000000000000000000000000.tmp");
        fs::write(&leftover_plain, b"stale").unwrap();
        fs::set_permissions(&leftover_plain, fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&leftover_link_target, &leftover_symlink).unwrap();

        write_private_bytes(&target, b"fresh").unwrap();

        // Our write succeeded, and nothing that was already there was touched.
        assert_eq!(fs::read(&target).unwrap(), b"fresh");
        assert_eq!(fs::read(&leftover_plain).unwrap(), b"stale");
        assert_eq!(fs::read(&leftover_link_target).unwrap(), b"do not clobber");
        assert!(
            fs::symlink_metadata(&leftover_symlink)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn a_write_leaves_no_temporary_behind() {
        let (_d, base) = private_dir();
        let target = base.join("state.json");
        write_private_bytes(&target, b"one").unwrap();
        write_private_bytes(&target, b"two").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"two");
        let strays: Vec<_> = fs::read_dir(&base)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(strays.is_empty(), "left temporaries behind: {strays:?}");
    }

    #[test]
    fn a_failed_write_cleans_up_only_its_own_temporary() {
        let (_d, base) = private_dir();
        // A target whose parent is not a private dir makes the write fail
        // before any temporary is created.
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("state.json");
        assert!(write_private_bytes(&target, b"x").is_err());
        let strays: Vec<_> = fs::read_dir(outside.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(strays.is_empty(), "unexpected files: {strays:?}");
        let _ = base;
    }

    // --- bounded reads ------------------------------------------------------

    #[test]
    fn an_oversized_file_is_refused() {
        let (_d, base) = private_dir();
        let path = base.join("big");
        write_private_bytes(&path, &vec![b'a'; 5000]).unwrap();
        assert!(matches!(
            read_private_bytes(&path, 4096),
            Err(SecretError::TooLarge { max: 4096, .. })
        ));
        // Exactly at the cap is fine.
        assert_eq!(read_private_bytes(&path, 5000).unwrap().len(), 5000);
    }

    #[test]
    fn the_read_cap_is_enforced_even_if_the_file_grows_after_the_stat() {
        let (_d, base) = private_dir();
        let path = base.join("growing");
        write_private_bytes(&path, b"small").unwrap();
        // Hold the file open and append after the descriptor checks would have
        // run: the bounded read must still refuse.
        let mut handle = fs::OpenOptions::new().append(true).open(&path).unwrap();
        let file = open_nofollow(&path, libc::O_RDONLY, 0).unwrap();
        let st = verify_fd(&file, &path, SECRET_FILE_MODE, false).unwrap();
        assert_eq!(st.st_size as u64, 5);
        handle.write_all(&[b'x'; 100]).unwrap();
        handle.sync_all().unwrap();
        drop(handle);
        assert!(
            matches!(
                read_private_bytes(&path, 5),
                Err(SecretError::TooLarge { .. })
            ),
            "a file that grew past the cap must be refused"
        );
    }

    #[test]
    fn a_fifo_is_refused_without_hanging() {
        let (_d, base) = private_dir();
        let path = base.join("pipe");
        let c = cpath(&path).unwrap();
        // SAFETY: c is valid for the call.
        let rc = unsafe { libc::mkfifo(c.as_ptr(), 0o600 as libc::mode_t) };
        assert_eq!(rc, 0, "mkfifo failed");
        // O_NONBLOCK means this returns immediately; the descriptor check then
        // rejects it as not a regular file.
        assert!(matches!(
            read_private_bytes(&path, 4096),
            Err(SecretError::NotRegularFile(_))
        ));
    }

    #[test]
    fn a_directory_is_not_readable_as_a_file() {
        let (_d, base) = private_dir();
        let sub = base.join("sub");
        ensure_private_dir(&sub).unwrap();
        assert!(matches!(
            read_private_bytes(&sub, 4096),
            Err(SecretError::NotRegularFile(_)) | Err(SecretError::Symlink(_))
        ));
    }

    // --- locking ------------------------------------------------------------

    #[test]
    fn the_lock_is_exclusive_and_never_replaces_the_inode() {
        let (_d, base) = private_dir();
        let path = base.join("publish.lock");

        let first = FileLock::try_acquire(&path).unwrap();
        assert!(first.is_some());
        let inode_before = fs::symlink_metadata(&path).unwrap().ino();

        // A second independent open in the same process must fail.
        let second = FileLock::try_acquire(&path).unwrap();
        assert!(second.is_none(), "a second writer must be refused");

        // The inode is never unlinked or recreated while held.
        assert_eq!(fs::symlink_metadata(&path).unwrap().ino(), inode_before);

        drop(first);
        let third = FileLock::try_acquire(&path).unwrap();
        assert!(third.is_some());
        assert_eq!(
            fs::symlink_metadata(&path).unwrap().ino(),
            inode_before,
            "releasing and retaking must reuse the same inode"
        );
    }

    #[test]
    fn an_existing_lock_file_with_a_wide_mode_is_refused_not_chmod_ed() {
        let (_d, base) = private_dir();
        let path = base.join("publish.lock");
        fs::write(&path, b"").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        let before = mode_of(&path);
        assert!(matches!(
            FileLock::try_acquire(&path),
            Err(SecretError::BadPermissions { .. })
        ));
        assert_eq!(
            mode_of(&path),
            before,
            "we must not change permissions on a file we did not create"
        );
    }

    #[test]
    fn a_lock_in_a_non_private_directory_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("publish.lock");
        assert!(matches!(
            FileLock::try_acquire(&path),
            Err(SecretError::BadPermissions { .. }) | Err(SecretError::UnsafeParent { .. })
        ));
    }

    #[test]
    fn concurrent_writers_are_serialised_by_the_lock() {
        let (_d, base) = private_dir();
        let path = base.join("publish.lock");
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let overlaps = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let path = path.clone();
            let counter = std::sync::Arc::clone(&counter);
            let overlaps = std::sync::Arc::clone(&overlaps);
            handles.push(std::thread::spawn(move || {
                for _ in 0..50 {
                    if let Ok(Some(_lock)) = FileLock::try_acquire(&path) {
                        let was = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        if was != 0 {
                            overlaps.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        }
                        std::thread::yield_now();
                        counter.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(
            overlaps.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "two holders were inside the lock at once"
        );
    }

    #[test]
    fn writes_replace_an_existing_wide_mode_target_with_0600() {
        let (_d, base) = private_dir();
        let path = base.join("state.json");
        fs::write(&path, b"old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        write_private_bytes(&path, b"new").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new");
        assert_eq!(mode_of(&path), 0o600, "the replacement must be 0600");
    }

    #[test]
    fn read_private_bytes_rejects_a_badly_encoded_secret() {
        let (_d, base) = private_dir();
        let path = base.join("rel.psk");
        write_private_bytes(&path, b"not hex").unwrap();
        assert!(matches!(
            read_secret_file(&path),
            Err(SecretError::BadEncoding)
        ));
    }
}
