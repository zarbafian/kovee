//! The local control socket: path resolution and hardened binding
//! (akson's control-socket discipline, kovee §8 personal profile).
//!
//! The socket file is `0600` inside a `0700` per-user directory; peer
//! authentication (`SO_PEERCRED` same-UID) happens per connection in the
//! serve loop. Framing is one newline-terminated JSON request per
//! connection: write one line, read one line, the daemon closes.

use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;

use crate::peercred::current_uid;

/// The runtime directory holding the socket. In priority:
/// `$KOVEE_RUNTIME_DIR` (the exact directory — tests and service units),
/// else `$XDG_RUNTIME_DIR/kovee` (a private `0700` per-user tmpfs), else
/// a UID-scoped temp directory. Daemon and CLI resolve through this one
/// function so they always agree.
pub fn socket_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("KOVEE_RUNTIME_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(rt) if !rt.is_empty() => PathBuf::from(rt).join("kovee"),
        _ => std::env::temp_dir().join(format!("kovee-{}", current_uid())),
    }
}

/// The control socket path (personal profile).
pub fn socket_path() -> PathBuf {
    socket_dir().join("kovee.sock")
}

#[derive(Debug, thiserror::Error)]
pub enum BindError {
    #[error("socket io: {0}")]
    Io(#[from] std::io::Error),
}

/// Creates the `0700` runtime directory, removes a stale socket file, and
/// binds the listener with the socket file at `0600`.
pub fn bind() -> Result<(UnixListener, PathBuf), BindError> {
    let dir = socket_dir();
    std::fs::create_dir_all(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    let path = socket_path();
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok((listener, path))
}
