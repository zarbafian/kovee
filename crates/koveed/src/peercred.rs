//! Unix peer-credential authentication for the local socket (kovee §9.1:
//! local mode binds one principal to Unix peer credentials; the akson
//! control-socket discipline). The daemon reads the connecting process's
//! credentials with `SO_PEERCRED` and refuses any peer whose UID is not
//! its own — this is the K1 channel authentication (§12.2 step 1).
//!
//! What you write:
//! ```
//! use koveed::peercred::{authenticate_same_uid, current_uid};
//! use std::os::unix::net::UnixStream;
//! let (a, _b) = UnixStream::pair().unwrap();
//! // A socketpair is created by this process, so its peer UID is our own.
//! authenticate_same_uid(&a, current_uid()).unwrap();
//! ```

use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;

/// The credentials of the process on the other end of a Unix socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCredentials {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

/// Why a local peer failed authentication.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("could not read peer credentials: {0}")]
    Credentials(String),
    /// The peer's UID is not the daemon's — refused. The message is generic so it
    /// leaks nothing about who connected.
    #[error("local peer is not authorized")]
    Unauthorized,
}

/// The effective UID of this process — the daemon's own UID (kovee §9.1).
pub fn current_uid() -> u32 {
    // SAFETY: geteuid is always safe and cannot fail.
    #[allow(unsafe_code)]
    unsafe {
        libc::geteuid()
    }
}

/// Reads the connected peer's credentials via `SO_PEERCRED` (kovee §9.1).
pub fn peer_credentials(stream: &UnixStream) -> Result<PeerCredentials, AuthError> {
    // SAFETY: getsockopt writes a `ucred` of `len` bytes into `cred` for a valid
    // socket fd; on success `cred` is fully initialized. We check the return code.
    #[allow(unsafe_code)]
    unsafe {
        let mut cred: libc::ucred = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let rc = libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast::<libc::c_void>(),
            &mut len,
        );
        if rc != 0 {
            return Err(AuthError::Credentials(
                std::io::Error::last_os_error().to_string(),
            ));
        }
        Ok(PeerCredentials {
            pid: cred.pid,
            uid: cred.uid,
            gid: cred.gid,
        })
    }
}

/// Authenticates a local peer under the personal profile (kovee §9.1): its UID
/// must equal `expected_uid` (the daemon's own). Returns the peer's credentials on
/// success, or [`AuthError::Unauthorized`] otherwise.
pub fn authenticate_same_uid(
    stream: &UnixStream,
    expected_uid: u32,
) -> Result<PeerCredentials, AuthError> {
    let cred = peer_credentials(stream)?;
    if cred.uid == expected_uid {
        Ok(cred)
    } else {
        Err(AuthError::Unauthorized)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_socketpair_peer_is_our_own_uid() {
        let (a, b) = UnixStream::pair().unwrap();
        let ca = peer_credentials(&a).unwrap();
        let cb = peer_credentials(&b).unwrap();
        assert_eq!(ca.uid, current_uid());
        assert_eq!(cb.uid, current_uid());
        assert_eq!(ca.gid, cb.gid);
    }

    #[test]
    fn same_uid_authenticates_and_a_foreign_uid_is_refused() {
        let (a, _b) = UnixStream::pair().unwrap();
        // Our own UID authenticates.
        authenticate_same_uid(&a, current_uid()).unwrap();
        // A different UID is refused with the generic error.
        let other = current_uid().wrapping_add(1);
        assert_eq!(
            authenticate_same_uid(&a, other),
            Err(AuthError::Unauthorized)
        );
    }
}
