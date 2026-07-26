//! The credential, and the fact that it cannot leave the broker.
//!
//! [`Credential`] is a newtype over the secret bytes with **no**
//! `Serialize`, **no** `Display`, and a `Debug` that prints
//! `Credential(redacted, 108 bytes)`. So the ways a key normally escapes —
//! `serde_json::to_value(record)`, `format!("{state:?}")` in an event
//! payload, a `Problem.detail` built with `{e}` — cannot compile or cannot
//! reveal it.
//!
//! `expose()` is the single exit, and it is **crate-private** (D-R3-1): its
//! only caller is the transport's header writer, and no code outside this
//! crate can read a key out of a `Credential` at all. [`resolve`] is the only
//! public way to obtain one, and it reads from the daemon's own environment
//! or secret table.
//!
//! What you write:
//! ```
//! use kovee_effects::{CredentialRef, resolve};
//! std::env::set_var("KOVEE_DOC_KEY", "sk-secret-value");
//! let credential = resolve(&CredentialRef::Env("KOVEE_DOC_KEY".into()), |_| None).unwrap();
//! // Debug never reveals it — an event payload built from `{:?}` is safe.
//! assert_eq!(format!("{credential:?}"), "Credential(redacted, 15 bytes)");
//! ```
//!
//! And the exit is not reachable from outside:
//! ```compile_fail,E0624
//! # fn f(credential: &kovee_effects::Credential) {
//! let secret = credential.expose();
//! # }
//! ```
//! nor is the constructor:
//! ```compile_fail,E0624
//! let credential = kovee_effects::Credential::new("sk-mine");
//! ```
//! and a resolved one cannot be duplicated:
//! ```compile_fail,E0599
//! # use kovee_effects::Credential;
//! # fn f(credential: Credential) -> (Credential, Credential) {
//! let copy = credential.clone();
//! (credential, copy)
//! # }
//! ```

use crate::binding::CredentialRef;

/// One resolved provider credential. Never serialized, never displayed,
/// never readable outside this crate — and, since R3-B02, never **copied**
/// either: without `Clone` a credential cannot be duplicated into a longer
/// lived place than the call that resolved it, and its `Drop` scrub is the
/// only end it has.
#[derive(PartialEq, Eq)]
pub struct Credential(String);

impl Credential {
    /// Wraps a secret. Trailing whitespace is trimmed: a key read from a
    /// file or a shell export commonly carries a newline, and sending it
    /// produces an opaque provider 401.
    pub(crate) fn new(secret: &str) -> Credential {
        Credential(secret.trim().to_owned())
    }

    /// The single explicit exit, called only where the credential is
    /// written into an outbound header — and crate-private, so that is the
    /// only place it *can* be called from.
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// A credential built from a literal — **test configuration only**, for
    /// the suites that dial a provider with a deliberately invalid key. A
    /// production build has no way to make one except [`resolve`], from the
    /// daemon's own environment or secret table.
    #[cfg(any(test, feature = "testing"))]
    pub fn for_testing(secret: &str) -> Credential {
        Credential::new(secret)
    }
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Credential(redacted, {} bytes)", self.0.len())
    }
}

impl Drop for Credential {
    fn drop(&mut self) {
        // Best-effort scrub of the heap buffer before it is freed. Not a
        // guarantee (a `String` that was moved may have been copied), but
        // the common case does not leave a readable key in freed memory.
        scrub_in_place(&mut self.0);
    }
}

/// Overwrites a `String`'s bytes in place, with no `unsafe`: `clear` keeps
/// the allocation, so pushing back the same number of NULs writes over the
/// old contents instead of reallocating.
fn scrub_in_place(text: &mut String) {
    let len = text.len();
    text.clear();
    for _ in 0..len {
        text.push('\0');
    }
    text.clear();
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CredentialError {
    #[error("the provider credential {0} is not configured")]
    Absent(String),
    #[error("the provider credential {0} is configured but empty")]
    Blank(String),
}

/// Resolves a credential reference. `env:NAME` reads the daemon's own
/// environment; `store:REF` is looked up by the closure the daemon
/// supplies (its secret table). The reference itself is safe to log; the
/// result is not.
pub fn resolve(
    reference: &CredentialRef,
    from_store: impl FnOnce(&str) -> Option<String>,
) -> Result<Credential, CredentialError> {
    let (name, raw) = match reference {
        CredentialRef::Env(name) => (
            format!("env:{name}"),
            std::env::var(name).ok().filter(|v| !v.is_empty()),
        ),
        CredentialRef::Store(reference) => (
            format!("store:{reference}"),
            from_store(reference).filter(|v| !v.is_empty()),
        ),
    };
    let credential = Credential::new(&raw.ok_or_else(|| CredentialError::Absent(name.clone()))?);
    if credential.is_empty() {
        return Err(CredentialError::Blank(name));
    }
    Ok(credential)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_reveals_the_secret() {
        let credential = Credential::new("sk-ant-super-secret");
        let rendered = format!("{credential:?}");
        assert_eq!(rendered, "Credential(redacted, 19 bytes)");
        assert!(!rendered.contains("sk-ant"));
        // The one explicit exit still works.
        assert_eq!(credential.expose(), "sk-ant-super-secret");
    }

    #[test]
    fn a_trailing_newline_is_trimmed() {
        assert_eq!(Credential::new("sk-value\n").expose(), "sk-value");
        assert!(Credential::new("   \n").is_empty());
    }

    #[test]
    fn an_env_reference_resolves_and_an_absent_one_fails_closed() {
        let name = "KOVEE_TEST_BROKER_KEY_RESOLVE";
        std::env::set_var(name, "sk-from-env");
        let credential = resolve(&CredentialRef::Env(name.to_owned()), |_| None).unwrap();
        assert_eq!(credential.expose(), "sk-from-env");
        std::env::remove_var(name);
        assert_eq!(
            resolve(&CredentialRef::Env(name.to_owned()), |_| None).unwrap_err(),
            CredentialError::Absent(format!("env:{name}"))
        );
        // Configured-but-empty is an absence, not a blank credential to send.
        std::env::set_var(name, "");
        assert!(matches!(
            resolve(&CredentialRef::Env(name.to_owned()), |_| None).unwrap_err(),
            CredentialError::Absent(_)
        ));
        std::env::remove_var(name);
    }

    #[test]
    fn a_store_reference_resolves_through_the_daemons_lookup() {
        let credential = resolve(&CredentialRef::Store("cred-1".to_owned()), |reference| {
            (reference == "cred-1").then(|| "sk-from-store".to_owned())
        })
        .unwrap();
        assert_eq!(credential.expose(), "sk-from-store");
        assert_eq!(
            resolve(&CredentialRef::Store("cred-2".to_owned()), |_| None).unwrap_err(),
            CredentialError::Absent("store:cred-2".to_owned())
        );
    }

    #[test]
    fn a_credential_reference_is_only_a_reference() {
        assert_eq!(
            CredentialRef::parse("env:ANTHROPIC_API_KEY"),
            Some(CredentialRef::Env("ANTHROPIC_API_KEY".to_owned()))
        );
        assert_eq!(
            CredentialRef::parse("store:cred-1"),
            Some(CredentialRef::Store("cred-1".to_owned()))
        );
        // A bare secret is not a reference, so it can never be recorded.
        assert_eq!(CredentialRef::parse("sk-ant-oops"), None);
        assert_eq!(CredentialRef::parse("env:"), None);
        assert_eq!(CredentialRef::parse(""), None);
    }
}
