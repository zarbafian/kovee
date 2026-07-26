//! Per-object erasure secrets, wrapped under the realm (Society) key —
//! the `local_erasure_safe` construction of family PROFILE §6.1 as
//! disposition D-R1-2 requires it: a **random** secret per object,
//! **wrapped** under the realm key, **individually destroyable**.
//!
//! A root-derived deterministic per-object key is the forbidden scope-key
//! substitution: erasing one object could not destroy that object's
//! verifiability, and destroying the root would destroy every object's.
//! Here the object's own randomness is the secret; the realm key only
//! protects the stored copy. Destroying one wrapped blob (`NULL`ing the
//! column) erases exactly that object's verifiability and touches no
//! other object.
//!
//! What you write (one object's erasure secret, minted and destroyed):
//! ```
//! use kovee_store::objkey;
//! let realm_key = [9u8; 32];
//! let key_ref = "kovee-contribution-object:contrib-1";
//! let secret = objkey::new_object_secret().unwrap();
//! let wrapped = objkey::wrap(&realm_key, key_ref, &secret).unwrap();
//! assert_eq!(objkey::unwrap(&realm_key, key_ref, &wrapped).unwrap(), secret);
//! // The wrap is bound to the object: another object's ref cannot open it.
//! assert!(objkey::unwrap(&realm_key, "kovee-contribution-object:contrib-2", &wrapped).is_err());
//! // Erasure is deleting the wrapped bytes — nothing else is affected.
//! ```

use crate::StoreError;

/// The wrap format marker: `kow1` ‖ nonce(16) ‖ ct(32) ‖ tag(32).
const MAGIC: &[u8; 4] = b"kow1";
const NONCE_LEN: usize = 16;
const SECRET_LEN: usize = 32;
const TAG_LEN: usize = 32;
/// Total wrapped length: 4 + 16 + 32 + 32.
pub const WRAPPED_LEN: usize = MAGIC.len() + NONCE_LEN + SECRET_LEN + TAG_LEN;

const KEYSTREAM_DOMAIN: &[u8] = b"kovee-object-key-wrap/v1";
const TAG_DOMAIN: &[u8] = b"kovee-object-key-wrap-tag/v1";

/// A fresh random per-object secret (32 bytes of OS entropy).
pub fn new_object_secret() -> Result<[u8; SECRET_LEN], StoreError> {
    let mut secret = [0u8; SECRET_LEN];
    crate::fill_random(&mut secret)?;
    Ok(secret)
}

fn framed(domain: &[u8], key_ref: &str, tail: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(domain.len() + key_ref.len() + tail.len() + 24);
    out.extend_from_slice(&(domain.len() as u64).to_be_bytes());
    out.extend_from_slice(domain);
    out.extend_from_slice(&(key_ref.len() as u64).to_be_bytes());
    out.extend_from_slice(key_ref.as_bytes());
    out.extend_from_slice(&(tail.len() as u64).to_be_bytes());
    out.extend_from_slice(tail);
    out
}

/// Wraps one per-object secret under the realm key, bound to `key_ref`.
pub fn wrap(
    realm_key: &[u8],
    key_ref: &str,
    secret: &[u8; SECRET_LEN],
) -> Result<Vec<u8>, StoreError> {
    let mut nonce = [0u8; NONCE_LEN];
    crate::fill_random(&mut nonce)?;
    let keystream =
        kovee_core::family::hmac_sha256(realm_key, &framed(KEYSTREAM_DOMAIN, key_ref, &nonce));
    let mut ct = [0u8; SECRET_LEN];
    for i in 0..SECRET_LEN {
        ct[i] = secret[i] ^ keystream[i];
    }
    let mut tag_input = Vec::with_capacity(NONCE_LEN + SECRET_LEN);
    tag_input.extend_from_slice(&nonce);
    tag_input.extend_from_slice(&ct);
    let tag = kovee_core::family::hmac_sha256(realm_key, &framed(TAG_DOMAIN, key_ref, &tag_input));
    let mut out = Vec::with_capacity(WRAPPED_LEN);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Unwraps a secret wrapped by [`wrap`] for the exact same `key_ref`. A
/// blob for another object, another realm key, or altered bytes fails.
pub fn unwrap(
    realm_key: &[u8],
    key_ref: &str,
    wrapped: &[u8],
) -> Result<[u8; SECRET_LEN], StoreError> {
    let broken = || StoreError::Corrupt("object secret is not an openable wrap".to_owned());
    if wrapped.len() != WRAPPED_LEN || !wrapped.starts_with(MAGIC) {
        return Err(broken());
    }
    let nonce = &wrapped[4..4 + NONCE_LEN];
    let ct = &wrapped[4 + NONCE_LEN..4 + NONCE_LEN + SECRET_LEN];
    let tag = &wrapped[4 + NONCE_LEN + SECRET_LEN..];
    let mut tag_input = Vec::with_capacity(NONCE_LEN + SECRET_LEN);
    tag_input.extend_from_slice(nonce);
    tag_input.extend_from_slice(ct);
    let expected =
        kovee_core::family::hmac_sha256(realm_key, &framed(TAG_DOMAIN, key_ref, &tag_input));
    // Constant-time-shaped compare (no early exit on the first difference).
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(tag) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return Err(broken());
    }
    let keystream =
        kovee_core::family::hmac_sha256(realm_key, &framed(KEYSTREAM_DOMAIN, key_ref, nonce));
    let mut secret = [0u8; SECRET_LEN];
    for i in 0..SECRET_LEN {
        secret[i] = ct[i] ^ keystream[i];
    }
    Ok(secret)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_wrap_round_trips_and_is_bound_to_its_object() {
        let realm_key = [3u8; 32];
        let secret = new_object_secret().unwrap();
        let wrapped = wrap(&realm_key, "obj:a", &secret).unwrap();
        assert_eq!(wrapped.len(), WRAPPED_LEN);
        assert_eq!(unwrap(&realm_key, "obj:a", &wrapped).unwrap(), secret);
        // Another object's key_ref, another realm key, tampered bytes.
        assert!(unwrap(&realm_key, "obj:b", &wrapped).is_err());
        assert!(unwrap(&[4u8; 32], "obj:a", &wrapped).is_err());
        let mut tampered = wrapped.clone();
        tampered[10] ^= 0xff;
        assert!(unwrap(&realm_key, "obj:a", &tampered).is_err());
    }

    #[test]
    fn two_objects_get_independent_random_secrets() {
        let realm_key = [5u8; 32];
        let a = new_object_secret().unwrap();
        let b = new_object_secret().unwrap();
        assert_ne!(a, b, "per-object secrets are random, never root-derived");
        // The same secret under two refs wraps to different bytes, and
        // destroying one wrap leaves the other openable.
        let wa = wrap(&realm_key, "obj:a", &a).unwrap();
        let wb = wrap(&realm_key, "obj:b", &b).unwrap();
        assert_ne!(wa, wb);
        drop(wa);
        assert_eq!(unwrap(&realm_key, "obj:b", &wb).unwrap(), b);
    }
}
