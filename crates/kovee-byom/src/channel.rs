//! byom's peer-bound channel proofs, from the CLIENT side (byom BY-C1,
//! `byom/crates/byomd/src/channel.rs`): the candidate and participant
//! surfaces authenticate with a per-call MAC, never with the bytes of the
//! credential file.
//!
//! What you write (the whole client side):
//! ```no_run
//! use kovee_byom::channel::Channel;
//! # fn f(run_dir: &std::path::Path, channels: &std::path::Path) -> Result<(), kovee_byom::channel::ChannelError> {
//! // ONE claim per process; byomd observes this connection's peer and
//! // hands back a proof key that is useless in any other process.
//! let channel = Channel::participant(run_dir, channels, "part-agent-1")?;
//! // then one fresh proof per call, bound to the exact operation
//! let preamble = channel.proof("episode_request", 1_800_000_000)?;
//! # let _ = preamble; Ok(()) }
//! ```
//!
//! Plumbing (byom's construction, mirrored exactly — Kovee re-derives it
//! independently rather than linking byomd, so agreement is a machine
//! check across two implementations):
//!
//! - the credential FILE is `bpk1.<hex JSON {channel_id, audience,
//!   scope_ref, binding_ref, fence_epoch}>` and carries NO key material;
//! - the CLAIM is one connection to the audience's socket carrying only
//!   `bpb1.<channel_id>`, answered with `result.proof_key` — this
//!   process's peer-bound key;
//! - the PROOF is `bpx1.<channel_id>.<nonce>.<issued_at>.<mac>` where the
//!   mac is HMAC-SHA-256 over `tagged("bpp-channel-proof-v0", {audience,
//!   channel_id, scope_ref, operation, binding_ref, fence_epoch,
//!   peer_pid, peer_process_start, nonce, issued_at})`;
//! - each nonce is spent once and a proof is accepted within 120 seconds
//!   of issue, so the key is kept and the proof is minted per call.

use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::UnixStream;
use std::path::Path;

use kovee_core::family::{hex, hmac_sha256, tagged_canonical};
use serde_json::{json, Value};

/// The credential-file tag.
pub const CREDENTIAL_PREFIX: &str = "bpk1.";
/// The claim-line tag (the whole claim protocol).
pub const CLAIM_PREFIX: &str = "bpb1.";
/// The presented-proof tag.
pub const PROOF_PREFIX: &str = "bpx1.";
/// The proof domain tag.
const PROOF_TAG: &str = "bpp-channel-proof-v0";

/// byom's two channel audiences.
pub const AUDIENCE_CANDIDATE: &str = "candidate";
pub const AUDIENCE_PARTICIPANT: &str = "participant";

#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    #[error("no byom channel credential at {0}")]
    NoCredential(String),
    #[error("{0} is not a byom channel credential file")]
    Malformed(String),
    #[error("byom refused the channel claim: {0}")]
    Refused(String),
    #[error("byom channel transport: {0}")]
    Transport(String),
    #[error("the channel proof could not be minted")]
    Unmintable,
}

/// The PUBLIC binding a credential file names. No key material: a copy of
/// the file mints nothing (BY-C1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    pub channel_id: String,
    pub audience: String,
    pub scope_ref: String,
    pub binding_ref: String,
    pub fence_epoch: u64,
}

/// Parses a credential file line.
pub fn parse_credential(line: &str) -> Option<Credential> {
    let body = line.trim().strip_prefix(CREDENTIAL_PREFIX)?;
    if body.len() % 2 != 0 {
        return None;
    }
    let bytes: Option<Vec<u8>> = (0..body.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(body.get(i..i + 2)?, 16).ok())
        .collect();
    let value: Value = serde_json::from_slice(&bytes?).ok()?;
    Some(Credential {
        channel_id: value["channel_id"].as_str()?.to_owned(),
        audience: value["audience"].as_str()?.to_owned(),
        scope_ref: value["scope_ref"].as_str()?.to_owned(),
        binding_ref: value["binding_ref"].as_str()?.to_owned(),
        fence_epoch: value["fence_epoch"].as_u64()?,
    })
}

/// The observed peer of one connection: what a proof is bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Peer {
    pub pid: i32,
    /// The kernel start time (`/proc/<pid>/stat` field 22) — pins the
    /// exact process, not a recycled pid.
    pub process_start: u64,
}

impl Peer {
    /// The peer of THIS process (what a client binds its own proof to).
    pub fn current() -> Peer {
        let pid = std::process::id() as i32;
        Peer {
            pid,
            process_start: process_start(pid),
        }
    }
}

/// Reads a process's kernel start time; 0 when unreadable (the binding
/// then rests on the pid alone, still per-process).
pub fn process_start(pid: i32) -> u64 {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return 0;
    };
    // Field 2 (comm) may contain spaces inside parentheses; fields are
    // counted after the closing one.
    let Some((_, rest)) = stat.rsplit_once(')') else {
        return 0;
    };
    rest.split_whitespace()
        .nth(19)
        .and_then(|f| f.parse().ok())
        .unwrap_or(0)
}

/// One claimed channel: the credential line plus the peer-bound proof key
/// byomd issued to THIS process. Claim once, mint one proof per call.
#[derive(Debug, Clone)]
pub struct Channel {
    credential: Credential,
    key: [u8; 32],
    peer: Peer,
}

impl Channel {
    /// Claims the channel named by `credential_line` over byomd's socket
    /// directory.
    pub fn open(run_dir: &Path, credential_line: &str) -> Result<Channel, ChannelError> {
        let credential = parse_credential(credential_line)
            .ok_or_else(|| ChannelError::Malformed(credential_line.chars().take(12).collect()))?;
        let key = claim(run_dir, &credential)?;
        Ok(Channel {
            credential,
            key,
            peer: Peer::current(),
        })
    }

    /// The participant channel byomd publishes for one admitted
    /// Participant (`channels/participant-<ref>.token`).
    pub fn participant(
        run_dir: &Path,
        channels_dir: &Path,
        participant_ref: &str,
    ) -> Result<Channel, ChannelError> {
        Channel::from_file(
            run_dir,
            &channels_dir.join(format!("participant-{participant_ref}.token")),
        )
    }

    /// The candidate channel byomd publishes for one open offer.
    pub fn candidate(
        run_dir: &Path,
        channels_dir: &Path,
        offer_ref: &str,
    ) -> Result<Channel, ChannelError> {
        Channel::from_file(
            run_dir,
            &channels_dir.join(format!("candidate-{offer_ref}.token")),
        )
    }

    pub fn from_file(run_dir: &Path, path: &Path) -> Result<Channel, ChannelError> {
        let line = std::fs::read_to_string(path)
            .map_err(|_| ChannelError::NoCredential(path.display().to_string()))?;
        Channel::open(run_dir, line.trim())
    }

    pub fn channel_id(&self) -> &str {
        &self.credential.channel_id
    }

    /// One fresh proof for the exact operation.
    pub fn proof(&self, operation: &str, now: i64) -> Result<String, ChannelError> {
        mint_proof(
            &self.credential,
            &self.key,
            operation,
            self.peer,
            &nonce(),
            now,
        )
        .ok_or(ChannelError::Unmintable)
    }
}

/// The client half of a claim: one connection carrying only
/// `bpb1.<channel_id>`, answered with this process's proof key.
fn claim(run_dir: &Path, credential: &Credential) -> Result<[u8; 32], ChannelError> {
    let surface = match credential.audience.as_str() {
        AUDIENCE_CANDIDATE => AUDIENCE_CANDIDATE,
        _ => AUDIENCE_PARTICIPANT,
    };
    let path = run_dir.join(format!("{surface}.sock"));
    let mut stream = UnixStream::connect(&path).map_err(|e| {
        ChannelError::Transport(format!("claim {}: {e} (is byomd running?)", path.display()))
    })?;
    stream
        .write_all(format!("{CLAIM_PREFIX}{}\n", credential.channel_id).as_bytes())
        .map_err(|e| ChannelError::Transport(e.to_string()))?;
    let mut reply = String::new();
    BufReader::new(stream)
        .read_line(&mut reply)
        .map_err(|e| ChannelError::Transport(e.to_string()))?;
    let parsed: Value = serde_json::from_str(reply.trim_end())
        .map_err(|e| ChannelError::Refused(format!("unusable claim reply: {e}")))?;
    if parsed["outcome"] != "ok" {
        return Err(ChannelError::Refused(parsed.to_string()));
    }
    parsed["result"]["proof_key"]
        .as_str()
        .and_then(unhex32)
        .ok_or_else(|| ChannelError::Refused(format!("claim reply carries no proof key: {parsed}")))
}

/// The canonical proof preimage — identical on both sides.
#[allow(clippy::too_many_arguments)]
fn preimage(
    credential: &Credential,
    operation: &str,
    peer: Peer,
    nonce: &str,
    issued_at: i64,
) -> Option<Vec<u8>> {
    tagged_canonical(
        PROOF_TAG,
        &json!({
            "audience": credential.audience,
            "channel_id": credential.channel_id,
            "scope_ref": credential.scope_ref,
            "operation": operation,
            "binding_ref": credential.binding_ref,
            "fence_epoch": credential.fence_epoch,
            "peer_pid": peer.pid,
            "peer_process_start": peer.process_start,
            "nonce": nonce,
            "issued_at": issued_at,
        }),
    )
    .ok()
}

/// Mints one proof for the exact call.
pub fn mint_proof(
    credential: &Credential,
    key: &[u8; 32],
    operation: &str,
    peer: Peer,
    nonce: &str,
    now: i64,
) -> Option<String> {
    let bytes = preimage(credential, operation, peer, nonce, now)?;
    Some(format!(
        "{PROOF_PREFIX}{}.{nonce}.{now}.{}",
        credential.channel_id,
        hex(&hmac_sha256(key, &bytes))
    ))
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// A fresh proof nonce (hex over OS entropy).
pub fn nonce() -> String {
    let mut bytes = [0u8; 16];
    let read = std::fs::File::open("/dev/urandom")
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut bytes));
    if read.is_err() {
        bytes.copy_from_slice(&(kovee_core::time::unix_now() as u128).to_be_bytes());
    }
    hex(&bytes)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn credential_line(channel_id: &str, audience: &str) -> String {
        let body = json!({
            "channel_id": channel_id,
            "audience": audience,
            "scope_ref": "offer-1",
            "binding_ref": "manif-1",
            "fence_epoch": 1,
        })
        .to_string();
        format!("{CREDENTIAL_PREFIX}{}", hex(body.as_bytes()))
    }

    #[test]
    fn a_credential_file_carries_the_binding_and_no_key_material() {
        let line = credential_line("chan-1", AUDIENCE_PARTICIPANT);
        let credential = parse_credential(&line).unwrap();
        assert_eq!(credential.channel_id, "chan-1");
        assert_eq!(credential.audience, AUDIENCE_PARTICIPANT);
        assert_eq!(credential.fence_epoch, 1);
        // Never frames as a request: the preamble line cannot be read as
        // the operation body.
        assert!(!line.starts_with('{'));
        assert!(parse_credential("not-a-credential").is_none());
    }

    #[test]
    fn a_proof_is_bound_to_its_peer_operation_and_nonce() {
        let credential = parse_credential(&credential_line("chan-1", AUDIENCE_CANDIDATE)).unwrap();
        let key = [3u8; 32];
        let peer = Peer {
            pid: 4242,
            process_start: 99,
        };
        let nonce = "ab".repeat(8);
        let mine = mint_proof(
            &credential,
            &key,
            "membership_accept",
            peer,
            &nonce,
            1_700_000_000,
        )
        .unwrap();
        assert!(mine.starts_with(&format!("{PROOF_PREFIX}chan-1.")));
        // Another same-UID process is a different peer, so the daemon
        // recomputes a different MAC.
        let other = Peer {
            pid: 4243,
            process_start: 99,
        };
        assert_ne!(
            mine,
            mint_proof(
                &credential,
                &key,
                "membership_accept",
                other,
                &nonce,
                1_700_000_000
            )
            .unwrap()
        );
        // A different operation is a different proof.
        assert_ne!(
            mine,
            mint_proof(
                &credential,
                &key,
                "membership_refuse",
                peer,
                &nonce,
                1_700_000_000
            )
            .unwrap()
        );
        // And a different nonce is a different proof (each spent once).
        assert_ne!(
            mine,
            mint_proof(
                &credential,
                &key,
                "membership_accept",
                peer,
                &"cd".repeat(8),
                1_700_000_000
            )
            .unwrap()
        );
    }

    #[test]
    fn the_current_peer_names_this_process() {
        let peer = Peer::current();
        assert_eq!(peer.pid, std::process::id() as i32);
        assert!(peer.process_start > 0, "/proc start time is readable");
    }

    #[test]
    fn a_nonce_is_fresh_hex() {
        let a = nonce();
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(a, nonce());
    }
}
