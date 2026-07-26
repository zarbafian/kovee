//! byom's RUNTIME surface (registry bundle B0.4, R30/R33/R35): the
//! Episode lease operations, the narrow Kovee placement adapter, and the
//! measured-meter settlement — each authenticated by a byomd-MINTED,
//! subject-scoped workload token in the transport preamble.
//!
//! What you write (one runtime call, end to end):
//! ```no_run
//! use kovee_byom::bpp::Endpoint;
//! use kovee_byom::runtime::{self, Workload};
//! # fn f(channels: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
//! let endpoint = Endpoint::local("local");
//! // The token is byomd's, read from its channel directory — never chosen
//! // by Kovee, and bound to ONE exact subject.
//! let worker = runtime::token(channels, Workload::Worker, "ep-1")?;
//! let reply = runtime::call(&endpoint, &worker, &serde_json::json!({
//!     "version": "0.2", "op": "episode_start", "meta": { /* … */ },
//!     "episode_ref": "ep-1", "generation": 1,
//!     "byom_attempt_ref": "att-1", "byom_fence_epoch": 1,
//!     "kovee_invocation_fence": 1,
//! }))?;
//! # let _ = reply; Ok(()) }
//! ```
//!
//! Plumbing worth knowing:
//!
//! - **Three channels, three classes.** The worker channel
//!   (`rwk1.`) is bound to one exact `episode|generation` and carries
//!   claim/start/checkpoint/yield/complete/fail plus worker usage
//!   EVIDENCE; the meter channel (`rmt1.`) is the only one whose
//!   `usage_report` may SETTLE; the placement channel (`rpl1.`) is bound
//!   to one exact `ResourceAllocation` and carries only
//!   `placement_admit`. The separation is byomd's — presenting the wrong
//!   class is `forbidden` there — and [`token`] refuses the wrong class
//!   here too, so a mix-up is caught before a byte is sent.
//! - **Nothing is derivable client-side.** The token is
//!   `hmac(byomd store key, "<class>|<subject>")`; Kovee reads the file
//!   byomd published `0600` in its channel directory and presents it
//!   verbatim. There is no Kovee-side minting path, by construction.
//! - **A terminal subject has no file.** byomd removes the token when the
//!   Episode or the allocation leaves its live states, so a missing token
//!   is a *state* answer, not a configuration one.

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::bpp::{BppError, Endpoint, Surface};

/// The narrow runtime channels of byom's B0.4 bundle that Kovee speaks on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Workload {
    /// One exact Episode attempt: claim, start, checkpoint, yield,
    /// complete, fail, worker usage evidence, effect-outcome admission.
    Worker,
    /// The narrow TRUSTED METER adapter: the only channel whose
    /// `usage_report` may settle (§11.4, family contract L33).
    Meter,
    /// One exact `ResourceAllocation`: `placement_admit` only.
    Placement,
    /// The TRUSTED HOST EFFECT SERVICE bound to one exact prepared act
    /// (byom R34): the only channel that may call
    /// `execution_permit_consume`. Its subject is the ActIntent id, so a
    /// permit token is unusable for any other act — which makes "the model
    /// broker cannot consume another act's authority" a transport fact
    /// rather than a code review.
    Permit,
}

impl Workload {
    /// byomd's channel-class tag (also the token file's infix).
    pub fn tag(self) -> &'static str {
        match self {
            Workload::Worker => "worker",
            Workload::Meter => "meter",
            Workload::Placement => "placement",
            Workload::Permit => "permit",
        }
    }

    /// byomd's wire prefix for this channel class.
    pub fn prefix(self) -> &'static str {
        match self {
            Workload::Worker => "rwk1.",
            Workload::Meter => "rmt1.",
            Workload::Placement => "rpl1.",
            Workload::Permit => "rpm1.",
        }
    }

    /// The file byomd publishes for one subject: the Episode id for the
    /// worker and meter channels, the allocation id for the placement one,
    /// and the ActIntent id for the permit one.
    pub fn token_file(self, subject: &str) -> String {
        format!("runtime-{}-{subject}.token", self.tag())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("byomd published no {class} workload token for {subject} (looked in {path})")]
    Absent {
        class: &'static str,
        subject: String,
        path: String,
    },
    #[error("the token at {path} is not a byom {class} workload token")]
    WrongClass { class: &'static str, path: String },
    #[error("no byom channel directory is configured (set $KOVEE_BYOM_CHANNELS_DIR)")]
    NoChannelDir,
}

/// One byomd-minted workload token, presented verbatim as the preamble.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadToken {
    channel: Workload,
    subject: String,
    line: String,
}

impl WorkloadToken {
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// The transport preamble line.
    pub fn preamble(&self) -> &str {
        &self.line
    }
}

/// byomd's channel directory, from `$KOVEE_BYOM_CHANNELS_DIR` — the same
/// resolution the R42 recovery-workload token uses.
pub fn channels_dir() -> Result<PathBuf, TokenError> {
    std::env::var_os("KOVEE_BYOM_CHANNELS_DIR")
        .filter(|d| !d.is_empty())
        .map(PathBuf::from)
        .ok_or(TokenError::NoChannelDir)
}

/// Reads the byomd-minted token for one exact subject and channel class.
/// A token of another class never passes: the class prefix is checked
/// before the line is ever sent.
pub fn token(
    channels_dir: &Path,
    channel: Workload,
    subject: &str,
) -> Result<WorkloadToken, TokenError> {
    let path = channels_dir.join(channel.token_file(subject));
    let line = std::fs::read_to_string(&path)
        .map(|t| t.trim().to_owned())
        .ok()
        .filter(|t| !t.is_empty())
        .ok_or_else(|| TokenError::Absent {
            class: channel.tag(),
            subject: subject.to_owned(),
            path: path.display().to_string(),
        })?;
    if !line.starts_with(channel.prefix()) {
        return Err(TokenError::WrongClass {
            class: channel.tag(),
            path: path.display().to_string(),
        });
    }
    Ok(WorkloadToken {
        channel,
        subject: subject.to_owned(),
        line,
    })
}

/// One runtime-surface call under a workload token.
pub fn call(
    endpoint: &Endpoint,
    token: &WorkloadToken,
    request: &Value,
) -> Result<crate::bpp::Reply, BppError> {
    endpoint.call_with_preamble(Surface::Runtime, Some(token.preamble()), request)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "kovee-runtime-token-{tag}-{}-{}",
            std::process::id(),
            kovee_core::time::unix_now()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_channels_are_byoms_own_classes() {
        assert_eq!(Workload::Worker.prefix(), "rwk1.");
        assert_eq!(Workload::Meter.prefix(), "rmt1.");
        assert_eq!(Workload::Placement.prefix(), "rpl1.");
        assert_eq!(Workload::Permit.prefix(), "rpm1.");
        assert_eq!(
            Workload::Worker.token_file("ep-1"),
            "runtime-worker-ep-1.token"
        );
        assert_eq!(
            Workload::Placement.token_file("alloc-1"),
            "runtime-placement-alloc-1.token"
        );
        // The permit channel's subject is the ACT, not the Episode.
        assert_eq!(
            Workload::Permit.token_file("actint-1"),
            "runtime-permit-actint-1.token"
        );
    }

    #[test]
    fn a_token_of_another_class_never_passes() {
        let dir = dir("class");
        std::fs::write(dir.join("runtime-worker-ep-1.token"), "rwk1.aabb\n").unwrap();
        // The meter file holds a WORKER token: the class check refuses it
        // before the line reaches byomd.
        std::fs::write(dir.join("runtime-meter-ep-1.token"), "rwk1.aabb\n").unwrap();
        let worker = token(&dir, Workload::Worker, "ep-1").unwrap();
        assert_eq!(worker.preamble(), "rwk1.aabb");
        assert_eq!(worker.subject(), "ep-1");
        assert!(matches!(
            token(&dir, Workload::Meter, "ep-1"),
            Err(TokenError::WrongClass { .. })
        ));
    }

    #[test]
    fn a_terminal_subject_has_no_token_and_that_is_a_state_answer() {
        let dir = dir("absent");
        assert!(matches!(
            token(&dir, Workload::Worker, "ep-gone"),
            Err(TokenError::Absent { .. })
        ));
        // An empty file is not a token either.
        std::fs::write(dir.join("runtime-worker-ep-empty.token"), "\n").unwrap();
        assert!(matches!(
            token(&dir, Workload::Worker, "ep-empty"),
            Err(TokenError::Absent { .. })
        ));
    }
}
