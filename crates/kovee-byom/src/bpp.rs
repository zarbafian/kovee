//! The Byom Participation Protocol client: one per-surface Unix-domain
//! connection to `byomd`, byom's own request/reply framing, and problem
//! passthrough.
//!
//! What you write:
//! ```no_run
//! use kovee_byom::bpp::{Endpoint, Surface};
//! let endpoint = Endpoint::local("local");
//! let hello = endpoint.hello(Surface::Governance)?;
//! println!("byomd incarnation {}", hello.endpoint_incarnation);
//! # Ok::<(), kovee_byom::bpp::BppError>(())
//! ```
//!
//! Plumbing (byom's wire, not kovee's — the two protocols never nest,
//! family contract L9):
//!
//! - one newline-terminated JSON request per connection; byomd writes one
//!   reply line and closes, so every call reconnects;
//! - the envelope is `{version, op, meta?}` with the operation arguments
//!   at the TOP LEVEL of the same object — byom has no `args` member;
//! - `version` is byom's `0.2`, never kovee's `0.1`;
//! - reads carry no `meta`; creates carry `meta` without
//!   `expected_revision`; updates carry it with one;
//! - the failure arm is `{"outcome":"problem","problem":{…}}` whose
//!   `type` is `https://byom.dev/problems/<snake_kind>` — explicitly NOT
//!   substitutable with kovee's `urn:kovee:error:<kebab-kind>`;
//! - the governance and projection sockets take no token preamble.

use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use kovee_core::problem::{Problem, ProblemKind};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The one BPP version this adapter speaks (byom §14.1).
pub const BPP_VERSION: &str = "0.2";

/// The byom problem-type prefix. Kovee's own prefix is
/// `urn:kovee:error:`; a byom problem is passed through, never renamed
/// into a kovee kind without the explicit table below.
pub const BYOM_PROBLEM_PREFIX: &str = "https://byom.dev/problems/";

/// How long a single BPP call may block before it is `unavailable`.
const CALL_TIMEOUT: Duration = Duration::from_secs(20);

/// One byomd authority surface — one socket file each (byom §14.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Surface {
    Governance,
    Candidate,
    Participant,
    Projection,
}

impl Surface {
    pub fn socket_file(self) -> &'static str {
        match self {
            Surface::Governance => "governance.sock",
            Surface::Candidate => "candidate.sock",
            Surface::Participant => "participant.sock",
            Surface::Projection => "projection.sock",
        }
    }

    /// Whether this surface reads a token preamble line before the
    /// request. Governance and projection never do; writing a preamble
    /// there makes byomd parse the token AS the request.
    pub fn takes_preamble(self) -> bool {
        matches!(self, Surface::Candidate | Surface::Participant)
    }
}

/// One byomd endpoint: the `byom_endpoint_ref` a `KoveeRealmByomBinding`
/// names, plus the directory its sockets live in.
#[derive(Debug, Clone)]
pub struct Endpoint {
    endpoint_ref: String,
    runtime_dir: PathBuf,
}

impl Endpoint {
    /// The locally configured byomd (`kovee governance enable --byom
    /// local`): socket directory from `$KOVEE_BYOM_RUNTIME_DIR`, else
    /// `$BYOM_RUNTIME_DIR`, else `$XDG_RUNTIME_DIR/byom`, else
    /// `$TMPDIR/byom-<uid>` — byomd's own resolution order.
    pub fn local(endpoint_ref: &str) -> Endpoint {
        Endpoint {
            endpoint_ref: endpoint_ref.to_owned(),
            runtime_dir: default_runtime_dir(),
        }
    }

    pub fn at(endpoint_ref: &str, runtime_dir: &Path) -> Endpoint {
        Endpoint {
            endpoint_ref: endpoint_ref.to_owned(),
            runtime_dir: runtime_dir.to_path_buf(),
        }
    }

    pub fn endpoint_ref(&self) -> &str {
        &self.endpoint_ref
    }

    pub fn socket_path(&self, surface: Surface) -> PathBuf {
        self.runtime_dir.join(surface.socket_file())
    }

    /// One request line to one reply line, on this surface's socket.
    pub fn call(&self, surface: Surface, request: &Value) -> Result<Reply, BppError> {
        let path = self.socket_path(surface);
        let mut stream = UnixStream::connect(&path)
            .map_err(|e| BppError::Transport(format!("connect {}: {e}", path.display())))?;
        stream
            .set_read_timeout(Some(CALL_TIMEOUT))
            .and_then(|()| stream.set_write_timeout(Some(CALL_TIMEOUT)))
            .map_err(|e| BppError::Transport(e.to_string()))?;
        let mut line = serde_json::to_string(request)
            .map_err(|e| BppError::Malformed(format!("request is not JSON: {e}")))?;
        line.push('\n');
        stream
            .write_all(line.as_bytes())
            .map_err(|e| BppError::Transport(e.to_string()))?;
        let mut reply = String::new();
        BufReader::new(stream)
            .read_line(&mut reply)
            .map_err(|e| BppError::Transport(e.to_string()))?;
        if reply.trim().is_empty() {
            // byomd drops a foreign-UID connection before reading a byte,
            // and a crash mid-request looks the same: no reply line.
            return Err(BppError::Transport(
                "byomd closed the connection without a reply".to_owned(),
            ));
        }
        let parsed: Value = serde_json::from_str(reply.trim_end())
            .map_err(|e| BppError::Malformed(format!("reply is not JSON: {e}")))?;
        Reply::from_value(&parsed)
    }

    /// `hello` on one surface: the negotiated versions and — the field
    /// every binding pins — the endpoint incarnation.
    pub fn hello(&self, surface: Surface) -> Result<Hello, BppError> {
        let reply = self.call(
            surface,
            &serde_json::json!({"version": BPP_VERSION, "op": "hello"}),
        )?;
        let hello: Hello = serde_json::from_value(reply.result)
            .map_err(|e| BppError::Malformed(format!("hello result: {e}")))?;
        if !hello.versions.iter().any(|v| v == BPP_VERSION) {
            return Err(BppError::VersionMismatch {
                offered: hello.versions.join(","),
            });
        }
        Ok(hello)
    }
}

fn default_runtime_dir() -> PathBuf {
    for key in ["KOVEE_BYOM_RUNTIME_DIR", "BYOM_RUNTIME_DIR"] {
        if let Some(dir) = std::env::var_os(key) {
            if !dir.is_empty() {
                return PathBuf::from(dir);
            }
        }
    }
    match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(rt) if !rt.is_empty() => PathBuf::from(rt).join("byom"),
        _ => std::env::temp_dir().join(format!("byom-{}", current_uid())),
    }
}

fn current_uid() -> u32 {
    // SAFETY: geteuid is always safe and cannot fail (the koveed
    // `peercred` module makes the same call under the same allowance).
    #[allow(unsafe_code)]
    unsafe {
        libc::geteuid()
    }
}

/// byom's `hello` result (§14.1/§14.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub versions: Vec<String>,
    pub surface: String,
    pub endpoint_incarnation: String,
}

/// byom's success envelope (§14.2).
#[derive(Debug, Clone, PartialEq)]
pub struct Reply {
    pub result: Value,
    pub revision: Option<u64>,
    pub source_cursor: Option<String>,
}

impl Reply {
    fn from_value(parsed: &Value) -> Result<Reply, BppError> {
        match parsed.get("outcome").and_then(Value::as_str) {
            Some("ok") => Ok(Reply {
                result: parsed.get("result").cloned().unwrap_or(Value::Null),
                revision: parsed.get("revision").and_then(Value::as_u64),
                source_cursor: parsed
                    .get("source_cursor")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            }),
            Some("problem") => Err(BppError::Problem(ByomProblem::from_value(
                parsed.get("problem").unwrap_or(&Value::Null),
            ))),
            _ => Err(BppError::Malformed("reply carries no outcome".to_owned())),
        }
    }
}

/// One byom problem, carried verbatim. Kovee never re-owns byom's
/// semantics: the kind string stays byom's `snake_case` token and the
/// type stays byom's URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByomProblem {
    pub type_uri: String,
    pub kind: String,
    pub title: String,
    pub status: Option<u16>,
    pub detail: Option<String>,
}

impl ByomProblem {
    fn from_value(problem: &Value) -> ByomProblem {
        let text = |key: &str| {
            problem
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .unwrap_or_default()
        };
        let type_uri = text("type");
        let kind = match problem.get("kind").and_then(Value::as_str) {
            Some(k) => k.to_owned(),
            // Derive from the type URI when the arm omits `kind`.
            None => type_uri
                .strip_prefix(BYOM_PROBLEM_PREFIX)
                .unwrap_or_default()
                .to_owned(),
        };
        ByomProblem {
            type_uri,
            kind,
            title: text("title"),
            status: problem
                .get("status")
                .and_then(Value::as_u64)
                .and_then(|s| u16::try_from(s).ok()),
            detail: problem
                .get("detail")
                .and_then(Value::as_str)
                .map(str::to_owned),
        }
    }

    /// The body-free passthrough detail a KCP client sees: byom's type
    /// and title, never rewritten into kovee vocabulary.
    pub fn passthrough_detail(&self) -> String {
        let mut out = format!("byom problem {}: {}", self.type_uri, self.title);
        if let Some(detail) = &self.detail {
            out.push_str("; ");
            out.push_str(detail);
        }
        out
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BppError {
    /// The socket could not be reached, or byomd closed without a reply —
    /// the CAS outcome is UNKNOWN and the saga may not guess.
    #[error("byom transport: {0}")]
    Transport(String),
    #[error("byom reply: {0}")]
    Malformed(String),
    #[error("byom problem: {}", .0.kind)]
    Problem(ByomProblem),
    #[error("byom offers no common protocol version (offered {offered})")]
    VersionMismatch { offered: String },
}

impl BppError {
    /// Whether this failure is a DEFINITE answer from byomd (a typed
    /// problem: the request was seen, understood, and refused) or an
    /// unknown outcome (transport). Only a definite answer may drive a
    /// saga rollback — guessing is not a transition (greenfield-saga §5).
    pub fn is_definite(&self) -> bool {
        matches!(
            self,
            BppError::Problem(_) | BppError::VersionMismatch { .. }
        )
    }
}

/// The closed byom-kind → kovee-kind passthrough table. Byom's problem is
/// carried in `detail` verbatim; the kovee kind is chosen here and
/// nowhere else, and an unlisted byom kind is conservatively
/// `unavailable` (kovee does not invent a meaning for it).
pub fn passthrough(error: &BppError) -> Problem {
    match error {
        BppError::Transport(detail) => {
            Problem::new(ProblemKind::Unavailable, "the byom endpoint did not answer")
                .with_detail(detail.clone())
        }
        BppError::Malformed(detail) => Problem::new(
            ProblemKind::Unavailable,
            "the byom endpoint answered with an unusable reply",
        )
        .with_detail(detail.clone()),
        BppError::VersionMismatch { offered } => Problem::new(
            ProblemKind::UnsupportedVersion,
            "no common Byom Participation Protocol version",
        )
        .with_detail(format!(
            "byomd offers {offered}, this adapter speaks {BPP_VERSION}"
        )),
        BppError::Problem(p) => {
            let kind = match p.kind.as_str() {
                "invalid" => ProblemKind::Invalid,
                "not_found" => ProblemKind::NotFound,
                "forbidden" => ProblemKind::Forbidden,
                "forbidden_surface" => ProblemKind::ForbiddenSurface,
                "unsupported_version" => ProblemKind::UnsupportedVersion,
                "stale_revision" | "stale_binding" | "stale_assembly_epoch" => {
                    ProblemKind::StaleRevision
                }
                "stale_lease" => ProblemKind::StaleLease,
                "idempotency_mismatch" => ProblemKind::IdempotencyMismatch,
                "budget_exceeded" => ProblemKind::BudgetExceeded,
                "effect_ambiguous" => ProblemKind::Ambiguous,
                "cursor_expired" => ProblemKind::CursorExpired,
                // feature_unavailable, endpoint_sealed, unavailable, and
                // every byom-governance kind kovee does not own.
                _ => ProblemKind::Unavailable,
            };
            Problem::new(kind, "the byom endpoint refused the request")
                .with_detail(p.passthrough_detail())
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn socket_files_are_the_four_byomd_surfaces() {
        assert_eq!(Surface::Governance.socket_file(), "governance.sock");
        assert_eq!(Surface::Projection.socket_file(), "projection.sock");
        // Governance and projection take no token preamble.
        assert!(!Surface::Governance.takes_preamble());
        assert!(!Surface::Projection.takes_preamble());
        assert!(Surface::Participant.takes_preamble());
    }

    #[test]
    fn the_ok_arm_carries_result_revision_and_cursor() {
        let reply = Reply::from_value(&serde_json::json!({
            "outcome": "ok", "result": {"state": "active"},
            "revision": 2, "source_cursor": "bc1.aa.bb",
        }))
        .unwrap();
        assert_eq!(reply.revision, Some(2));
        assert_eq!(reply.result["state"], "active");
    }

    #[test]
    fn a_byom_problem_is_passed_through_never_renamed() {
        let err = Reply::from_value(&serde_json::json!({
            "outcome": "problem",
            "problem": {
                "type": "https://byom.dev/problems/stale_revision",
                "kind": "stale_revision",
                "title": "revision moved",
                "status": 409,
            },
        }))
        .unwrap_err();
        assert!(err.is_definite());
        let problem = passthrough(&err);
        assert_eq!(problem.kind, ProblemKind::StaleRevision);
        let detail = problem.detail.unwrap();
        assert!(detail.contains("https://byom.dev/problems/stale_revision"));
        assert!(detail.contains("revision moved"));
    }

    #[test]
    fn an_unknown_byom_kind_is_conservatively_unavailable() {
        let err = Reply::from_value(&serde_json::json!({
            "outcome": "problem",
            "problem": {
                "type": "https://byom.dev/problems/mandate_held",
                "kind": "mandate_held", "title": "held",
            },
        }))
        .unwrap_err();
        assert_eq!(passthrough(&err).kind, ProblemKind::Unavailable);
    }

    #[test]
    fn a_transport_failure_is_never_a_definite_answer() {
        // §5 of the saga: only a verified answer drives retry or
        // rollback; an unreachable endpoint may not.
        let err = BppError::Transport("connect: no such file".to_owned());
        assert!(!err.is_definite());
        assert_eq!(passthrough(&err).kind, ProblemKind::Unavailable);
    }
}
