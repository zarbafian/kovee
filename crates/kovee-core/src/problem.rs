//! RFC 9457 problem details with the closed §11.7 kind enum
//! (`urn:kovee:error:<kind>`), exactly the 21 kinds and their statuses.

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The closed §11.7 problem-kind enum. Safety-relevant enums are closed
/// (§11.8); an unknown kind fails deserialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProblemKind {
    Invalid,
    Unauthenticated,
    Forbidden,
    NotFound,
    UnsupportedVersion,
    UnknownOp,
    ForbiddenSurface,
    StaleRevision,
    StaleLease,
    IdempotencyMismatch,
    IdempotencyResultExpired,
    AuthorizationStale,
    BudgetExceeded,
    DeadlineExceeded,
    Cycle,
    CursorExpired,
    SnapshotExpired,
    RateLimited,
    Ambiguous,
    Unavailable,
    Internal,
}

impl ProblemKind {
    /// All 21 kinds, in §11.7 table order.
    pub const ALL: [ProblemKind; 21] = [
        ProblemKind::Invalid,
        ProblemKind::Unauthenticated,
        ProblemKind::Forbidden,
        ProblemKind::NotFound,
        ProblemKind::UnsupportedVersion,
        ProblemKind::UnknownOp,
        ProblemKind::ForbiddenSurface,
        ProblemKind::StaleRevision,
        ProblemKind::StaleLease,
        ProblemKind::IdempotencyMismatch,
        ProblemKind::IdempotencyResultExpired,
        ProblemKind::AuthorizationStale,
        ProblemKind::BudgetExceeded,
        ProblemKind::DeadlineExceeded,
        ProblemKind::Cycle,
        ProblemKind::CursorExpired,
        ProblemKind::SnapshotExpired,
        ProblemKind::RateLimited,
        ProblemKind::Ambiguous,
        ProblemKind::Unavailable,
        ProblemKind::Internal,
    ];

    /// The bare kind token as it appears after `urn:kovee:error:`.
    pub fn token(self) -> &'static str {
        match self {
            ProblemKind::Invalid => "invalid",
            ProblemKind::Unauthenticated => "unauthenticated",
            ProblemKind::Forbidden => "forbidden",
            ProblemKind::NotFound => "not-found",
            ProblemKind::UnsupportedVersion => "unsupported-version",
            ProblemKind::UnknownOp => "unknown-op",
            ProblemKind::ForbiddenSurface => "forbidden-surface",
            ProblemKind::StaleRevision => "stale-revision",
            ProblemKind::StaleLease => "stale-lease",
            ProblemKind::IdempotencyMismatch => "idempotency-mismatch",
            ProblemKind::IdempotencyResultExpired => "idempotency-result-expired",
            ProblemKind::AuthorizationStale => "authorization-stale",
            ProblemKind::BudgetExceeded => "budget-exceeded",
            ProblemKind::DeadlineExceeded => "deadline-exceeded",
            ProblemKind::Cycle => "cycle",
            ProblemKind::CursorExpired => "cursor-expired",
            ProblemKind::SnapshotExpired => "snapshot-expired",
            ProblemKind::RateLimited => "rate-limited",
            ProblemKind::Ambiguous => "ambiguous",
            ProblemKind::Unavailable => "unavailable",
            ProblemKind::Internal => "internal",
        }
    }

    /// The full `urn:kovee:error:<kind>` type value.
    pub fn urn(self) -> String {
        format!("urn:kovee:error:{}", self.token())
    }

    /// The §11.7 HTTP-style status pinned per kind.
    pub fn status(self) -> u16 {
        match self {
            ProblemKind::Invalid => 422,
            ProblemKind::Unauthenticated => 401,
            ProblemKind::Forbidden | ProblemKind::ForbiddenSurface => 403,
            ProblemKind::NotFound => 404,
            ProblemKind::UnsupportedVersion | ProblemKind::UnknownOp => 400,
            ProblemKind::StaleRevision
            | ProblemKind::StaleLease
            | ProblemKind::IdempotencyMismatch
            | ProblemKind::AuthorizationStale
            | ProblemKind::BudgetExceeded
            | ProblemKind::DeadlineExceeded
            | ProblemKind::Cycle
            | ProblemKind::Ambiguous => 409,
            ProblemKind::IdempotencyResultExpired
            | ProblemKind::CursorExpired
            | ProblemKind::SnapshotExpired => 410,
            ProblemKind::RateLimited => 429,
            ProblemKind::Unavailable => 503,
            ProblemKind::Internal => 500,
        }
    }

    /// Parses a `urn:kovee:error:<kind>` type back into the closed enum.
    pub fn from_urn(urn: &str) -> Option<ProblemKind> {
        let token = urn.strip_prefix("urn:kovee:error:")?;
        ProblemKind::ALL.into_iter().find(|k| k.token() == token)
    }
}

impl Serialize for ProblemKind {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.urn())
    }
}

impl<'de> Deserialize<'de> for ProblemKind {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let urn = String::deserialize(d)?;
        ProblemKind::from_urn(&urn)
            .ok_or_else(|| D::Error::custom(format!("unknown problem type {urn:?}")))
    }
}

/// One §11.7 problem. `status` always carries the kind's pinned value;
/// `detail` never leaks paths, tokens, policy internals, or peer existence
/// (§11.7 `internal` row — the discipline applies to every kind).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Problem {
    #[serde(rename = "type")]
    pub kind: ProblemKind,
    pub title: String,
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub detail: Option<String>,
}

impl Problem {
    pub fn new(kind: ProblemKind, title: impl Into<String>) -> Problem {
        Problem {
            kind,
            title: title.into(),
            status: kind.status(),
            detail: None,
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Problem {
        self.detail = Some(detail.into());
        self
    }
}
