//! The effect-attempt state machine (§16.1): a model call is an Effect,
//! and every dispatch of it is a durable attempt whose record exists
//! BEFORE a byte leaves.
//!
//! ```text
//! prepared -> dispatching -> completed | failed | ambiguous
//!    |
//!    +-> canceled            (nothing was sent; safe to abandon)
//! ```
//!
//! `dispatching` is the durable-before-effect point. A crash while
//! `prepared` transmitted nothing, so the effect may be abandoned or
//! retried under the same idempotency key. A crash after `dispatching`
//! resolves to `ambiguous` and is **never** auto-retried: "no receipt
//! observed" is not proof of failure (§16.1), and a duplicate model call
//! would double both the disclosure and the cost.
//!
//! What you write:
//! ```
//! use kovee_effects::{next, EffectEvent, EffectState};
//! let s = next(EffectState::Prepared, EffectEvent::Dispatch).unwrap();
//! let s = next(s, EffectEvent::Complete).unwrap();
//! assert!(s.is_terminal());
//! // A crash mid-flight freezes retry instead of guessing.
//! let frozen = next(EffectState::Dispatching, EffectEvent::RecoverAfterCrash).unwrap();
//! assert_eq!(frozen, EffectState::Ambiguous);
//! assert!(frozen.retry_frozen());
//! ```

use serde::{Deserialize, Serialize};

/// The state of one model-effect attempt (§16.1 `EffectAttempt.state`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectState {
    /// The pre-egress record is durable: subject, disclosure, provider
    /// context, and the stable execution key are committed. Nothing has
    /// been sent, and no permit has been consumed for this attempt.
    Prepared,
    /// Recorded and committed before the first byte leaves.
    Dispatching,
    /// The provider answered in full.
    Completed,
    /// A clean failure with no possible transmission: a refused egress
    /// check, a connection that never opened, a pre-send validation error.
    Failed,
    /// The outcome is uncertain — the request may have been transmitted
    /// and the model may have been billed. Retry is frozen until an
    /// operator reconciles (§16.1).
    Ambiguous,
    /// Canceled before dispatch. Cancellation cannot pretend an already
    /// transmitted request did not occur, so it is only reachable from
    /// `prepared`.
    Canceled,
}

impl EffectState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            EffectState::Completed
                | EffectState::Failed
                | EffectState::Ambiguous
                | EffectState::Canceled
        )
    }

    /// Whether automatic retry is frozen. Only `ambiguous` freezes: a
    /// clean `failed` may be retried under the same external idempotency
    /// key, and `completed` needs no retry.
    pub fn retry_frozen(self) -> bool {
        self == EffectState::Ambiguous
    }

    pub fn as_str(self) -> &'static str {
        match self {
            EffectState::Prepared => "prepared",
            EffectState::Dispatching => "dispatching",
            EffectState::Completed => "completed",
            EffectState::Failed => "failed",
            EffectState::Ambiguous => "ambiguous",
            EffectState::Canceled => "canceled",
        }
    }

    /// Parses a persisted state string.
    #[allow(clippy::should_implement_trait)] // a fallible Option helper, not FromStr.
    pub fn from_str(s: &str) -> Option<EffectState> {
        Some(match s {
            "prepared" => EffectState::Prepared,
            "dispatching" => EffectState::Dispatching,
            "completed" => EffectState::Completed,
            "failed" => EffectState::Failed,
            "ambiguous" => EffectState::Ambiguous,
            "canceled" => EffectState::Canceled,
            _ => return None,
        })
    }
}

/// An event driving one attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectEvent {
    /// Record `dispatching` before the first byte leaves.
    Dispatch,
    Complete,
    /// A clean failure with no possible transmission.
    Fail,
    /// The outcome is uncertain (a request may have been transmitted).
    MarkAmbiguous,
    /// Cancel an un-dispatched attempt.
    Cancel,
    /// Recovery found an attempt left `dispatching` by a crash.
    RecoverAfterCrash,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TransitionError {
    #[error("{} is terminal; no further transition", state.as_str())]
    AlreadyTerminal { state: EffectState },
    #[error("{event:?} is not valid from {}", state.as_str())]
    Invalid {
        state: EffectState,
        event: EffectEvent,
    },
}

/// Applies one event. Pure, total, and fail-closed: a terminal state or an
/// out-of-order event is refused, so the store drives transitions without
/// re-deriving the rules.
pub fn next(state: EffectState, event: EffectEvent) -> Result<EffectState, TransitionError> {
    use EffectEvent as E;
    use EffectState as S;

    if state.is_terminal() {
        return Err(TransitionError::AlreadyTerminal { state });
    }
    Ok(match (state, event) {
        (S::Prepared, E::Dispatch) => S::Dispatching,
        (S::Prepared, E::Cancel) => S::Canceled,
        (S::Dispatching, E::Complete) => S::Completed,
        (S::Dispatching, E::Fail) => S::Failed,
        (S::Dispatching, E::MarkAmbiguous) => S::Ambiguous,
        // A crash after dispatch began cannot be classified as failure.
        (S::Dispatching, E::RecoverAfterCrash) => S::Ambiguous,
        // Cancellation cannot undo a transmitted disclosure.
        (S::Dispatching, E::Cancel) => S::Ambiguous,
        _ => return Err(TransitionError::Invalid { state, event }),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use EffectEvent as E;
    use EffectState as S;

    #[test]
    fn the_happy_path_dispatches_then_completes() {
        let s = next(S::Prepared, E::Dispatch).unwrap();
        assert_eq!(s, S::Dispatching);
        let s = next(s, E::Complete).unwrap();
        assert_eq!(s, S::Completed);
        assert!(s.is_terminal());
        assert!(!s.retry_frozen());
    }

    #[test]
    fn a_crash_while_dispatching_freezes_retry() {
        let s = next(S::Dispatching, E::RecoverAfterCrash).unwrap();
        assert_eq!(s, S::Ambiguous);
        assert!(s.retry_frozen());
        assert!(matches!(
            next(s, E::Dispatch),
            Err(TransitionError::AlreadyTerminal { .. })
        ));
    }

    #[test]
    fn a_crash_while_prepared_sent_nothing() {
        // Recovery cannot make a prepared attempt ambiguous: no byte left.
        assert!(matches!(
            next(S::Prepared, E::RecoverAfterCrash),
            Err(TransitionError::Invalid { .. })
        ));
        assert_eq!(next(S::Prepared, E::Cancel).unwrap(), S::Canceled);
        assert!(!S::Prepared.retry_frozen());
    }

    #[test]
    fn cancel_is_clean_only_before_dispatch() {
        assert_eq!(next(S::Prepared, E::Cancel).unwrap(), S::Canceled);
        assert_eq!(next(S::Dispatching, E::Cancel).unwrap(), S::Ambiguous);
    }

    #[test]
    fn out_of_order_events_are_refused() {
        assert!(matches!(
            next(S::Prepared, E::Complete),
            Err(TransitionError::Invalid { .. })
        ));
        assert!(matches!(
            next(S::Dispatching, E::Dispatch),
            Err(TransitionError::Invalid { .. })
        ));
    }

    #[test]
    fn state_strings_round_trip() {
        for s in [
            S::Prepared,
            S::Dispatching,
            S::Completed,
            S::Failed,
            S::Ambiguous,
            S::Canceled,
        ] {
            assert_eq!(EffectState::from_str(s.as_str()), Some(s));
        }
        assert_eq!(EffectState::from_str("nope"), None);
    }
}
