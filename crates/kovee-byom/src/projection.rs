//! Projection-surface reads against byomd — the only way Kovee learns
//! whether a Society exists and is active.
//!
//! What you write:
//! ```no_run
//! use kovee_byom::bpp::Endpoint;
//! use kovee_byom::projection::society_show;
//! let endpoint = Endpoint::local("local");
//! let society = society_show(&endpoint, "soc-1")?;
//! assert!(society.is_active());
//! # Ok::<(), kovee_byom::bpp::BppError>(())
//! ```
//!
//! Plumbing: `society_show` is a byom read on `projection.sock`, so the
//! request carries no `meta`. An unknown society answers `not_found`,
//! which is a DEFINITE answer — Kovee refuses to enable rather than
//! establishing a Society itself (amendment A2: Kovee is never the
//! genesis governance actor).

use serde::{Deserialize, Serialize};

use crate::bpp::{BppError, Endpoint, Surface, BPP_VERSION};

/// The closed byom Society lifecycle states (§14.6).
pub const SOCIETY_STATES: [&str; 5] = ["forming", "active", "held", "dissolving", "dissolved"];

/// What Kovee needs from one Society: its identity, its lifecycle state,
/// and the recovery epoch every derived binding pins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocietyView {
    pub society_id: String,
    pub revision: u64,
    pub state: String,
    pub recovery_epoch: u64,
}

impl SocietyView {
    pub fn is_active(&self) -> bool {
        self.state == "active"
    }
}

/// Reads one Society through byomd's projection surface.
pub fn society_show(endpoint: &Endpoint, society_id: &str) -> Result<SocietyView, BppError> {
    let reply = endpoint.call(
        Surface::Projection,
        &serde_json::json!({
            "version": BPP_VERSION,
            "op": "society_show",
            "society_id": society_id,
        }),
    )?;
    let pick_u64 = |key: &str| reply.result.get(key).and_then(serde_json::Value::as_u64);
    let state = reply
        .result
        .get("state")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| BppError::Malformed("society_show result carries no state".to_owned()))?;
    if !SOCIETY_STATES.contains(&state) {
        // Safety-relevant enums are closed: an unknown lifecycle state is
        // not silently treated as inactive-but-fine, it is unusable.
        return Err(BppError::Malformed(format!(
            "society_show returned the unknown state {state:?}"
        )));
    }
    Ok(SocietyView {
        society_id: reply
            .result
            .get("society_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(society_id)
            .to_owned(),
        revision: reply.revision.or_else(|| pick_u64("revision")).unwrap_or(0),
        state: state.to_owned(),
        recovery_epoch: pick_u64("recovery_epoch").unwrap_or(0),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn only_the_active_state_is_active() {
        for state in SOCIETY_STATES {
            let view = SocietyView {
                society_id: "soc-1".to_owned(),
                revision: 2,
                state: state.to_owned(),
                recovery_epoch: 0,
            };
            assert_eq!(view.is_active(), state == "active", "{state}");
        }
    }
}
