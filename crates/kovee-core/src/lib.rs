//! Ids, canonicalization, records, and state transitions (design §24):
//! the protocol/core types every bounded context depends on instead of
//! each other's SQL tables.
//!
//! K1 slice 1 provides the KCP wire layer: strict I-JSON acceptance
//! ([`ijson`]), the §11.2 command envelope and §11.2 command result
//! ([`envelope`]), the closed §11.7 problem kinds ([`problem`]), the §11.3
//! event envelope ([`event`]), the per-operation argument schemas for the
//! first op set ([`ops`]), the §10 record projections ([`records`]), the
//! §11.8 digest constructions ([`canonical`]), and the branch head chain
//! ([`branch`]). The K0 schemas in `spec/schemas/` are the wire truth; the
//! Rust here enforces the same constraints and the vector round-trip test
//! (`tests/k1_slice1_vectors.rs`) proves agreement.
//!
//! What you write (a mutation command, parsed and checked):
//! ```
//! use kovee_core::envelope::{RawCommand, Shape};
//! let line = r#"{"version":"0.1","op":"space_create",
//!   "meta":{"request_id":"req-1","idempotency_key":"idem-1"},
//!   "realm_id":"realm-personal","project_id":"proj-1",
//!   "args":{"title":"Garden","visibility":"project"}}"#;
//! let value = kovee_core::ijson::parse_strict(line).unwrap();
//! let cmd = RawCommand::from_value(value).unwrap();
//! cmd.validate(Shape::Mutation).unwrap();
//! assert_eq!(cmd.op, "space_create");
//! ```

pub mod branch;
pub mod canonical;
pub mod envelope;
pub mod event;
pub mod family;
pub mod ijson;
pub mod limits;
pub mod ops;
pub mod problem;
pub mod records;
pub mod time;

/// The one protocol version this implementation speaks (§11).
pub const PROTOCOL_VERSION: &str = "0.1";
