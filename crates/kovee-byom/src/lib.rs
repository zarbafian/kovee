//! The byom governance adapter (design §24 as amended by A1): protocol,
//! provider, and projection adapter speaking the Byom Participation
//! Protocol (BPP). Replaces the design's `kovee-sage` — there is no
//! `kovee-sage` crate and Sage is never wired in; this crate implements
//! the `governed_work_binding_v1` KCP feature bundle.
//!
//! K2 slice 1 delivers the binding half:
//!
//! - [`bpp`] — the per-surface UDS client for byomd's governance,
//!   candidate, participant, projection, and runtime sockets, byom's own
//!   framing, and problem passthrough;
//! - [`projection`] — the Society read that proves a governance owner
//!   already exists (Kovee is never the genesis actor, amendment A2);
//! - [`records`] — the C2 host records `KoveeRealmByomBinding`,
//!   `KoveeSocietyMapping`, and `KoveeGovernanceOwnerBinding`, with their
//!   typed family digests;
//! - [`credential`] — the `DelegatedPrincipalCredential` profile and its
//!   atomic `(issuer, nonce)` consume key;
//! - [`scope`] — the governed-scope selector grammar and the overlap
//!   predicate the owner-binding uniqueness rule needs.
//!
//! K2 slice 2 adds the governed-work half:
//!
//! - [`hostint`] — the CROSS-BOUNDARY `portable_public` derivations both
//!   sides recompute (the command digest, the attempt proof, the wire
//!   projections byomd has installed);
//! - [`formation`] — the `EndeavorFormationIntent`/`Slot`/`Attempt`
//!   machine and the five-fact union that drives it;
//! - [`episode`] — `ByomEpisodeBinding`, `PlacementBinding`, and the DUAL
//!   fences every runtime mutation must present;
//! - [`budget`] — the `byom_subordinate` reservation bridge, never above
//!   parent and settled only from a trusted meter.
//!
//! What you write (the whole binding half, in outline):
//! ```no_run
//! use kovee_byom::bpp::{Endpoint, Surface};
//! use kovee_byom::projection::society_show;
//! use kovee_byom::scope::Selector;
//!
//! let endpoint = Endpoint::local("local");
//! let hello = endpoint.hello(Surface::Governance)?;
//! let society = society_show(&endpoint, "soc-1")?;
//! assert!(society.is_active(), "Kovee never establishes a Society itself");
//! let scope = Selector::parse("project:proj-1")?;
//! # let _ = (hello.endpoint_incarnation, scope);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! The saga that drives these pieces — create the inert bindings, then
//! CAS the owner `none → byom` at the expected revision — lives in the
//! daemon (`koveed::governance`), because it needs the §12.2 command
//! transaction to be crash-honest.

pub mod bpp;
pub mod budget;
pub mod credential;
pub mod episode;
pub mod formation;
pub mod hostint;
pub mod projection;
pub mod records;
pub mod scope;
