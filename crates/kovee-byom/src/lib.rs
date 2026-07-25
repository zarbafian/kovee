//! The byom governance adapter (design §24 as amended by A1): protocol,
//! provider, and projection adapter speaking the Byom Participation
//! Protocol (BPP). Replaces the design's `kovee-sage` — there is no
//! `kovee-sage` crate and Sage is never wired in; this crate implements
//! the `governed_work_binding_v1` KCP feature bundle.
