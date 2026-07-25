//! The Kovee reference API/control daemon (design §24), personal
//! profile: one plain-SQLite store, one Unix-domain control socket
//! (`$XDG_RUNTIME_DIR/kovee/kovee.sock`, `0600` in a `0700` dir,
//! `SO_PEERCRED` same-UID — the akson control-socket discipline), one
//! newline-terminated JSON request per connection, and the K1 slice-1
//! operation set dispatched through the §12.2 command transaction.
//!
//! What a client writes (one line in, one line out):
//! ```text
//! {"version":"0.1","op":"realm_show","realm_id":"realm-personal","args":{}}
//! → {"outcome":"ok","result":{...realm...},"revision":1}
//! ```

pub mod dispatch;
pub mod handlers;
pub mod peercred;
pub mod socket;

pub use dispatch::Daemon;
