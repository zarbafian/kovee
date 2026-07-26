//! The Kovee reference API/control daemon (design §24), personal
//! profile: one plain-SQLite store, two Unix-domain sockets — the
//! external client socket (`$XDG_RUNTIME_DIR/kovee/kovee.sock`) and the
//! separate §23.3 worker socket (`kovee-worker.sock`), both `0600` in a
//! `0700` dir, `SO_PEERCRED` same-UID — one newline-terminated JSON
//! request per connection, and the K1 operation set dispatched through
//! the §12.2 command transaction.
//!
//! What a client writes (one line in, one line out):
//! ```text
//! {"version":"0.1","op":"realm_show","realm_id":"realm-personal","args":{}}
//! → {"outcome":"ok","result":{...realm...},"revision":1}
//! ```

pub mod artifact_ops;
pub mod assistant_ops;
pub mod budget;
pub mod credentials;
pub mod dispatch;
pub mod disposition_ops;
pub mod episode;
pub mod formation;
pub mod governance;
pub mod handlers;
pub mod invoke;
pub mod lifecycle_ops;
pub mod peercred;
pub mod reads;
pub mod socket;
pub mod space_admin_ops;
pub mod space_ops;
pub mod state;

pub use dispatch::{Daemon, Surface};
