//! `koveed` — the personal-profile daemon: open (and bootstrap) the plain
//! SQLite WAL store, bind the hardened Unix socket, serve one request per
//! connection.
//!
//! ```text
//! koveed [--data-dir <dir>]
//! ```
//!
//! The socket lives at `$XDG_RUNTIME_DIR/kovee/kovee.sock`
//! (`$KOVEE_RUNTIME_DIR` overrides the directory); state lives at
//! `<data-dir>/kovee.db` (default `$XDG_DATA_HOME/kovee`, else
//! `~/.local/share/kovee`; `$KOVEE_DATA_DIR` overrides).
//!
//! A **test build** (`--features testing`) additionally honours
//! `$KOVEE_TESTING_RECORDING_EGRESS`: see [`recording_egress`]. A production
//! build does not compile that function at all.

use std::path::PathBuf;

use koveed::dispatch::AbortSpec;
use koveed::Daemon;

fn data_dir(cli_override: Option<PathBuf>) -> PathBuf {
    if let Some(dir) = cli_override {
        return dir;
    }
    if let Some(dir) = std::env::var_os("KOVEE_DATA_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
        if !xdg.is_empty() {
            return PathBuf::from(xdg).join("kovee");
        }
    }
    match std::env::var_os("HOME") {
        Some(home) => PathBuf::from(home).join(".local/share/kovee"),
        None => PathBuf::from(".kovee"),
    }
}

/// The no-network wire a **test-built** daemon serves its real operations
/// over (R3-I02).
///
/// What you write, to run koveed with a stub provider:
///
/// ```text
/// KOVEE_TESTING_RECORDING_EGRESS='{"id":"msg_01","usage":{...}}' koveed
/// KOVEE_TESTING_RECORDING_EGRESS=@/path/to/reply.json           koveed
/// ```
///
/// The value is the provider reply body the recording transport answers
/// every send with (a leading `@` reads it from a file). With it set, the
/// daemon's own `model_complete` **completes** over
/// [`kovee_effects::RecordingTransport`] instead of the live TLS wire, so a
/// conformance gate can drive the op koveed actually exposes rather than
/// linking kovee as a library and choosing a transport itself — which was
/// the whole of R3-I02.
///
/// Production builds do not compile this: the seal is the absence of the
/// code, not a flag. `cargo build -p koveed` (no `--features testing`) has
/// no `RecordingTransport` in it and no way to reach one.
#[cfg(feature = "testing")]
fn recording_egress() -> Option<kovee_effects::RecordingTransport> {
    let spec = std::env::var("KOVEE_TESTING_RECORDING_EGRESS")
        .ok()
        .filter(|s| !s.is_empty())?;
    let body = match spec.strip_prefix('@') {
        Some(path) => match std::fs::read(path) {
            Ok(body) => body,
            Err(e) => {
                eprintln!("koveed: $KOVEE_TESTING_RECORDING_EGRESS {path}: {e}");
                std::process::exit(1);
            }
        },
        None => spec.into_bytes(),
    };
    eprintln!(
        "koveed: TESTING BUILD — egress is kovee-effects' RecordingTransport (no network), \
         answering {} byte(s)",
        body.len()
    );
    Some(kovee_effects::RecordingTransport::answering(&body))
}

/// Production builds have no such wire, so there is nothing to select.
#[cfg(not(feature = "testing"))]
fn recording_egress() -> Option<std::convert::Infallible> {
    None
}

/// The daemon, with the egress this build is allowed to offer.
fn open_daemon(
    store: kovee_store::Store,
    abort: Option<AbortSpec>,
    dir: &std::path::Path,
) -> Daemon {
    let daemon = Daemon::new(store, abort, dir);
    match recording_egress() {
        #[cfg(feature = "testing")]
        Some(transport) => daemon.with_recording_egress(transport),
        #[cfg(not(feature = "testing"))]
        Some(never) => match never {},
        None => daemon,
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let mut dir_flag = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--data-dir" => {
                dir_flag = Some(PathBuf::from(args.next().ok_or("--data-dir needs a path")?));
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    let dir = data_dir(dir_flag);
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let db = dir.join("kovee.db");
    let mut store = kovee_store::Store::open(&db).map_err(|e| format!("open store: {e}"))?;
    store
        .bootstrap(kovee_core::time::unix_now())
        .map_err(|e| format!("bootstrap: {e}"))?;
    let (listener, path) = koveed::socket::bind().map_err(|e| format!("bind socket: {e}"))?;
    let (worker_listener, worker_path) =
        koveed::socket::bind_worker().map_err(|e| format!("bind worker socket: {e}"))?;
    println!(
        "koveed: personal profile; store {}; listening on {} (external) and {} (worker)",
        db.display(),
        path.display(),
        worker_path.display()
    );
    let daemon = std::sync::Arc::new(open_daemon(store, AbortSpec::from_env(), &dir));
    let worker_daemon = std::sync::Arc::clone(&daemon);
    std::thread::spawn(move || {
        worker_daemon.serve(worker_listener, koveed::Surface::Worker);
    });
    daemon.serve(listener, koveed::Surface::External);
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("koveed: {e}");
        std::process::exit(1);
    }
}
