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
    println!(
        "koveed: personal profile; store {}; listening on {}",
        db.display(),
        path.display()
    );
    let mut daemon = Daemon::new(store, AbortSpec::from_env());
    daemon.serve(&listener);
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("koveed: {e}");
        std::process::exit(1);
    }
}
