//! `kovee` — the thin operator/client CLI (akson-cli style): each verb
//! builds one KCP command line, writes it to the daemon's Unix socket,
//! reads one reply line, and prints `result` (or the `problem`).
//!
//! ```text
//! kovee hello
//! kovee init
//! kovee space create --project <id> --title <t> [--visibility project|restricted]
//! kovee space show --project <id> <space_id>
//! kovee space contribute --project <id> --space <id> --text <t> [--kind utterance]
//! kovee events --project <id> [--after <cursor>] [--limit <n>]
//! ```
//!
//! The CLI is a client: it computes the §10.3 expected branch head by
//! folding the authorized event ledger (`events_read`), never by a
//! privileged read.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use kovee_core::branch;
use serde_json::{json, Map, Value};

/// The one realm of the personal profile (koveed bootstraps it).
const REALM: &str = "realm-personal";
const CONTRIBUTION_APPENDED: &str = "dev.kovee.space.contribution-appended.v1";

fn socket_path() -> PathBuf {
    // Mirrors koveed::socket::socket_dir — both sides resolve through the
    // same rules so they always agree.
    if let Some(dir) = std::env::var_os("KOVEE_RUNTIME_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir).join("kovee.sock");
        }
    }
    match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(rt) if !rt.is_empty() => PathBuf::from(rt).join("kovee").join("kovee.sock"),
        _ => {
            // SAFETY: geteuid is always safe and cannot fail.
            #[allow(unsafe_code)]
            let uid = unsafe { libc::geteuid() };
            std::env::temp_dir()
                .join(format!("kovee-{uid}"))
                .join("kovee.sock")
        }
    }
}

#[derive(Debug)]
enum CliError {
    Usage(String),
    Io(String),
    Problem(Value),
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> CliError {
        CliError::Io(e.to_string())
    }
}

/// One request line in, one reply line out (the whole protocol).
fn request(command: &Value) -> Result<Value, CliError> {
    let path = socket_path();
    let mut stream = UnixStream::connect(&path).map_err(|e| {
        CliError::Io(format!(
            "cannot reach koveed at {} ({e}); is the daemon running?",
            path.display()
        ))
    })?;
    let mut line = serde_json::to_string(command).map_err(|e| CliError::Io(e.to_string()))?;
    line.push('\n');
    stream.write_all(line.as_bytes())?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut reply = String::new();
    BufReader::new(stream).read_line(&mut reply)?;
    let parsed: Value =
        serde_json::from_str(reply.trim_end()).map_err(|e| CliError::Io(e.to_string()))?;
    match parsed["outcome"].as_str() {
        Some("ok") => Ok(parsed),
        Some("problem") => Err(CliError::Problem(parsed["problem"].clone())),
        _ => Err(CliError::Io("malformed reply".to_owned())),
    }
}

fn fresh_idempotency_key() -> Result<String, CliError> {
    let mut bytes = [0u8; 12];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    let mut hex = String::new();
    for b in bytes {
        hex.push_str(&format!("{b:02x}"));
    }
    Ok(format!("cli-{hex}"))
}

fn mutation(op: &str, project_id: Option<&str>, args: Value, key: &str) -> Value {
    let mut cmd = Map::new();
    cmd.insert("version".into(), json!("0.1"));
    cmd.insert("op".into(), json!(op));
    cmd.insert(
        "meta".into(),
        json!({"request_id": format!("req-{key}"), "idempotency_key": key}),
    );
    cmd.insert("realm_id".into(), json!(REALM));
    if let Some(p) = project_id {
        cmd.insert("project_id".into(), json!(p));
    }
    cmd.insert("args".into(), args);
    Value::Object(cmd)
}

fn read(op: &str, project_id: Option<&str>, args: Value) -> Value {
    let mut cmd = Map::new();
    cmd.insert("version".into(), json!("0.1"));
    cmd.insert("op".into(), json!(op));
    if op != "hello" {
        cmd.insert("realm_id".into(), json!(REALM));
    }
    if let Some(p) = project_id {
        cmd.insert("project_id".into(), json!(p));
    }
    cmd.insert("args".into(), args);
    Value::Object(cmd)
}

fn print_ok(reply: &Value) {
    match serde_json::to_string_pretty(&reply["result"]) {
        Ok(pretty) => println!("{pretty}"),
        Err(_) => println!("{}", reply["result"]),
    }
    if let Some(cursor) = reply["event_cursor"].as_str() {
        eprintln!("event_cursor: {cursor}");
    }
}

// ------------------------------------------------------------- verbs ----

fn cmd_hello() -> Result<(), CliError> {
    let reply = request(&read(
        "hello",
        None,
        json!({
            "supported_versions": ["0.1"],
            "implementation": "kovee-cli",
            "implementation_version": env!("CARGO_PKG_VERSION"),
            "requested_features": [],
        }),
    ))?;
    print_ok(&reply);
    Ok(())
}

/// `kovee init`: hello, show the personal realm, and idempotently create
/// the default project (a fixed idempotency key, so repeating `init`
/// replays the stored byte-identical result instead of minting a second
/// project — §11.2 working as intended).
fn cmd_init() -> Result<(), CliError> {
    let hello = request(&read(
        "hello",
        None,
        json!({
            "supported_versions": ["0.1"],
            "implementation": "kovee-cli",
            "implementation_version": env!("CARGO_PKG_VERSION"),
            "requested_features": [],
        }),
    ))?;
    let realm = request(&read("realm_show", None, json!({})))?;
    let project = request(&mutation(
        "project_create",
        None,
        json!({"name": "personal"}),
        "kovee-init-default-project",
    ))?;
    println!(
        "installation: {}",
        hello["result"]["installation_id"].as_str().unwrap_or("?")
    );
    println!(
        "realm:        {}",
        realm["result"]["realm_id"].as_str().unwrap_or("?")
    );
    println!(
        "project:      {} (name {:?})",
        project["result"]["project_id"].as_str().unwrap_or("?"),
        project["result"]["name"].as_str().unwrap_or("?")
    );
    Ok(())
}

fn cmd_space_create(opts: &Opts) -> Result<(), CliError> {
    let project = opts.require("--project")?;
    let title = opts.require("--title")?;
    let visibility = opts.get("--visibility").unwrap_or("project");
    let key = match opts.get("--idempotency-key") {
        Some(k) => k.to_owned(),
        None => fresh_idempotency_key()?,
    };
    let reply = request(&mutation(
        "space_create",
        Some(project),
        json!({"title": title, "visibility": visibility}),
        &key,
    ))?;
    print_ok(&reply);
    Ok(())
}

fn cmd_space_show(opts: &Opts) -> Result<(), CliError> {
    let project = opts.require("--project")?;
    let space = opts
        .positional
        .first()
        .ok_or_else(|| CliError::Usage("space show needs a <space_id>".into()))?;
    let reply = request(&read(
        "space_show",
        Some(project),
        json!({"space_id": space}),
    ))?;
    print_ok(&reply);
    Ok(())
}

/// Folds the event ledger into the current §10.3 branch head.
fn derive_branch_head(project: &str, branch_id: &str) -> Result<String, CliError> {
    let mut entries: Vec<(u64, String)> = Vec::new();
    let mut after: Option<String> = None;
    loop {
        let mut args = Map::new();
        args.insert("source".into(), json!(project));
        args.insert("limit".into(), json!(512));
        args.insert("type_prefixes".into(), json!([CONTRIBUTION_APPENDED]));
        if let Some(cursor) = &after {
            args.insert("after_cursor".into(), json!(cursor));
        }
        let reply = request(&read("events_read", Some(project), Value::Object(args)))?;
        let events = reply["result"]["events"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        for event in &events {
            let payload = &event["payload"];
            if payload["origin_branch_id"].as_str() == Some(branch_id) {
                if let (Some(seq), Some(digest)) = (
                    payload["origin_branch_sequence"].as_u64(),
                    payload["content_digest"].as_str(),
                ) {
                    entries.push((seq, digest.to_owned()));
                }
            }
        }
        if events.len() < 512 {
            break;
        }
        after = reply["result"]["next_cursor"].as_str().map(str::to_owned);
    }
    entries.sort();
    let mut head = branch::genesis_head(branch_id);
    for (seq, digest) in entries {
        head = branch::next_head(&head, seq, &digest);
    }
    Ok(head)
}

fn cmd_space_contribute(opts: &Opts) -> Result<(), CliError> {
    let project = opts.require("--project")?;
    let space = opts.require("--space")?;
    let text = opts.require("--text")?;
    let kind = opts.get("--kind").unwrap_or("utterance");
    let key = match opts.get("--idempotency-key") {
        Some(k) => k.to_owned(),
        None => fresh_idempotency_key()?,
    };
    let shown = request(&read(
        "space_show",
        Some(project),
        json!({"space_id": space}),
    ))?;
    let branch_id = shown["result"]["main_branch_id"]
        .as_str()
        .ok_or_else(|| CliError::Io("space has no main branch".into()))?
        .to_owned();
    let head = derive_branch_head(project, &branch_id)?;
    let reply = request(&mutation(
        "contribution_append",
        Some(project),
        json!({
            "space_id": space,
            "branch_id": branch_id,
            "expected_head_digest": head,
            "kind": kind,
            "body_parts": [{"media_type": "text/plain", "text": text}],
        }),
        &key,
    ))?;
    print_ok(&reply);
    Ok(())
}

fn cmd_events(opts: &Opts) -> Result<(), CliError> {
    let project = opts.require("--project")?;
    let limit: u64 = match opts.get("--limit") {
        Some(n) => n
            .parse()
            .map_err(|_| CliError::Usage("--limit needs a number".into()))?,
        None => 100,
    };
    let mut args = Map::new();
    args.insert("source".into(), json!(project));
    args.insert("limit".into(), json!(limit));
    if let Some(cursor) = opts.get("--after") {
        args.insert("after_cursor".into(), json!(cursor));
    }
    let reply = request(&read("events_read", Some(project), Value::Object(args)))?;
    let events = reply["result"]["events"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    for event in &events {
        println!(
            "{:>4}  {}  {}  {}",
            event["project_sequence"].as_u64().unwrap_or(0),
            event["occurred_at"].as_str().unwrap_or("?"),
            event["type"].as_str().unwrap_or("?"),
            event["resource_ref"].as_str().unwrap_or("?"),
        );
    }
    eprintln!(
        "next_cursor: {}",
        reply["result"]["next_cursor"].as_str().unwrap_or("?")
    );
    Ok(())
}

// ------------------------------------------------------ arg plumbing ----

struct Opts {
    flags: Vec<(String, String)>,
    positional: Vec<String>,
}

impl Opts {
    fn parse(args: &[String]) -> Result<Opts, CliError> {
        let mut flags = Vec::new();
        let mut positional = Vec::new();
        let mut it = args.iter();
        while let Some(arg) = it.next() {
            if let Some(name) = arg.strip_prefix("--").map(|_| arg.clone()) {
                let value = it
                    .next()
                    .ok_or_else(|| CliError::Usage(format!("{name} needs a value")))?;
                flags.push((name, value.clone()));
            } else {
                positional.push(arg.clone());
            }
        }
        Ok(Opts { flags, positional })
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.flags
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    fn require(&self, name: &str) -> Result<&str, CliError> {
        self.get(name)
            .ok_or_else(|| CliError::Usage(format!("{name} is required")))
    }
}

const USAGE: &str = "usage:
  kovee hello
  kovee init
  kovee space create --project <id> --title <t> [--visibility project|restricted]
  kovee space show --project <id> <space_id>
  kovee space contribute --project <id> --space <id> --text <t> [--kind <kind>]
  kovee events --project <id> [--after <cursor>] [--limit <n>]";

fn run() -> Result<(), CliError> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match argv.split_first() {
        Some((verb, rest)) => match (verb.as_str(), rest.split_first()) {
            ("hello", _) => cmd_hello(),
            ("init", _) => cmd_init(),
            ("space", Some((sub, tail))) => {
                let opts = Opts::parse(tail)?;
                match sub.as_str() {
                    "create" => cmd_space_create(&opts),
                    "show" => cmd_space_show(&opts),
                    "contribute" => cmd_space_contribute(&opts),
                    other => Err(CliError::Usage(format!("unknown space verb {other:?}"))),
                }
            }
            ("events", _) => cmd_events(&Opts::parse(rest)?),
            (other, _) => Err(CliError::Usage(format!("unknown verb {other:?}"))),
        },
        None => Err(CliError::Usage("no verb".into())),
    }
}

fn main() {
    match run() {
        Ok(()) => {}
        Err(CliError::Usage(msg)) => {
            eprintln!("kovee: {msg}\n{USAGE}");
            std::process::exit(2);
        }
        Err(CliError::Io(msg)) => {
            eprintln!("kovee: {msg}");
            std::process::exit(1);
        }
        Err(CliError::Problem(problem)) => {
            eprintln!(
                "kovee: problem {}: {}",
                problem["type"].as_str().unwrap_or("?"),
                problem["title"].as_str().unwrap_or("?")
            );
            if let Some(detail) = problem["detail"].as_str() {
                eprintln!("  {detail}");
            }
            std::process::exit(1);
        }
    }
}
