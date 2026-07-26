//! A scripted byomd stand-in for the K2 saga tests: byom's own wire
//! framing on byom's own socket names, with per-call answers so a single
//! `governance_enable` invocation can observe the endpoint changing
//! between its step-1 read and its pre-CAS re-verification.
//!
//! The real byomd is exercised separately (`k2_byomd_integration`); this
//! stub exists to make every saga branch deterministic.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::VecDeque;
use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

/// One scripted reply.
#[derive(Debug, Clone)]
pub enum Answer {
    Ok(Value),
    /// A byom problem arm — a DEFINITE answer.
    Problem(&'static str, u16),
    /// Close without replying — the UNKNOWN outcome (transport).
    Close,
}

impl Answer {
    pub fn society(state: &str, recovery_epoch: u64) -> Answer {
        Answer::Ok(json!({
            "society_id": "soc-stub",
            "revision": 2,
            "state": state,
            "recovery_epoch": recovery_epoch,
            "home_authority_ref": "auth-home-stub",
        }))
    }

    pub fn hello(incarnation: &str) -> Answer {
        Answer::Ok(json!({
            "versions": ["0.2"],
            "surface": "governance",
            "endpoint_incarnation": incarnation,
        }))
    }
}

#[derive(Default)]
struct Script {
    hello: VecDeque<Answer>,
    society: VecDeque<Answer>,
    last_hello: Option<Answer>,
    last_society: Option<Answer>,
}

impl Script {
    fn next(&mut self, op: &str) -> Answer {
        let (queue, last) = match op {
            "hello" => (&mut self.hello, &mut self.last_hello),
            _ => (&mut self.society, &mut self.last_society),
        };
        match queue.pop_front() {
            Some(answer) => {
                *last = Some(answer.clone());
                answer
            }
            // Exhausted: the last scripted answer repeats forever.
            None => last.clone().unwrap_or(Answer::Problem("not_found", 404)),
        }
    }
}

pub struct ByomStub {
    dir: PathBuf,
    script: Arc<Mutex<Script>>,
    stop: Arc<Mutex<bool>>,
}

impl ByomStub {
    /// Serves byom's four socket names in `dir`. `hello` and `society`
    /// are the scripted answer sequences; the last one repeats.
    pub fn start(dir: &Path, hello: Vec<Answer>, society: Vec<Answer>) -> ByomStub {
        std::fs::create_dir_all(dir).unwrap();
        let script = Arc::new(Mutex::new(Script {
            hello: hello.into(),
            society: society.into(),
            last_hello: None,
            last_society: None,
        }));
        let stop = Arc::new(Mutex::new(false));
        for name in [
            "governance.sock",
            "projection.sock",
            "participant.sock",
            "candidate.sock",
        ] {
            let path = dir.join(name);
            let _ = std::fs::remove_file(&path);
            let listener = UnixListener::bind(&path).unwrap();
            let script = Arc::clone(&script);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if *stop.lock().unwrap() {
                        return;
                    }
                    let Ok(stream) = stream else { continue };
                    serve(stream, &script);
                }
            });
        }
        ByomStub {
            dir: dir.to_path_buf(),
            script,
            stop,
        }
    }

    /// The common happy stub: one stable incarnation, one active Society.
    pub fn active(dir: &Path) -> ByomStub {
        ByomStub::start(
            dir,
            vec![Answer::hello("inc-stub-1")],
            vec![Answer::society("active", 0)],
        )
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Replaces the remaining scripted answers mid-test.
    pub fn rescript(&self, hello: Vec<Answer>, society: Vec<Answer>) {
        let mut script = self.script.lock().unwrap();
        script.hello = hello.into();
        script.society = society.into();
        script.last_hello = None;
        script.last_society = None;
    }
}

impl Drop for ByomStub {
    fn drop(&mut self) {
        *self.stop.lock().unwrap() = true;
        // Nudge each accept loop so it observes the stop flag.
        for name in [
            "governance.sock",
            "projection.sock",
            "participant.sock",
            "candidate.sock",
        ] {
            let _ = UnixStream::connect(self.dir.join(name));
            let _ = std::fs::remove_file(self.dir.join(name));
        }
    }
}

fn serve(stream: UnixStream, script: &Arc<Mutex<Script>>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() || line.trim().is_empty() {
        return;
    }
    let request: Value = match serde_json::from_str(line.trim_end()) {
        Ok(v) => v,
        Err(_) => return,
    };
    let op = request["op"].as_str().unwrap_or_default().to_owned();
    let answer = script.lock().unwrap().next(&op);
    let reply = match answer {
        // byomd closes without a reply when it drops a connection; that is
        // exactly the UNKNOWN outcome the saga must not guess about.
        Answer::Close => return,
        Answer::Ok(result) => json!({"outcome": "ok", "result": result}),
        Answer::Problem(kind, status) => json!({
            "outcome": "problem",
            "problem": {
                "type": format!("https://byom.dev/problems/{kind}"),
                "kind": kind,
                "title": "stub refusal",
                "status": status,
            },
        }),
    };
    let mut stream = stream;
    let _ = stream.write_all(reply.to_string().as_bytes());
    let _ = stream.write_all(b"\n");
}
