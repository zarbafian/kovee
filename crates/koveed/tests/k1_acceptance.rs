//! K1 acceptance (kovee §26 K1 exit, verbatim): init → open a space →
//! append a question → invoke the deterministic assistant over an
//! inspectable ContextAssembly → kill koveed mid-flow (after the
//! synthesis commit, before the reply) → restart → EXACTLY ONE synthesis
//! contribution plus its `addresses` relation and causal provenance, no
//! duplication.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use common::*;
use serde_json::json;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn spawn_reviewer(
    runtime_dir: &std::path::Path,
    project: &str,
    space: &str,
    branch: &str,
    question: &str,
    key: &str,
) -> std::process::Child {
    Command::new("python3")
        .arg(
            repo_root()
                .join("assistants")
                .join("deterministic_reviewer.py"),
        )
        .args(["--project", project])
        .args(["--space", space])
        .args(["--branch", branch])
        .args(["--question", question])
        .args(["--invocation-key", key])
        .args(["--retry-seconds", "60"])
        .env("KOVEE_RUNTIME_DIR", runtime_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn deterministic_reviewer.py")
}

#[test]
fn acceptance_one_synthesis_and_addresses_after_kill_and_restart() {
    let base = tmp("k1-acceptance");
    let data = base.join("data");
    let run = base.join("run");

    // Init: daemon up, project, space, question.
    let daemon = DaemonProc::start(&data, &run, None);
    let (project, space, branch, head) = setup_space(&daemon);
    let (question_id, _q_digest, _head) = append(
        &daemon,
        &project,
        &space,
        &branch,
        &head,
        "idem-question",
        "question",
        "What is the answer to everything?",
        json!({}),
    );
    drop(daemon);

    // Armed daemon: dies AFTER the worker's synthesis contribution
    // commits, BEFORE the reply reaches the SDK — the worst mid-flow cut.
    let mut armed = DaemonProc::start(&data, &run, Some("after_commit:contribution_append"));
    let mut reviewer = spawn_reviewer(&run, &project, &space, &branch, &question_id, "review-1");
    assert!(
        armed.wait_exit(Duration::from_secs(30)),
        "the armed daemon must die at the synthesis commit"
    );
    armed.wait_dead();

    // Restart on the same database; the SDK's bounded retries are still
    // running and must replay the committed synthesis, then finish the
    // relation + completion — exactly once end to end.
    let recovered = DaemonProc::start(&data, &run, None);
    let status = reviewer.wait().expect("reviewer exits");
    assert!(
        status.success(),
        "the assistant must complete after restart"
    );

    // Exactly one synthesis, exactly one addresses relation.
    let events = recovered.expect_ok(&events_read(&project));
    let list = events["result"]["events"].as_array().unwrap().clone();
    let syntheses: Vec<_> = list
        .iter()
        .filter(|e| {
            e["type"].as_str() == Some("dev.kovee.space.contribution-appended.v1")
                && e["payload"]["kind"].as_str() == Some("synthesis")
        })
        .collect();
    assert_eq!(syntheses.len(), 1, "exactly one synthesis: {list:#?}");
    let synthesis = &syntheses[0]["payload"];
    let relations: Vec<_> = list
        .iter()
        .filter(|e| e["type"].as_str() == Some("dev.kovee.space.relation-asserted.v1"))
        .collect();
    assert_eq!(relations.len(), 1, "exactly one relation: {list:#?}");
    let relation = &relations[0]["payload"];
    assert_eq!(relation["kind"].as_str(), Some("addresses"));
    assert_eq!(
        relation["from_ref"]["object_ref"].as_str(),
        synthesis["contribution_id"].as_str(),
        "the relation addresses FROM the synthesis"
    );
    assert_eq!(
        relation["to_ref"]["object_ref"].as_str(),
        Some(question_id.as_str()),
        "… TO the question"
    );
    // The public/worker surface can only create semantic assertions.
    assert_eq!(
        relation["relation_class"].as_str(),
        Some("semantic_assertion")
    );

    // Causal provenance: the synthesis is attributed to the deployment
    // and bound to the exact invocation + assembly.
    assert_eq!(
        synthesis["author_actor_ref"].as_str(),
        Some("asstdep-dep-local-dev")
    );
    let invocation_ref = synthesis["invocation_ref"].as_str().unwrap().to_owned();
    let assembly_ref = synthesis["context_assembly_ref"]
        .as_str()
        .unwrap()
        .to_owned();

    // The invocation succeeded exactly once and names the synthesis.
    let invocation = recovered.expect_ok(&read_cmd(
        "invocation_show",
        Some(&project),
        json!({"invocation_id": invocation_ref}),
    ));
    assert_eq!(invocation["result"]["state"].as_str(), Some("succeeded"));
    assert_eq!(
        invocation["result"]["context_assembly_ref"].as_str(),
        Some(assembly_ref.as_str())
    );

    // The assembly is inspectable and pins the question exactly.
    let assembly = recovered.expect_ok(&read_cmd(
        "context_assembly_show",
        Some(&project),
        json!({"assembly_id": assembly_ref}),
    ));
    let items = assembly["result"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0]["object_ref"].as_str(),
        Some(question_id.as_str()),
        "the assembly includes exactly the question"
    );
    assert_eq!(items[0]["inclusion_reason"].as_str(), Some("explicit_ref"));
    assert_eq!(
        assembly["result"]["selection_policy_ref"].as_str(),
        Some("explicit_refs_v1")
    );
    assert_eq!(
        assembly["result"]["omissions"].as_array().map(Vec::len),
        Some(0)
    );

    // Re-running the whole assistant flow after the invocation has
    // COMPLETED commits nothing new — and, since KV-R1, does not hand
    // the finished attempt its old receipts either: the completed
    // attempt is refused `stale-lease` at its first write, without
    // re-execution. (The mid-flow replay above, with the attempt still
    // running, is the one this daemon is required to serve.)
    let mut rerun = spawn_reviewer(&run, &project, &space, &branch, &question_id, "review-1");
    let status = rerun.wait().expect("rerun exits");
    assert!(
        !status.success(),
        "a completed attempt must not be able to replay its writes"
    );
    let events_after = recovered.expect_ok(&events_read(&project));
    let list_after = events_after["result"]["events"].as_array().unwrap();
    assert_eq!(
        list_after.len(),
        list.len(),
        "a refused replay commits nothing new"
    );

    // The Stream and Workbench lenses render the flow (presentation
    // only): the workbench card for the question carries the incoming
    // addresses relation.
    let stream = recovered.expect_ok(&read_cmd(
        "lens_read",
        Some(&project),
        json!({"lens_id": format!("lens-stream-{space}"), "limit": 100}),
    ));
    let stream_items = stream["result"]["items"].as_array().unwrap();
    assert_eq!(stream_items.len(), 2, "question + synthesis in the stream");
    let workbench = recovered.expect_ok(&read_cmd(
        "lens_read",
        Some(&project),
        json!({"lens_id": format!("lens-workbench-{space}"), "limit": 100}),
    ));
    let cards = workbench["result"]["items"].as_array().unwrap();
    let question_card = cards
        .iter()
        .find(|c| c["contribution"]["contribution_id"].as_str() == Some(question_id.as_str()))
        .expect("the question card exists");
    assert_eq!(
        question_card["relations_in"].as_array().map(Vec::len),
        Some(1),
        "the workbench shows the addresses relation on the question card"
    );

    // events_wait long-poll: an already-satisfiable wait returns
    // immediately with the same events; a wait at the head times out
    // empty without blocking the daemon.
    let head_cursor = events_after["result"]["next_cursor"].as_str().unwrap();
    let waited = recovered.expect_ok(&read_cmd(
        "events_wait",
        Some(&project),
        json!({
            "source": project,
            "after_cursor": head_cursor,
            "timeout_ms": 100,
        }),
    ));
    assert_eq!(
        waited["result"]["events"].as_array().map(Vec::len),
        Some(0),
        "a wait at the head returns empty at timeout"
    );
}
