//! Erasure proof (R1: KV-A5-1, KV-A5-2, D-R1-2).
//!
//! These tests do not inspect a wire projection and call it erasure. They
//! **grep the bytes on disk** — the whole database file, its WAL and
//! shared-memory files, and the artifact store — for the plaintext and
//! for the digest a plaintext-derived construction would have produced,
//! after building exactly the retention-graph copies the R1 review found
//! surviving: a stored idempotency replay result, a relation created
//! BEFORE the redaction, audit rows, event payloads, and a branch fold.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::Path;

use common::*;
use serde_json::{json, Value};

/// Every byte the store keeps on disk: the database, its WAL, its shared
/// memory, and the artifact store.
fn all_stored_bytes(data_dir: &Path) -> Vec<u8> {
    let mut bytes = Vec::new();
    fn walk(dir: &Path, out: &mut Vec<u8>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if let Ok(mut content) = std::fs::read(&path) {
                out.append(&mut content);
                // A separator so a needle cannot be assembled across
                // two files by accident.
                out.push(0);
            }
        }
    }
    walk(data_dir, &mut bytes);
    assert!(!bytes.is_empty(), "the data directory must not be empty");
    bytes
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    contains_bytes(haystack, needle.as_bytes())
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// The exact content projection `contribution_append` keys its digest
/// over — the preimage the confirmation's probe re-derives from.
fn content_projection(
    space: &str,
    branch: &str,
    branch_sequence: u64,
    kind: &str,
    text: &str,
) -> Value {
    json!({
        "space_id": space,
        "origin_branch_id": branch,
        "origin_branch_sequence": branch_sequence,
        "kind": kind,
        "body_parts": [{"media_type": "text/plain", "text": text}],
        "subject_refs": [],
        "source_refs": [],
        "epistemic_posture": null,
    })
}

/// The wrapped per-object secret a contribution row still retains, if any.
fn retained_wrap(db: &Path, contribution_id: &str) -> Option<Vec<u8>> {
    let conn = rusqlite::Connection::open(db).unwrap();
    conn.query_row(
        "SELECT object_secret FROM contributions WHERE contribution_id = ?1",
        [contribution_id],
        |r| r.get::<_, Option<Vec<u8>>>(0),
    )
    .unwrap()
}

fn realm_object_key(db: &Path) -> Vec<u8> {
    let conn = rusqlite::Connection::open(db).unwrap();
    conn.query_row(
        "SELECT value FROM meta WHERE key = 'realm_object_key'",
        [],
        |r| r.get(0),
    )
    .unwrap()
}

/// **The R1 confirmation's own probe.** Take whatever key material the
/// retained row still carries, open it with the realm key that is sitting
/// in `meta` right beside it, and recompute the object's stored HMAC
/// digest from the plaintext. `Ok(digest)` means the "erased" text is
/// still confirmable from what is on disk; `Err` means the key material
/// is gone and the digest can no longer be re-derived.
fn unwrap_and_rederive(
    db: &Path,
    contribution_id: &str,
    projection: &Value,
) -> Result<(String, Vec<u8>, [u8; 32]), String> {
    let wrapped = retained_wrap(db, contribution_id)
        .ok_or_else(|| "no key material is retained beside the object".to_owned())?;
    let key_ref = format!("kovee-contribution-object:{contribution_id}");
    let secret = kovee_store::objkey::unwrap(&realm_object_key(db), &key_ref, &wrapped)
        .map_err(|e| e.to_string())?;
    let preimage =
        kovee_core::family::tagged_canonical("kovee-contribution-content", projection).unwrap();
    let digest = kovee_core::family::hex(&kovee_core::family::hmac_sha256(&secret, &preimage));
    Ok((digest, wrapped, secret))
}

/// Appends one text contribution and returns
/// `(id, digest, origin_branch_sequence, new_head)`.
fn append_seq(
    daemon: &DaemonProc,
    project: &str,
    space: &str,
    branch: &str,
    head: &str,
    key: &str,
    text: &str,
) -> (String, String, u64, String) {
    let reply = daemon.expect_ok(&mutation(
        "contribution_append",
        Some(project),
        key,
        json!({
            "space_id": space,
            "branch_id": branch,
            "expected_head_digest": head,
            "kind": "claim",
            "body_parts": [{"media_type": "text/plain", "text": text}],
        }),
    ));
    let id = reply["result"]["contribution_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let digest = reply["result"]["content_digest"]
        .as_str()
        .unwrap()
        .to_owned();
    let seq = reply["result"]["origin_branch_sequence"].as_u64().unwrap();
    let new_head = kovee_core::branch::next_head(head, seq, &digest);
    (id, digest, seq, new_head)
}

/// KV-A5-1, re-probed exactly as the R1 confirmation probed it.
///
/// The first attempt scrubbed the plaintext but kept the 84-byte wrapped
/// contribution secret beside the redacted row. The confirmation
/// unwrapped it with the realm key and reproduced the supposedly-erased
/// plaintext's stored HMAC digest — so the erasure was worth nothing.
/// This test runs that same probe twice: it must SUCCEED before the
/// redaction (otherwise the probe proves nothing) and must be impossible
/// after it, with no wrap and no raw secret left anywhere in the data
/// directory. An unrelated contribution stays fully verifiable, and the
/// branch chain still folds.
#[test]
fn redaction_destroys_the_key_material_that_re_derives_the_erased_digest() {
    let base = tmp("k1-erasure-key-material");
    let data = base.join("data");
    let db = data.join("kovee.db");
    let daemon = DaemonProc::start(&data, &base.join("run"), None);
    let (project, space, branch, head) = setup_space(&daemon);

    let secret_text = "erase me: the passphrase is correct-horse-battery-staple";
    let other_text = "an unrelated claim that must stay verifiable";
    let (secret_id, secret_digest, secret_seq, head) = append_seq(
        &daemon,
        &project,
        &space,
        &branch,
        &head,
        "idem-secret",
        secret_text,
    );
    let (other_id, other_digest, other_seq, head) = append_seq(
        &daemon,
        &project,
        &space,
        &branch,
        &head,
        "idem-other",
        other_text,
    );
    let secret_projection = content_projection(&space, &branch, secret_seq, "claim", secret_text);
    let other_projection = content_projection(&space, &branch, other_seq, "claim", other_text);

    // ---- the probe, BEFORE redaction: it must work ----
    // If this ever stops reproducing the digest the probe is broken and
    // the post-redaction assertion below would prove nothing.
    let (rederived, wrapped, raw_secret) =
        unwrap_and_rederive(&db, &secret_id, &secret_projection).expect("the probe must work here");
    assert_eq!(
        rederived, secret_digest,
        "the confirmation's probe: unwrap the retained secret, re-derive the stored digest"
    );
    assert_eq!(
        wrapped.len(),
        kovee_store::objkey::WRAPPED_LEN,
        "the retained blob is the 84-byte wrap the confirmation opened"
    );
    let live = all_stored_bytes(&data);
    assert!(
        contains_bytes(&live, &wrapped),
        "the fixture must really hold the wrap before erasure"
    );

    // ---- redact ----
    daemon.expect_ok(&mutation(
        "contribution_redact",
        Some(&project),
        "idem-redact",
        json!({"contribution_ref": secret_id, "reason_class": "policy_erasure"}),
    ));

    // ---- the same probe, AFTER redaction: it must be impossible ----
    // Run the probe first, exactly as before. It must not get as far as a
    // digest; anything else means the erased plaintext is still
    // confirmable from the retained row.
    match unwrap_and_rederive(&db, &secret_id, &secret_projection) {
        Err(why) => assert!(why.contains("no key material"), "unexpected: {why}"),
        Ok((rederived, _, _)) => panic!(
            "the erased plaintext's digest was re-derived from the retained row \
             ({rederived}; stored {secret_digest})"
        ),
    }
    assert_eq!(
        retained_wrap(&db, &secret_id),
        None,
        "the redacted row still retains key material"
    );

    // And nowhere else either: the whole data directory — database, WAL,
    // shared memory, artifact store — carries neither the wrap nor the
    // raw secret it unwrapped to.
    let after = all_stored_bytes(&data);
    assert!(
        !contains_bytes(&after, &wrapped),
        "the wrapped contribution secret survives somewhere on disk"
    );
    assert!(
        !contains_bytes(&after, &raw_secret),
        "the raw per-object secret survives somewhere on disk"
    );
    assert!(!contains(&after, secret_text), "the plaintext survives");

    // The object keeps its address; that address is now unverifiable —
    // which is exactly what erasing this object's verifiability means.
    let shown = daemon.expect_ok(&read_cmd(
        "contribution_show",
        Some(&project),
        json!({"contribution_id": secret_id}),
    ));
    assert_eq!(
        shown["result"]["content_digest"].as_str(),
        Some(secret_digest.as_str())
    );

    // ---- the unrelated contribution is untouched: still verifiable ----
    let (other_rederived, other_wrap, _) = unwrap_and_rederive(&db, &other_id, &other_projection)
        .expect("an unrelated object keeps its own secret");
    assert_eq!(
        other_rederived, other_digest,
        "erasing one object must not erase another's verifiability"
    );
    assert!(
        contains_bytes(&after, &other_wrap),
        "the unrelated object's wrap is still on disk, as it must be"
    );

    // ---- the branch chain still folds (D-R1-2) ----
    // The redacted entry is no longer verifiable, but every entry still
    // folds: an authorized reader recomputes the head from the ledger and
    // the next append is accepted against it.
    let recomputed = kovee_core::branch::next_head(
        &kovee_core::branch::next_head(
            &kovee_core::branch::genesis_head(&branch),
            secret_seq,
            &secret_digest,
        ),
        other_seq,
        &other_digest,
    );
    assert_eq!(recomputed, head, "the fold is unchanged by the erasure");
    let (_, _, _) = append(
        &daemon,
        &project,
        &space,
        &branch,
        &recomputed,
        "idem-after-erasure",
        "claim",
        "the chain still folds after the secret is destroyed",
        json!({}),
    );
    let diagnosis = daemon.expect_ok(&read_cmd("diagnose", None, json!({})));
    assert_eq!(
        diagnosis["result"]["status"].as_str(),
        Some("pass"),
        "the audit chain must still verify: {diagnosis}"
    );
}

/// The digest the pre-R1 construction produced: an ordinary
/// canonical-object digest over the plaintext content projection. Nothing
/// in the store may equal it — that is the whole point of keying the
/// content digest from the first append.
fn plaintext_canonical_digest(
    space: &str,
    branch: &str,
    branch_sequence: u64,
    kind: &str,
    text: &str,
) -> String {
    let projection = json!({
        "space_id": space,
        "origin_branch_id": branch,
        "origin_branch_sequence": branch_sequence,
        "kind": kind,
        "body_parts": [{"media_type": "text/plain", "text": text}],
        "subject_refs": [],
        "source_refs": [],
        "epistemic_posture": null,
    });
    let (_, hexd) = kovee_core::canonical::canonical_object_digest(
        "kovee-contribution-content",
        "schema:contribution-body-v1",
        &projection,
    )
    .unwrap();
    hexd
}

#[test]
fn redaction_scrubs_every_retention_graph_copy_of_the_plaintext() {
    let base = tmp("k1-erasure-redaction");
    let data = base.join("data");
    let daemon = DaemonProc::start(&data, &base.join("run"), None);
    let (project, space, branch, head) = setup_space(&daemon);

    // The plaintext under test, and a second contribution to relate it to.
    let secret_text = "the launch code is 0000 and the vault word is orchid";
    let append_args = json!({
        "space_id": space,
        "branch_id": branch,
        "expected_head_digest": head,
        "kind": "claim",
        "body_parts": [{"media_type": "text/plain", "text": secret_text}],
    });
    let appended = daemon.expect_ok(&mutation(
        "contribution_append",
        Some(&project),
        "idem-secret",
        append_args.clone(),
    ));
    let secret_id = appended["result"]["contribution_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let secret_digest = appended["result"]["content_digest"]
        .as_str()
        .unwrap()
        .to_owned();
    let secret_seq = appended["result"]["origin_branch_sequence"]
        .as_u64()
        .unwrap();
    let head = kovee_core::branch::next_head(&head, secret_seq, &secret_digest);

    // The digest the old construction would have produced. It must never
    // appear anywhere — not before redaction and not after.
    let plaintext_digest =
        plaintext_canonical_digest(&space, &branch, secret_seq, "claim", secret_text);
    assert_ne!(
        plaintext_digest, secret_digest,
        "the content digest must not be the plaintext canonical digest"
    );
    assert!(
        !contains(&all_stored_bytes(&data), &plaintext_digest),
        "no plaintext-derived digest is ever written"
    );

    // A relation created BEFORE the redaction — the copy the R1 review
    // found surviving.
    let (other_id, other_digest, head) = append(
        &daemon,
        &project,
        &space,
        &branch,
        &head,
        "idem-other",
        "claim",
        "an unrelated claim",
        json!({}),
    );
    daemon.expect_ok(&mutation(
        "relation_assert",
        Some(&project),
        "idem-relation",
        json!({
            "space_id": space,
            "branch_id": branch,
            "expected_head_digest": head,
            "kind": "addresses",
            "from_ref": {"object_ref": other_id, "revision": 1, "digest": other_digest},
            "to_ref": {"object_ref": secret_id, "revision": 1, "digest": secret_digest},
        }),
    ));

    // An idempotency replay row for the append: the stored bytes that
    // used to hand the plaintext back forever.
    let replayed = daemon.expect_ok(&mutation(
        "contribution_append",
        Some(&project),
        "idem-secret",
        append_args.clone(),
    ));
    assert_eq!(
        replayed["result"]["body_parts"][0]["text"].as_str(),
        Some(secret_text),
        "before redaction the replay returns the stored plaintext"
    );

    // The plaintext really is on disk in several places right now.
    let before = all_stored_bytes(&data);
    assert!(
        contains(&before, secret_text),
        "the fixture must actually contain the plaintext before redaction"
    );

    // ---- redact ----
    daemon.expect_ok(&mutation(
        "contribution_redact",
        Some(&project),
        "idem-redact",
        json!({"contribution_ref": secret_id, "reason_class": "policy_erasure"}),
    ));

    // The grep: nothing on disk holds the plaintext or a plaintext-derived
    // digest — database, WAL, shared memory, artifact store.
    let after = all_stored_bytes(&data);
    assert!(
        !contains(&after, secret_text),
        "the plaintext survives somewhere in the data directory"
    );
    assert!(
        !contains(&after, &plaintext_digest),
        "a plaintext-derived digest survives somewhere in the data directory"
    );

    // The object is still addressable by its keyed digest, and the
    // relation that pinned it still resolves.
    assert!(
        contains(&after, &secret_digest),
        "the keyed content address stays: it is not plaintext-derived"
    );
    let shown = daemon.expect_ok(&read_cmd(
        "contribution_show",
        Some(&project),
        json!({"contribution_id": secret_id}),
    ));
    assert_eq!(
        shown["result"]["content_digest"].as_str(),
        Some(secret_digest.as_str())
    );
    assert_eq!(
        shown["result"]["body_parts"][0]["media_type"].as_str(),
        Some("application/x.kovee.redacted")
    );

    // The stored replay result was scrubbed in the same transaction:
    // replaying the append now yields the redacted projection, never the
    // erased plaintext.
    let replay_after = daemon.expect_ok(&mutation(
        "contribution_append",
        Some(&project),
        "idem-secret",
        append_args,
    ));
    assert_eq!(
        replay_after["result"]["body_parts"][0]["media_type"].as_str(),
        Some("application/x.kovee.redacted"),
        "erasure wins over byte-identical replay"
    );
    assert_eq!(
        replay_after["result"]["contribution_id"].as_str(),
        Some(secret_id.as_str()),
        "the replay still answers for the same object"
    );

    // The audit chain and the keyed branch chain both still verify: the
    // head equals the fold over the ledger's entry digests, so an
    // authorized reader can still recompute it and keep appending.
    let diagnosis = daemon.expect_ok(&read_cmd("diagnose", None, json!({})));
    assert_eq!(
        diagnosis["result"]["status"].as_str(),
        Some("pass"),
        "the audit chain must still verify after an erasure rewrite: {diagnosis}"
    );
    let events = daemon.expect_ok(&events_read(&project));
    let mut recomputed = kovee_core::branch::genesis_head(&branch);
    let mut sequence = 0u64;
    for event in events["result"]["events"].as_array().unwrap() {
        let digest = match event["type"].as_str() {
            Some("dev.kovee.space.contribution-appended.v1") => event["payload"]["content_digest"]
                .as_str()
                .unwrap()
                .to_owned(),
            Some("dev.kovee.space.relation-asserted.v1") => {
                event["payload"]["digest"].as_str().unwrap().to_owned()
            }
            _ => continue,
        };
        sequence += 1;
        recomputed = kovee_core::branch::next_head(&recomputed, sequence, &digest);
    }
    let (_, _, _) = append(
        &daemon,
        &project,
        &space,
        &branch,
        &recomputed,
        "idem-after-erasure",
        "claim",
        "the chain is still recomputable from the ledger",
        json!({}),
    );
}

#[test]
fn redacting_a_contribution_erases_its_artifact_bytes_and_secret() {
    let base = tmp("k1-erasure-artifact");
    let data = base.join("data");
    let daemon = DaemonProc::start(&data, &base.join("run"), None);
    let (project, space, branch, head) = setup_space(&daemon);

    let payload = b"attachment plaintext: bearer token hunter2hunter2";
    let raw_hex = sha256_hex(payload);
    let begin = daemon.expect_ok(&mutation(
        "artifact_upload_begin",
        None,
        "idem-begin",
        json!({
            "declared_raw_sha256": raw_hex,
            "declared_size": payload.len(),
            "declared_media_type": "text/plain",
        }),
    ));
    // KV-A5-2: the declared checksum is transient — the begin result (and
    // therefore the stored replay bytes) never carries it back.
    assert!(
        begin["result"].get("declared_raw_sha256").is_none(),
        "the begin result must not echo the caller's raw checksum"
    );
    let upload_id = begin["result"]["upload_id"].as_str().unwrap().to_owned();
    let artifact_id = begin["result"]["artifact_id"].as_str().unwrap().to_owned();
    let credential = daemon.expect_ok(&read_cmd(
        "artifact_upload_credential",
        None,
        json!({"upload_id": upload_id}),
    ));
    let staging = credential["result"]["credential"]["path"]
        .as_str()
        .unwrap()
        .to_owned();
    std::fs::write(&staging, payload).unwrap();
    let finalized = daemon.expect_ok(&mutation(
        "artifact_upload_finalize",
        None,
        "idem-finalize",
        json!({"upload_id": upload_id}),
    ));
    assert_eq!(finalized["result"]["state"].as_str(), Some("completed"));
    assert!(
        finalized["result"].get("declared_raw_sha256").is_none(),
        "the finalize result must not carry the raw checksum either"
    );

    // The checksum is nowhere durable, even while the artifact is live.
    let live = all_stored_bytes(&data);
    assert!(
        !contains(&live, &raw_hex),
        "the declared raw checksum must never reach a durable row or result"
    );
    assert!(
        contains(&live, std::str::from_utf8(payload).unwrap()),
        "the sealed artifact bytes must actually be on disk before erasure"
    );

    // A contribution carries the artifact as a part.
    let appended = daemon.expect_ok(&mutation(
        "contribution_append",
        Some(&project),
        "idem-with-artifact",
        json!({
            "space_id": space,
            "branch_id": branch,
            "expected_head_digest": head,
            "kind": "claim",
            "body_parts": [
                {"media_type": "text/plain", "text": "see the attachment"},
                {"artifact_ref": artifact_id, "title": "attachment"},
            ],
        }),
    ));
    let contribution_id = appended["result"]["contribution_id"]
        .as_str()
        .unwrap()
        .to_owned();

    // ---- redact: the contribution AND its artifact ----
    daemon.expect_ok(&mutation(
        "contribution_redact",
        Some(&project),
        "idem-redact",
        json!({"contribution_ref": contribution_id, "reason_class": "policy_erasure"}),
    ));

    let after = all_stored_bytes(&data);
    assert!(
        !contains(&after, std::str::from_utf8(payload).unwrap()),
        "the artifact blob bytes survive erasure"
    );
    assert!(
        !contains(&after, &raw_hex),
        "the declared checksum survives erasure"
    );

    // The tombstone: identity kept, content and secret gone.
    let shown = daemon.expect_ok(&read_cmd(
        "artifact_show",
        None,
        json!({"artifact_id": artifact_id}),
    ));
    assert_eq!(shown["result"]["state"].as_str(), Some("erased"));
    assert_eq!(
        shown["result"]["artifact_id"].as_str(),
        Some(artifact_id.as_str()),
        "a tombstone still names the object"
    );
    assert!(shown["result"].get("size").is_none());
    assert!(shown["result"].get("sealed_storage_ref").is_none());
    assert!(
        !Path::new(&staging).exists(),
        "the staging copy is gone too"
    );
}

fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let digest = <sha2::Sha256 as sha2::Digest>::digest(bytes);
    digest.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

/// The per-object secrets are RANDOM and WRAPPED (D-R1-2), not derived
/// from a store root: two contributions with byte-identical content get
/// different content digests, and neither secret is readable as raw key
/// material beside its object.
#[test]
fn per_object_secrets_are_random_and_wrapped_not_root_derived() {
    let base = tmp("k1-erasure-secrets");
    let data = base.join("data");
    let daemon = DaemonProc::start(&data, &base.join("run"), None);
    let (project, space, branch, head) = setup_space(&daemon);

    let text = "identical content in two objects";
    let (_a_id, a_digest, head) = append(
        &daemon,
        &project,
        &space,
        &branch,
        &head,
        "idem-a",
        "claim",
        text,
        json!({}),
    );
    let (b_id, b_digest, _head) = append(
        &daemon,
        &project,
        &space,
        &branch,
        &head,
        "idem-b",
        "claim",
        text,
        json!({}),
    );
    assert_ne!(
        a_digest, b_digest,
        "identical content under different per-object secrets must not collide \
         (a root-derived key would make this a plaintext equality oracle)"
    );

    // Every stored secret opens only under the realm key for its own
    // object: the blob beside the object is a wrap, not the key.
    let db = data.join("kovee.db");
    let conn = rusqlite::Connection::open(&db).unwrap();
    let stored: Vec<u8> = conn
        .query_row(
            "SELECT object_secret FROM contributions WHERE contribution_id = ?1",
            [&b_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        stored.len(),
        kovee_store::objkey::WRAPPED_LEN,
        "the stored secret is a wrap, not 32 raw key bytes"
    );
    assert!(stored.starts_with(b"kow1"));
    let realm_key: Vec<u8> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'realm_object_key'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let key_ref = format!("kovee-contribution-object:{b_id}");
    let secret = kovee_store::objkey::unwrap(&realm_key, &key_ref, &stored).unwrap();
    // The digest really is the HMAC of the tagged content projection
    // under this object's own secret.
    let projection: Value = json!({
        "space_id": space,
        "origin_branch_id": branch,
        "origin_branch_sequence": 2,
        "kind": "claim",
        "body_parts": [{"media_type": "text/plain", "text": text}],
        "subject_refs": [],
        "source_refs": [],
        "epistemic_posture": null,
    });
    let preimage =
        kovee_core::family::tagged_canonical("kovee-contribution-content", &projection).unwrap();
    assert_eq!(
        kovee_core::family::hex(&kovee_core::family::hmac_sha256(&secret, &preimage)),
        b_digest,
        "the content digest is the keyed HMAC under this object's secret"
    );
    // And the wrap is bound to its object: another object's ref cannot
    // open it, so erasing one secret cannot erase another's.
    assert!(kovee_store::objkey::unwrap(
        &realm_key,
        "kovee-contribution-object:contrib-other",
        &stored
    )
    .is_err());
}

/// The pre-V5 shape the R1 review actually found in the retained K1
/// database: a contribution whose `content_digest` is the PLAINTEXT
/// canonical digest, copied into the branch ledger, the event payload,
/// the stored idempotency result, and the audit log. Redaction has to
/// re-key the object and sweep every one of those copies — and leave the
/// audit chain and the branch fold verifiable.
#[test]
fn a_legacy_plaintext_digest_is_rekeyed_and_every_copy_is_swept() {
    let base = tmp("k1-erasure-legacy");
    let data = base.join("data");
    let run = base.join("run");
    let daemon = DaemonProc::start(&data, &run, None);
    let (project, space, branch, head) = setup_space(&daemon);

    let secret_text = "legacy plaintext: the sealed bid is 4 200 000";
    let append_args = json!({
        "space_id": space,
        "branch_id": branch,
        "expected_head_digest": head,
        "kind": "claim",
        "body_parts": [{"media_type": "text/plain", "text": secret_text}],
    });
    let appended = daemon.expect_ok(&mutation(
        "contribution_append",
        Some(&project),
        "idem-legacy",
        append_args,
    ));
    let id = appended["result"]["contribution_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let keyed = appended["result"]["content_digest"]
        .as_str()
        .unwrap()
        .to_owned();
    let seq = appended["result"]["origin_branch_sequence"]
        .as_u64()
        .unwrap();
    let plaintext_digest = plaintext_canonical_digest(&space, &branch, seq, "claim", secret_text);
    drop(daemon);

    // Rewind this row to the pre-fix construction, copies and all.
    {
        let conn = rusqlite::Connection::open(data.join("kovee.db")).unwrap();
        conn.execute(
            "UPDATE contributions SET content_digest = ?2, content_digest_ref = NULL,
                 object_secret = NULL
             WHERE contribution_id = ?1",
            rusqlite::params![id, plaintext_digest],
        )
        .unwrap();
        conn.execute(
            "UPDATE branch_entries SET object_digest = ?2 WHERE object_ref = ?1",
            rusqlite::params![id, plaintext_digest],
        )
        .unwrap();
        let swap = |text: &str| text.replace(&keyed, &plaintext_digest);
        let events: Vec<(String, String)> = {
            let mut stmt = conn
                .prepare("SELECT event_id, payload FROM events WHERE resource_ref = ?1")
                .unwrap();
            let mapped = stmt
                .query_map([&id], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap();
            mapped.collect::<Result<_, _>>().unwrap()
        };
        for (event_id, payload) in events {
            conn.execute(
                "UPDATE events SET payload = ?2 WHERE event_id = ?1",
                rusqlite::params![event_id, swap(&payload)],
            )
            .unwrap();
        }
        let records: Vec<(String, Vec<u8>)> = {
            let mut stmt = conn
                .prepare("SELECT idempotency_key, result FROM idempotency_records")
                .unwrap();
            let mapped = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
            mapped.collect::<Result<_, _>>().unwrap()
        };
        for (key, result) in records {
            let text = String::from_utf8(result).unwrap();
            conn.execute(
                "UPDATE idempotency_records SET result = ?2 WHERE idempotency_key = ?1",
                rusqlite::params![key, swap(&text).as_bytes()],
            )
            .unwrap();
        }
        // …and the audit detail, re-linked so the chain still verifies.
        let rows: Vec<(i64, String)> = {
            let mut stmt = conn.prepare("SELECT seq, detail FROM audit").unwrap();
            let mapped = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
            mapped.collect::<Result<_, _>>().unwrap()
        };
        let rewrites: Vec<(i64, String)> = rows
            .into_iter()
            .filter(|(_, detail)| detail.contains(&keyed))
            .map(|(seq, detail)| (seq, swap(&detail)))
            .collect();
        assert!(!rewrites.is_empty(), "the audit row must carry the digest");
        kovee_store::audit::rewrite_details(&conn, &rewrites).unwrap();
    }

    let daemon = DaemonProc::start(&data, &run, None);
    let before = all_stored_bytes(&data);
    assert!(
        contains(&before, &plaintext_digest),
        "the legacy fixture must really hold the plaintext digest"
    );
    daemon.expect_ok(&mutation(
        "contribution_redact",
        Some(&project),
        "idem-redact",
        json!({"contribution_ref": id, "reason_class": "policy_erasure"}),
    ));

    let after = all_stored_bytes(&data);
    assert!(!contains(&after, secret_text), "the plaintext survived");
    assert!(
        !contains(&after, &plaintext_digest),
        "a copy of the plaintext canonical digest survived"
    );
    // Re-keyed under a fresh wrapped secret.
    let shown = daemon.expect_ok(&read_cmd(
        "contribution_show",
        Some(&project),
        json!({"contribution_id": id}),
    ));
    let rekeyed = shown["result"]["content_digest"].as_str().unwrap();
    assert_ne!(rekeyed, plaintext_digest);
    assert_eq!(rekeyed.len(), 64);

    // The audit chain still verifies after its rewrite, and the branch
    // head is the fold over the (re-keyed) ledger entries.
    let diagnosis = daemon.expect_ok(&read_cmd("diagnose", None, json!({})));
    assert_eq!(
        diagnosis["result"]["status"].as_str(),
        Some("pass"),
        "audit chain after erasure rewrite: {diagnosis}"
    );
    let expected_head =
        kovee_core::branch::next_head(&kovee_core::branch::genesis_head(&branch), seq, rekeyed);
    let (_, _, _) = append(
        &daemon,
        &project,
        &space,
        &branch,
        &expected_head,
        "idem-after-rekey",
        "claim",
        "the recomputed keyed chain still accepts appends",
        json!({}),
    );
}
