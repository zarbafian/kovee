//! K1 privacy-access suite: the internal, developer-labeled
//! `PrivacyAccessRecord` chain (family PROFILE §7, D-R0-1) on allowed
//! AND denied sensitive reads — chained `scope_erasure_safe` record
//! digests under the per-chain key, genesis link wholly absent, and the
//! release rule (the record commits before sensitive bytes are served).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use kovee_core::family::{hex, hmac_sha256, tagged_canonical, DigestRef, PRIVACY_RECORD_TAG};
use serde_json::{json, Value};

#[test]
fn sensitive_reads_chain_records_on_allow_and_deny() {
    let base = tmp("k1-privacy");
    let data = base.join("data");
    let run = base.join("run");
    let daemon = DaemonProc::start(&data, &run, None);
    let (project, space, branch, head) = setup_space(&daemon);

    // One ordinary and one sensitive contribution.
    let (_plain_id, _, head) = append(
        &daemon,
        &project,
        &space,
        &branch,
        &head,
        "idem-plain",
        "utterance",
        "nothing sensitive here",
        json!({}),
    );
    let (sensitive_id, _, _head) = append(
        &daemon,
        &project,
        &space,
        &branch,
        &head,
        "idem-sensitive",
        "evidence",
        "the sensitive payload bytes",
        json!({"classification_ref": "class-sensitive"}),
    );

    // A second project scopes the denied read.
    let other = daemon.expect_ok(&mutation(
        "project_create",
        None,
        "idem-p2",
        json!({"name": "other"}),
    ));
    let other_project = other["result"]["project_id"].as_str().unwrap();

    // Allowed sensitive read: served, and recorded BEFORE release.
    let shown = daemon.expect_ok(&read_cmd(
        "contribution_show",
        Some(&project),
        json!({"contribution_id": sensitive_id}),
    ));
    assert_eq!(
        shown["result"]["classification_ref"].as_str(),
        Some("class-sensitive")
    );

    // A non-sensitive read chains nothing.
    let _ = daemon.expect_ok(&read_cmd(
        "contribution_show",
        Some(&project),
        json!({"contribution_id": _plain_id}),
    ));

    // Denied sensitive read (wrong project scope): uniform not-found,
    // still chained.
    daemon.expect_problem(
        &read_cmd(
            "contribution_show",
            Some(other_project),
            json!({"contribution_id": sensitive_id}),
        ),
        "not-found",
    );

    // A sensitive list read chains one more allowed record.
    let listed = daemon.expect_ok(&read_cmd(
        "contribution_list",
        Some(&project),
        json!({"space_id": space, "limit": 100}),
    ));
    assert_eq!(listed["result"]["items"].as_array().unwrap().len(), 2);

    drop(daemon);

    // Verify the chain offline against the store: exact PROFILE §7
    // construction under the per-chain scope key.
    let store = kovee_store::Store::open(&data.join("kovee.db")).unwrap();
    let verified = kovee_store::privacy::verify_chain(&store).unwrap();
    assert_eq!(verified, 3, "show-allowed, show-denied, list-allowed");

    let chain_key = store.privacy_chain_key().unwrap();
    let mut stmt = store
        .conn()
        .prepare(
            "SELECT record FROM privacy_access_records
             ORDER BY internal_access_sequence ASC",
        )
        .unwrap();
    let records: Vec<Value> = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(|r| serde_json::from_str(&r.unwrap()).unwrap())
        .collect();
    assert_eq!(records.len(), 3);

    // Record 1: allowed show; genesis — previous_access_digest is
    // WHOLLY ABSENT (never a null-valued pseudo-ref).
    let first = &records[0];
    assert_eq!(first["operation"].as_str(), Some("contribution_show"));
    assert_eq!(first["outcome"].as_str(), Some("allowed"));
    assert_eq!(first["result_object_count"].as_u64(), Some(1));
    assert!(first["result_bytes"].as_u64().unwrap() > 0);
    assert!(first.get("previous_access_digest").is_none());
    assert_eq!(first["society_id"].as_str(), Some("realm-personal"));
    // Never result plaintext.
    assert!(!first.to_string().contains("sensitive payload"));

    // Record 2: the DENIED read still chained, linked to record 1.
    let second = &records[1];
    assert_eq!(second["operation"].as_str(), Some("contribution_show"));
    assert_eq!(second["outcome"].as_str(), Some("denied"));
    assert_eq!(second["result_object_count"].as_u64(), Some(0));
    let link: DigestRef = serde_json::from_value(second["previous_access_digest"].clone()).unwrap();
    let first_digest: DigestRef = serde_json::from_value(first["record_digest"].clone()).unwrap();
    assert_eq!(link.value_hex, first_digest.value_hex);

    // Record 3: the allowed list read.
    let third = &records[2];
    assert_eq!(third["operation"].as_str(), Some("contribution_list"));
    assert_eq!(third["outcome"].as_str(), Some("allowed"));
    assert_eq!(third["result_object_count"].as_u64(), Some(1));

    // Every digest is a typed scope_erasure_safe ref under the chain
    // key (D-R0-1: a scope key, never per-object, never a public hash),
    // and re-derives by hand from the tagged preimage.
    for record in &records {
        let stored: DigestRef = serde_json::from_value(record["record_digest"].clone()).unwrap();
        assert_eq!(stored.class, "scope_erasure_safe");
        assert_eq!(stored.algorithm, "hmac-sha-256");
        assert_eq!(
            stored.key_ref.as_deref(),
            Some("kovee-privacy-chain:realm-personal")
        );
        let mut preimage_record = record.clone();
        preimage_record
            .as_object_mut()
            .unwrap()
            .remove("record_digest");
        let preimage = tagged_canonical(PRIVACY_RECORD_TAG, &preimage_record).unwrap();
        assert_eq!(
            stored.value_hex,
            hex(&hmac_sha256(&chain_key, &preimage)),
            "record digest re-derives under the chain key"
        );
    }
}
