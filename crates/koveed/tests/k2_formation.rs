//! K2 slice 2 — the endeavor-promotion saga against the REAL `byomd`.
//!
//! No stub anywhere in this file: it builds and spawns byom's daemon,
//! bootstraps a Society natively (the genesis path Kovee is never allowed
//! to take), installs the inert host binding Kovee derived from its own
//! ACTIVE seam, and then drives `endeavor_promotion_*` against that live
//! endpoint over the delegated-principal channel.
//!
//! | branch | proof |
//! |---|---|
//! | happy path, `prepared → … → linked` | `a_promotion_forms_one_endeavor_against_a_real_byomd` |
//! | five-fact `committed` | same test's reconcile half |
//! | five-fact `absent` → `awaiting_principal` | `a_verified_absence_holds_the_slot_and_a_fresh_principal_resubmits` |
//! | five-fact `non_reexecuting_tombstone` | `formation_requires_participation_leaves_no_endeavor_and_records_the_tombstone` |
//! | five-fact `unknown` → `ambiguous`, and R40 terminalization | `an_unknown_fact_is_a_conservative_hold_that_never_releases` |
//! | five-fact `historically_fenced_absent` | `a_historically_fenced_absence_releases_the_slot_without_a_tombstone` |
//! | crash at every saga commit point | `every_saga_commit_point_forms_exactly_once` |
//! | pre-send cancel is the only local release | `a_pre_send_cancel_is_the_only_local_release` |
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::byomd::*;
use common::*;
use kovee_byom::credential::GATEWAY_ISSUER_REF;
use kovee_byom::formation::{Fact, IntentState, Move};
use kovee_byom::hostint;
use kovee_byom::records::{KoveeRealmByomBinding, KoveeSocietyMapping};
use serde_json::{json, Value};

const SCOPE: &str = "project:*";
const ENDPOINT_ROOT: &str = "endpoint-root-k2";

struct Fx {
    byomd: Byomd,
    daemon: DaemonProc,
    society: String,
    participant: String,
    participant_epoch: u64,
    binding_ref: String,
    project: String,
    frontier: String,
    assembly: String,
    base: std::path::PathBuf,
}

/// The whole seam, end to end: a real byomd with a native Society, a Kovee
/// realm with an ACTIVE governed-work binding, and byomd configured with
/// the inert host binding Kovee derived from that binding.
fn fixture(tag: &str, abort: Option<&str>) -> Option<Fx> {
    let repo = byom_repo()?;
    let binary = byomd_binary(&repo);
    let base = tmp(tag);
    let mut byomd = Byomd::start(&binary, &base.join("byom-data"), &base.join("byom-run"));
    let incarnation = byomd.incarnation();
    let society = bootstrap_society(&byomd, &incarnation);
    let (participant, participant_epoch) = sovereign_participant(&byomd, &society);

    let run_dir = base.join("byom-run").to_string_lossy().into_owned();
    let channels = byomd.channels_dir().to_string_lossy().into_owned();
    let daemon = DaemonProc::start_with_env(
        &base.join("kovee-data"),
        &base.join("kovee-run"),
        abort,
        &[
            ("KOVEE_BYOM_RUNTIME_DIR", run_dir.as_str()),
            ("KOVEE_BYOM_CHANNELS_DIR", channels.as_str()),
        ],
    );

    // The greenfield saga, against the live endpoint (K2 slice 1).
    let enabled = daemon.expect_ok(&mutation(
        "governance_enable",
        None,
        "idem-enable-1",
        json!({
            "byom_endpoint_ref": "local",
            "society_ref": society,
            "exact_scope_selector": SCOPE,
            "allowed_project_and_space_selectors": [SCOPE],
            "classification_binding_ref": "class-bind-k2",
            "expected_owner_revision": 0,
        }),
    ));
    assert_eq!(enabled["result"]["state"], json!("active"));
    let binding: KoveeRealmByomBinding =
        serde_json::from_value(enabled["result"]["binding"].clone()).unwrap();
    let mapping: KoveeSocietyMapping =
        serde_json::from_value(enabled["result"]["mapping"].clone()).unwrap();

    // Amendment A2's "Kovee may start/configure/bind byomd and supply
    // inert context only": the wire projection of the very binding Kovee
    // committed, with the CROSS-BOUNDARY portable digests byomd recomputes.
    let document = hostint::host_binding_document(
        &binding,
        &mapping,
        &[GATEWAY_ISSUER_REF.to_owned()],
        ENDPOINT_ROOT,
    )
    .unwrap();
    let binding_ref = document["realm_byom_binding"]["binding_ref"]
        .as_str()
        .unwrap()
        .to_owned();
    byomd.install_host_binding(&document);
    // A restart publishes the narrow recovery-workload token; the endpoint
    // incarnation is persistent, so this is not a re-incarnation.
    byomd.restart(&[]);
    assert_eq!(byomd.incarnation(), incarnation, "a restart re-incarnated");
    assert!(
        byomd.recovery_token(&binding_ref).is_some(),
        "byomd published no recovery-workload token for {binding_ref}"
    );

    // The Kovee side of the bundle: a space, a pinned frontier, and a
    // ContextAssembly taken AT that frontier.
    let (project, space, branch, head) = setup_space(&daemon);
    let (question, _, _) = append(
        &daemon,
        &project,
        &space,
        &branch,
        &head,
        "idem-q",
        "question",
        "what should we take on?",
        json!({}),
    );
    let assembled = daemon.expect_ok(&mutation(
        "context_assembly_create",
        Some(&project),
        "idem-assembly",
        json!({
            "space_id": space, "branch_id": branch,
            "audience_ref": "asstdep-dep-local-dev",
            "purpose": "endeavor promotion",
            "selection_policy_ref": "explicit_refs_v1",
            "required_refs": [question],
            "trigger_refs": [question],
        }),
    ));
    let assembly = assembled["result"]["assembly_id"]
        .as_str()
        .unwrap()
        .to_owned();
    // The assembly pins the frontier it was taken at; the formation pins
    // exactly that one, so the bundle and the intent cannot disagree.
    let frontier = assembled["result"]["frontier_ref"]
        .as_str()
        .unwrap()
        .to_owned();

    Some(Fx {
        byomd,
        daemon,
        society,
        participant,
        participant_epoch,
        binding_ref,
        project,
        frontier,
        assembly,
        base,
    })
}

impl Fx {
    /// The canonical EndeavorProposal subject — the shape byom's B0.1
    /// `endeavor_propose` subject owns, carried opaque.
    fn proposal(&self, sponsors: Vec<&str>) -> Value {
        json!({
            "purpose_ref": "purp-k2-1",
            "purpose_digest": {
                "class": "portable_public", "algorithm": "sha-256",
                "value_hex": "1".repeat(64),
            },
            "sponsor_participant_refs": sponsors,
            "governance_rule_set_ref": "rules-k2-1",
            "outcome_schema_refs": ["outcome-k2-1"],
            "acceptance_rule_ref": "accept-k2-1",
            "classification_join_ref": "class-join-k2-1",
            "budget_account_set_ref": "budget-k2-1",
        })
    }

    fn prepare_args(&self, key: &str, sponsors: Vec<&str>) -> Value {
        json!({
            "byom_endpoint_ref": "local",
            "society_ref": self.society,
            "frontier_ref": self.frontier,
            "collaboration_context_bundle_ref": self.assembly,
            "bound_participant_ref": self.participant,
            "participant_binding_epoch": self.participant_epoch,
            "client_formation_key": key,
            "endeavor_proposal_ref": "prop-k2-1",
            "endeavor_proposal": self.proposal(sponsors),
            "source_principal_position": {
                "participant_ref": self.participant,
                "value": "assent",
                "assent_mode": "direct_participant",
            },
        })
    }

    fn prepare(&self, key: &str, sponsors: Vec<&str>) -> String {
        let prepared = self.daemon.expect_ok(&mutation(
            "endeavor_promotion_prepare",
            None,
            &format!("idem-prepare-{key}"),
            self.prepare_args(key, sponsors),
        ));
        assert_eq!(prepared["result"]["state"], json!("prepared"));
        assert_eq!(prepared["result"]["slot"]["state"], json!("held"));
        prepared["result"]["formation_id"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    fn start_cmd(&self, formation: &str, observation: &str) -> Value {
        mutation(
            "endeavor_promotion_start",
            None,
            &format!("idem-start-{observation}"),
            json!({
                "formation_id": formation,
                "authentication_observation_ref": observation,
            }),
        )
    }

    fn reconcile_cmd(&self, formation: &str, key: &str) -> Value {
        mutation(
            "endeavor_promotion_reconcile",
            None,
            &format!("idem-reconcile-{key}"),
            json!({"formation_id": formation}),
        )
    }

    fn show(&self, formation: &str) -> Value {
        self.daemon.expect_ok(&read_cmd(
            "endeavor_promotion_show",
            None,
            json!({"formation_id": formation}),
        ))["result"]
            .clone()
    }
}

fn skip(tag: &str) {
    println!("{tag}: skipped — no byom repository (set KOVEE_BYOM_REPO or check out ../byom)");
}

// ------------------------------------------------------------ happy path ----

#[test]
fn a_promotion_forms_one_endeavor_against_a_real_byomd() {
    let Some(fx) = fixture("k2-formation-happy", None) else {
        return skip("k2_formation");
    };
    let formation = fx.prepare("form-key-happy", vec![&fx.participant]);

    // prepare made NO external contact: byomd has no Endeavor yet.
    assert!(endeavors(&fx).is_empty(), "prepare contacted byomd");

    let linked = fx
        .daemon
        .expect_ok(&fx.start_cmd(&formation, "authobs-happy-1"));
    let view = &linked["result"];
    assert_eq!(view["state"], json!("linked"), "{view}");
    assert_eq!(view["slot"]["state"], json!("released"));
    let endeavor_ref = view["external_link"]["endeavor_ref"]
        .as_str()
        .expect("an ExternalLink")
        .to_owned();

    // byomd formed exactly ONE Endeavor, and it is the linked one.
    let formed = endeavors(&fx);
    assert_eq!(formed.len(), 1, "{formed:?}");
    assert_eq!(formed[0]["endeavor_id"], json!(endeavor_ref));
    assert_eq!(formed[0]["state"], json!("active"));

    // The stored envelope is byom's own bytes, and its digest covers them.
    let envelope = view["byom_result"].clone();
    assert_eq!(envelope["endeavor_ref"], json!(endeavor_ref));
    let recomputed = hostint::self_digest(hostint::RESULT_TAG, &envelope).unwrap();
    assert_eq!(
        serde_json::to_value(&recomputed).unwrap(),
        envelope["digest"],
        "the result digest must cover the exact stored bytes"
    );

    // ONE attempt, terminal, with its send time recorded.
    let attempts = view["attempts"].as_array().unwrap();
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0]["state"], json!("reply_received"));
    assert!(!attempts[0]["sent_at"].is_null());

    // The five-fact `committed` arm, from byomd's retained signed fact.
    let again = fx
        .daemon
        .expect_ok(&fx.reconcile_cmd(&formation, "committed"));
    assert_eq!(again["result"]["state"], json!("linked"));
    let query = raw_query(&fx, &formation);
    assert_eq!(query["result"]["status"], json!("committed"), "{query}");
    let fact = Fact::from_query_result(&query["result"]).unwrap();
    assert!(matches!(fact, Fact::Committed(_)), "{fact:?}");

    // A retry of the whole start is byte-identical: one Endeavor, always.
    let a = fx
        .daemon
        .request_raw(&fx.start_cmd(&formation, "authobs-happy-1"))
        .unwrap();
    let b = fx
        .daemon
        .request_raw(&fx.start_cmd(&formation, "authobs-happy-1"))
        .unwrap();
    assert_eq!(a, b);
    assert_eq!(endeavors(&fx).len(), 1);
}

// ------------------------------------------------------ five-fact absent ----

#[test]
fn a_verified_absence_holds_the_slot_and_a_fresh_principal_resubmits() {
    let Some(fx) = fixture("k2-formation-absent", None) else {
        return skip("k2_formation");
    };
    let formation = fx.prepare("form-key-absent", vec![&fx.participant]);

    // Hide the governance socket PATH: the send cannot reach byomd, so the
    // outcome is UNKNOWN — and an unknown outcome is not a transition to
    // "nothing happened".
    fx.byomd.hide_governance_socket();
    let reply = fx
        .daemon
        .request(&fx.start_cmd(&formation, "authobs-absent-1"));
    assert_eq!(reply["outcome"], json!("problem"), "{reply}");
    let view = fx.show(&formation);
    assert_eq!(view["state"], json!("remote_unknown"));
    assert_eq!(view["slot"]["state"], json!("remote_unknown"));
    assert_eq!(view["attempts"][0]["state"], json!("transport_unknown"));
    fx.byomd.restore_governance_socket();

    // byomd's OWN answer: a complete query of the live target domain finds
    // neither result nor tombstone.
    let query = raw_query(&fx, &formation);
    assert_eq!(query["result"]["status"], json!("absent"), "{query}");
    assert_eq!(
        Fact::from_query_result(&query["result"]).unwrap(),
        Fact::Absent
    );

    let reconciled = fx.daemon.expect_ok(&fx.reconcile_cmd(&formation, "absent"));
    let view = &reconciled["result"];
    // Absence proves nothing about later arrival: NO release, ever.
    assert_eq!(view["state"], json!("awaiting_principal"));
    assert_eq!(view["slot"]["state"], json!("awaiting_principal"));
    assert!(view["external_link"].is_null());

    // Reusing the previous attempt's observation is not freshness.
    let stale = fx
        .daemon
        .request(&fx.start_cmd(&formation, "authobs-absent-1"));
    assert_eq!(stale["problem"]["type"], json!("urn:kovee:error:forbidden"));
    assert_eq!(
        stale["problem"]["title"],
        json!("resubmission requires a freshly authenticated principal"),
        "{stale}"
    );

    // A FRESHLY authenticated principal resubmits the exact stored bytes.
    let before = fx.show(&formation)["canonical_byom_command_digest"].clone();
    let linked = fx
        .daemon
        .expect_ok(&fx.start_cmd(&formation, "authobs-absent-2"));
    let view = &linked["result"];
    assert_eq!(view["state"], json!("linked"), "{view}");
    assert_eq!(
        view["canonical_byom_command_digest"], before,
        "a resubmission must preserve the semantic command bytes"
    );
    // Two attempts, append-only: the first attempt's evidence survives.
    let attempts = view["attempts"].as_array().unwrap();
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0]["state"], json!("reconciled"));
    assert_eq!(
        attempts[0]["authentication_observation_ref"],
        json!("authobs-absent-1")
    );
    assert_eq!(attempts[1]["state"], json!("reply_received"));
    assert_ne!(attempts[0]["attempt_nonce"], attempts[1]["attempt_nonce"]);
    // And the same idempotency domain formed exactly one Endeavor.
    assert_eq!(endeavors(&fx).len(), 1);
}

// --------------------------------------------------- five-fact tombstone ----

#[test]
fn formation_requires_participation_leaves_no_endeavor_and_records_the_tombstone() {
    let Some(fx) = fixture("k2-formation-tombstone", None) else {
        return skip("k2_formation");
    };
    // TWO required seats: the sole-computed-seat rule of §16.3 does not
    // hold, so byomd's DEFINITE pre-commit rejection claims the exact
    // IdempotencyDomain with a non-reexecuting tombstone.
    let formation = fx.prepare(
        "form-key-tombstone",
        vec![&fx.participant, "part-someone-else"],
    );
    let refused = fx
        .daemon
        .request(&fx.start_cmd(&formation, "authobs-tomb-1"));
    assert_eq!(refused["outcome"], json!("problem"), "{refused}");
    assert!(
        refused["problem"]["detail"]
            .as_str()
            .unwrap()
            .contains("non-reexecuting tombstone"),
        "{refused}"
    );

    // No Kovee-side endeavor, no ExternalLink — and the slot RELEASED,
    // because byom has claimed the domain and must reject every future
    // execution under it.
    let view = fx.show(&formation);
    assert_eq!(view["state"], json!("canceled"));
    assert_eq!(view["slot"]["state"], json!("released"));
    assert!(view["external_link"].is_null());
    assert!(view["byom_result"].is_null());
    assert!(endeavors(&fx).is_empty(), "an Endeavor was created anyway");

    // The tombstone is recorded, and byomd's signed five-fact query agrees.
    let events = promotion_events(&fx, &formation);
    let canceled = events
        .iter()
        .find(|e| e["type"] == json!("dev.kovee.endeavor-formation.canceled.v1"))
        .unwrap_or_else(|| panic!("no canceled transition among {events:?}"));
    assert_eq!(
        canceled["payload"]["via"],
        json!(Move::TombstoneVerified.as_str())
    );
    assert_eq!(
        canceled["payload"]["reason_kind"],
        json!("formation_requires_participation")
    );
    assert!(
        canceled["payload"]["tombstone_ref"].is_string(),
        "{canceled}"
    );

    let query = raw_query(&fx, &formation);
    assert_eq!(
        query["result"]["status"],
        json!("non_reexecuting_tombstone"),
        "{query}"
    );
    assert_eq!(
        Fact::from_query_result(&query["result"]).unwrap(),
        Fact::Tombstone
    );
    // A terminal pair is reported, never re-driven.
    let after = fx
        .daemon
        .expect_ok(&fx.reconcile_cmd(&formation, "tombstone"));
    assert_eq!(after["result"]["state"], json!("canceled"));
}

// ----------------------------------------------------- five-fact unknown ----

#[test]
fn an_unknown_fact_is_a_conservative_hold_that_never_releases() {
    let Some(fx) = fixture("k2-formation-unknown", None) else {
        return skip("k2_formation");
    };

    // ---- byomd PRODUCES `unknown`. A retained row over this domain that
    // is bound to ANOTHER canonical command is not a fact about THIS
    // command: unverifiable, therefore unknown — never absent, and never
    // the other command's committed result.
    let committed = fx.prepare("form-key-unknown-a", vec![&fx.participant]);
    fx.daemon
        .expect_ok(&fx.start_cmd(&committed, "authobs-unknown-1"));
    let claimed = raw_query(&fx, &committed);
    assert_eq!(claimed["result"]["status"], json!("committed"));
    let other = raw_query_with(&fx, &committed, |request| {
        request["canonical_command_digest"] = json!({
            "class": "portable_public", "algorithm": "sha-256",
            "value_hex": "c".repeat(64),
        });
    });
    assert_eq!(
        other["result"]["status"],
        json!("unknown"),
        "a row for another command is unknown, never that command's result: {other}"
    );
    // The closed arms hold: an `unknown` answer carries no result, no
    // tombstone, and no fence receipt to lean on.
    assert!(other["result"].get("committed_result_envelope").is_none());
    assert!(other["result"].get("tombstone_ref").is_none());
    assert!(other["result"]
        .get("historical_fence_receipt_ref")
        .is_none());
    assert_eq!(
        Fact::from_query_result(&other["result"]).unwrap(),
        Fact::Unknown
    );

    // ---- and Kovee's machine holds on it. A second promotion is left
    // unresolved (the send could not reach byomd), and then the recovery
    // query itself cannot be answered: guessing is not a transition.
    let held = fx.prepare("form-key-unknown-b", vec![&fx.participant]);
    fx.byomd.hide_governance_socket();
    let lost = fx.daemon.request(&fx.start_cmd(&held, "authobs-unknown-2"));
    assert_eq!(lost["outcome"], json!("problem"), "{lost}");
    assert_eq!(fx.show(&held)["state"], json!("remote_unknown"));
    fx.byomd.restore_governance_socket();
    // Only the RECOVERY surface is unreachable now: the query cannot be
    // answered, so the fact is unknown rather than absent.
    fx.byomd.hide_projection_socket();
    let reconciled = fx.daemon.expect_ok(&fx.reconcile_cmd(&held, "unknown"));
    let view = &reconciled["result"];
    assert_eq!(view["state"], json!("ambiguous"), "{view}");
    // Ambiguity never releases the slot — conservative hold, no guessing.
    assert_eq!(view["slot"]["state"], json!("ambiguous"));
    assert!(view["external_link"].is_null());
    fx.byomd.restore_projection_socket();

    // ---- R40: from `ambiguous`, the SAME source human freshly
    // authenticated is the only actor who may deny future execution. byom
    // installs the restore-safe tombstone, which is what releases the pair.
    let terminalized = fx.daemon.expect_ok(&mutation(
        "endeavor_promotion_reconcile",
        None,
        "idem-reconcile-terminalize",
        json!({
            "formation_id": held,
            "terminalize": true,
            "authentication_observation_ref": "authobs-unknown-3",
            "reason": "the principal denies future execution",
        }),
    ));
    let view = &terminalized["result"];
    assert_eq!(view["state"], json!("canceled"), "{view}");
    assert_eq!(view["slot"]["state"], json!("released"));
    assert!(view["external_link"].is_null());
    // byomd agrees, and its own claim is a tombstone — not a result.
    let query = raw_query(&fx, &held);
    assert_eq!(
        query["result"]["status"],
        json!("non_reexecuting_tombstone"),
        "{query}"
    );
    // The committed promotion is untouched: exactly one Endeavor exists.
    assert_eq!(endeavors(&fx).len(), 1);
    assert_eq!(fx.show(&committed)["state"], json!("linked"));
}

// -------------------------------------- five-fact historically fenced ----

#[test]
fn a_historically_fenced_absence_releases_the_slot_without_a_tombstone() {
    // The fifth fact needs a SECOND endpoint incarnation joined to the
    // first by a complete externally witnessed RestoreLineage chain, which
    // only byom's §15.3 sealed restore protocol produces — no
    // test-reachable operation re-incarnates a live byomd. So this branch
    // is proven at the fact-verification and machine level: byomd's exact
    // envelope shape drives the exact row, and it is NEVER relabelled as
    // an idempotency tombstone that never existed.
    let envelope = json!({
        "status": "historically_fenced_absent",
        "restore_lineage_evidence_ref": "rlp-1",
        "restore_lineage_evidence_digest": {
            "class": "portable_public", "algorithm": "sha-256",
            "value_hex": "a".repeat(64),
        },
        "historical_fence_receipt_ref": "hfr-1",
        "historical_fence_receipt_digest": {
            "class": "portable_public", "algorithm": "sha-256",
            "value_hex": "b".repeat(64),
        },
    });
    let fact = Fact::from_query_result(&envelope).unwrap();
    assert_eq!(
        fact,
        Fact::HistoricallyFencedAbsent {
            receipt_ref: "hfr-1".to_owned()
        }
    );
    // The signed fence receipt proves the old command can no longer
    // arrive, so the slot releases — via its OWN transition, not the
    // tombstone one.
    for from in [
        IntentState::Prepared,
        IntentState::Submitting,
        IntentState::RemoteUnknown,
        IntentState::AwaitingPrincipal,
        IntentState::Ambiguous,
    ] {
        let step = kovee_byom::formation::resolve(from, &fact).unwrap();
        assert_eq!(step.intent, IntentState::Canceled);
        assert!(step.releases_slot);
        assert_eq!(step.via, Move::HistoricallyFencedAbsentVerified);
        assert_ne!(step.via, Move::TombstoneVerified);
    }
    // And an incomplete lineage is unknown, never live absent: a fenced
    // answer without its evidence is not a fenced answer at all.
    assert!(Fact::from_query_result(&json!({"status": "historically_fenced_absent"})).is_err());
}

// ----------------------------------------------------------- pre-send cancel ----

#[test]
fn a_pre_send_cancel_is_the_only_local_release() {
    let Some(fx) = fixture("k2-formation-cancel", None) else {
        return skip("k2_formation");
    };
    let formation = fx.prepare("form-key-cancel", vec![&fx.participant]);
    let canceled = fx.daemon.expect_ok(&mutation(
        "endeavor_promotion_cancel",
        None,
        "idem-cancel-1",
        json!({"formation_id": formation, "reason": "abandoned before sending"}),
    ));
    assert_eq!(canceled["result"]["state"], json!("canceled"));
    assert_eq!(canceled["result"]["slot"]["state"], json!("released"));
    assert!(endeavors(&fx).is_empty());
    // Terminal: no send is admissible afterwards.
    let refused = fx
        .daemon
        .expect_problem(&fx.start_cmd(&formation, "authobs-cancel-1"), "forbidden");
    assert_eq!(
        refused["problem"]["title"],
        json!("this formation is terminal"),
        "{refused}"
    );

    // And after a send, cancel is not a row of this machine.
    let second = fx.prepare("form-key-cancel-2", vec![&fx.participant]);
    fx.daemon
        .expect_ok(&fx.start_cmd(&second, "authobs-cancel-2"));
    let late = fx.daemon.expect_problem(
        &mutation(
            "endeavor_promotion_cancel",
            None,
            "idem-cancel-2",
            json!({"formation_id": second, "reason": "too late"}),
        ),
        "forbidden",
    );
    assert_eq!(
        late["problem"]["title"],
        json!("cancel exists only before the first send"),
        "{late}"
    );
}

// ------------------------------------------------------------- crash matrix ----

/// Every §12.2 commit point of the saga, both phases. The property is the
/// same at each: after the crash and the EXACT retry there is exactly one
/// Endeavor, and the pair is either resumable or terminal — never a second
/// formation and never a silently released slot.
#[test]
fn every_saga_commit_point_forms_exactly_once() {
    // Short tags on purpose: a Unix socket path caps at 108 bytes, and
    // the fixture puts four of them under the per-case temp directory.
    const POINTS: [(&str, &str); 5] = [
        ("prep", "endeavor_promotion_prepare"),
        ("attempt", "endeavor_promotion_start#attempt"),
        ("result", "endeavor_promotion_start#result"),
        ("linking", "endeavor_promotion_start#linking"),
        ("link", "endeavor_promotion_start#link"),
    ];
    for (code, point) in POINTS {
        for (suffix, phase) in [("b", "before_commit"), ("a", "after_commit")] {
            let tag = format!("k2f-{code}-{suffix}");
            let Some(mut fx) = fixture(&tag, Some(&format!("{phase}:{point}"))) else {
                return skip("k2_formation");
            };
            let key = "form-key-crash";
            let prepare = mutation(
                "endeavor_promotion_prepare",
                None,
                &format!("idem-prepare-{key}"),
                fx.prepare_args(key, vec![&fx.participant]),
            );

            // Drive up to the armed point; the daemon may die mid-request.
            let prepared = fx.daemon.request_raw(&prepare);
            if prepared.is_none() {
                fx.restart_kovee(None);
            }
            let prepared = fx
                .daemon
                .request_raw(&prepare)
                .unwrap_or_else(|| panic!("{tag}: prepare never answered"));
            let prepared: Value = serde_json::from_str(&prepared).unwrap();
            assert_eq!(prepared["outcome"], json!("ok"), "{tag}: {prepared}");
            let formation = prepared["result"]["formation_id"]
                .as_str()
                .unwrap()
                .to_owned();

            let start = fx.start_cmd(&formation, "authobs-crash-1");
            let first = fx.daemon.request_raw(&start);
            if first.is_none() {
                fx.restart_kovee(None);
            }
            // The EXACT retry, on a daemon with no fault armed.
            let retried = fx
                .daemon
                .request_raw(&start)
                .unwrap_or_else(|| panic!("{tag}: the retry never answered"));
            let retried: Value = serde_json::from_str(&retried).unwrap();

            // Exactly-once formation, whatever the boundary.
            let formed = endeavors(&fx);
            assert!(
                formed.len() <= 1,
                "{tag}: {} Endeavors formed: {formed:?}",
                formed.len()
            );
            let view = fx.show(&formation);
            let state = view["state"].as_str().unwrap();
            if formed.len() == 1 {
                // byom committed: Kovee must reach the linked terminal on
                // this retry or on the RECOVERY path, never a
                // released-but-unlinked pair. Which path applies is the
                // machine's own rule: `start` resumes a byom_committed or
                // linking pair, and `reconcile` is what resolves a
                // `submitting` pair whose reply Kovee never recorded.
                let view = if state == "linked" {
                    view
                } else {
                    fx.daemon.request(&start);
                    fx.daemon.request(&fx.reconcile_cmd(&formation, "crash"));
                    fx.daemon.request(&start);
                    fx.show(&formation)
                };
                assert_eq!(view["state"], json!("linked"), "{tag}: {view}");
                assert_eq!(view["slot"]["state"], json!("released"));
                assert_eq!(
                    view["external_link"]["endeavor_ref"], formed[0]["endeavor_id"],
                    "{tag}: the link must name the one formed Endeavor"
                );
            } else {
                // Nothing formed: the pair is held, never released.
                assert_ne!(
                    view["slot"]["state"],
                    json!("released"),
                    "{tag}: the slot released with nothing formed: {view}"
                );
                assert!(
                    retried["outcome"] == json!("ok") || retried["outcome"] == json!("problem"),
                    "{tag}: {retried}"
                );
            }
            // Still exactly one, after every retry.
            assert!(endeavors(&fx).len() <= 1, "{tag}: a second formation");
        }
    }
}

// ------------------------------------------------------------------ helpers ----

impl Fx {
    /// Restarts koveed against the same store, optionally with a fault.
    fn restart_kovee(&mut self, abort: Option<&str>) {
        let run_dir = self.base.join("byom-run").to_string_lossy().into_owned();
        let channels = self.byomd.channels_dir().to_string_lossy().into_owned();
        self.daemon = DaemonProc::start_with_env(
            &self.base.join("kovee-data"),
            &self.base.join("kovee-run"),
            abort,
            &[
                ("KOVEE_BYOM_RUNTIME_DIR", run_dir.as_str()),
                ("KOVEE_BYOM_CHANNELS_DIR", channels.as_str()),
            ],
        );
    }
}

/// byomd's own Endeavor set — the authority on what was formed.
fn endeavors(fx: &Fx) -> Vec<Value> {
    let snapshot = fx.byomd.call_ok(
        "projection",
        &json!({"version": BPP_VERSION, "op": "snapshot_get",
                "society_id": fx.society, "kinds": ["endeavors"]}),
    );
    snapshot["result"]["endeavors"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

/// The five-fact query, asked DIRECTLY of byomd with the exact domain and
/// command digest Kovee recorded — so the fact under test is byomd's, not
/// Kovee's reading of it.
fn raw_query(fx: &Fx, formation: &str) -> Value {
    raw_query_with(fx, formation, |_| {})
}

/// The same query, letting a test bend ONE member away from the exact
/// contract — so the fact under test is still byomd's own answer.
fn raw_query_with(fx: &Fx, formation: &str, bend: impl FnOnce(&mut Value)) -> Value {
    let view = fx.show(formation);
    let token = fx
        .byomd
        .recovery_token(&fx.binding_ref)
        .expect("byomd published a recovery-workload token");
    let document_pin = pin(fx);
    let request = json!({
        "version": BPP_VERSION,
        "op": "external_command_result_query",
        "current_byom_endpoint_ref": "local",
        "current_endpoint_incarnation": fx.byomd.incarnation(),
        "current_recovery_binding_ref": document_pin["binding_ref"],
        "current_recovery_binding_revision": document_pin["binding_revision"],
        "current_recovery_binding_epoch": document_pin["binding_epoch"],
        "current_recovery_binding_digest": document_pin["digest"],
        "kovee_formation_intent_ref": formation,
        "target_byom_endpoint_ref": "local",
        "target_endpoint_incarnation": view["command_endpoint_incarnation"],
        "target_realm_byom_binding_ref": document_pin["binding_ref"],
        "target_realm_byom_binding_revision": document_pin["binding_revision"],
        "target_realm_byom_binding_epoch": document_pin["binding_epoch"],
        "target_realm_byom_binding_digest": document_pin["digest"],
        "target_society_ref": fx.society,
        "target_society_recovery_epoch": view["society_recovery_epoch"],
        "source_principal_ref": "prin-owner",
        "source_actor_binding_digest": actor_binding(fx),
        "operation": "kovee_endeavor_form",
        "byom_command_idempotency_key": view["byom_command_idempotency_key"],
        "canonical_command_digest": view["canonical_byom_command_digest"],
        "idempotency_domain_digest": view["idempotency_domain_digest"],
    });
    let mut request = request;
    bend(&mut request);
    let reply = fx
        .byomd
        .try_call_with("projection", Some(&token), &request)
        .expect("byomd answered the recovery query");
    assert_eq!(reply["outcome"], json!("ok"), "byomd refused: {reply}");
    reply
}

fn pin(fx: &Fx) -> Value {
    let shown = fx
        .daemon
        .expect_ok(&read_cmd("governance_show", None, json!({})));
    let record = &shown["result"]["enablements"].as_array().unwrap()[0]["record"];
    let binding: KoveeRealmByomBinding = serde_json::from_value(record["binding"].clone()).unwrap();
    let wire = hostint::wire_binding(&binding).unwrap();
    json!({
        "binding_ref": wire["binding_ref"],
        "binding_revision": wire["binding_revision"],
        "binding_epoch": wire["binding_epoch"],
        "digest": wire["digest"],
    })
}

fn actor_binding(fx: &Fx) -> Value {
    serde_json::to_value(
        hostint::actor_binding_digest(
            "realm-personal",
            "prin-owner",
            &fx.participant,
            fx.participant_epoch,
        )
        .unwrap(),
    )
    .unwrap()
}

fn promotion_events(fx: &Fx, formation: &str) -> Vec<Value> {
    let page = fx.daemon.expect_ok(&read_cmd(
        "events_read",
        Some(&fx.project),
        json!({"source": fx.project, "limit": 512}),
    ));
    page["result"]["events"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|e| e["resource_ref"] == json!(formation))
        .collect()
}
