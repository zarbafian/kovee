//! The compile-fail gate (D-R3-1, R3-B02): **proof, from an outside crate,
//! that the authority-bearing types cannot be built, copied, mutated or
//! bypassed.**
//!
//! Why this exists as a test and not only as ```compile_fail``` doctests: a
//! `compile_fail` doctest passes when the snippet fails to compile *for any
//! reason*, and rustdoc does not enforce the `E0xxx` code even when one is
//! written. A typo would make such a test pass while proving nothing. So each
//! case below runs `rustc` against this crate's real rlib and asserts
//!
//! - the compile FAILS,
//! - with the EXPECTED diagnostic — the error code and the words that name
//!   the reason, so a snippet that broke for some other reason cannot pass —
//!   and
//! - that a control snippet — the same code with only the offending line
//!   changed — compiles.
//!
//! # Which rlib (R3's P2)
//!
//! A gate that can read the wrong artifact is not a gate. This one used to
//! take the newest `libkovee_effects-*.rlib` by mtime; R3's confirmation
//! caught that guess reading a stale artifact in a shared target directory
//! and reporting a `Clone` mutant green. Now [`linked_rlib`] asks rustc to
//! prove each candidate's identity — a snippet asserting
//! `kovee_effects::SOURCE_FINGERPRINT` equals the value **this test binary**
//! was linked with — and demands exactly one survivor. A stale or
//! differently-featured artifact fails the assertion; two indistinguishable
//! ones abort the test rather than being guessed between.
//!
//! What you write: a `Case`, and the harness does the rest.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// One snippet that must not compile, and the reason it must not.
struct Case {
    what: &'static str,
    /// Fragments that must ALL appear in rustc's own diagnostic. Rustdoc does
    /// not check the code on a `compile_fail` doctest; this does.
    expect: &'static [&'static str],
    /// The body compiled against `kovee_effects`.
    denied: &'static str,
    /// The same body with the offending line replaced by something lawful, so
    /// the failure is attributable to that line and nothing else.
    control: &'static str,
}

const PRELUDE: &str = "extern crate kovee_effects;\n";

/// How many refusals this build proves. The daemon's door is one more case in
/// a build that does not have it (see `cases`), so the number is a property of
/// the feature set rather than a magic constant.
#[cfg(not(feature = "daemon"))]
const EXPECTED_CASES: usize = 24;
#[cfg(feature = "daemon")]
const EXPECTED_CASES: usize = 23;

fn cases() -> Vec<Case> {
    #[allow(unused_mut)]
    let mut cases = vec![
        // ------------------------------------------------- the permit ----
        Case {
            what: "a permit literal (private fields, no public constructor)",
            expect: &["cannot construct `ExecutionPermit` with struct literal syntax due to private fields"],
            denied: r#"
                use kovee_effects::ExecutionPermit;
                pub fn f() -> ExecutionPermit {
                    ExecutionPermit { max_uses: 1 }
                }
            "#,
            control: r#"
                use kovee_effects::ExecutionPermit;
                pub fn f(minted: ExecutionPermit) -> ExecutionPermit {
                    minted
                }
            "#,
        },
        Case {
            what: "cloning a permit",
            expect: &["error[E0599]", "no method named `clone` found for struct `ExecutionPermit`"],
            denied: r#"
                use kovee_effects::ExecutionPermit;
                pub fn f(permit: ExecutionPermit) -> (ExecutionPermit, ExecutionPermit) {
                    let copy = permit.clone();
                    (permit, copy)
                }
            "#,
            control: r#"
                use kovee_effects::ExecutionPermit;
                pub fn f(permit: ExecutionPermit) -> (ExecutionPermit, u64) {
                    let copy = permit.max_uses();
                    (permit, copy)
                }
            "#,
        },
        Case {
            what: "deserializing a permit",
            expect: &["error[E0277]", "the trait bound `ExecutionPermit: serde::Deserialize<'de>` is not satisfied"],
            denied: r#"
                use kovee_effects::{serde_json, ExecutionPermit};
                pub fn f(text: &str) -> ExecutionPermit {
                    serde_json::from_str::<ExecutionPermit>(text).unwrap()
                }
            "#,
            control: r#"
                use kovee_effects::{serde_json, ExecutionPermit};
                pub fn f(permit: &ExecutionPermit) -> String {
                    serde_json::to_string(permit).unwrap()
                }
            "#,
        },
        Case {
            what: "writing a permit field after authorization",
            expect: &["error[E0616]", "field `execution_key` of struct `ExecutionPermit` is private"],
            denied: r#"
                use kovee_effects::ExecutionPermit;
                pub fn f(mut permit: ExecutionPermit) -> ExecutionPermit {
                    permit.execution_key = String::from("exec-someone-elses");
                    permit
                }
            "#,
            control: r#"
                use kovee_effects::ExecutionPermit;
                pub fn f(permit: ExecutionPermit) -> ExecutionPermit {
                    let _ = permit.execution_key();
                    permit
                }
            "#,
        },
        Case {
            what: "dispatching twice with one permit (it is consumed by value)",
            expect: &["error[E0382]", "use of moved value: `permit`"],
            denied: r#"
                use kovee_effects::*;
                use std::time::Duration;
                pub fn f(plan: &CallPlan, permit: ExecutionPermit, egress: &Egress<'_>,
                         credential: &Credential, authority: &ConsumptionAuthority<'_>) {
                    let _first = dispatch(plan, permit, egress, credential, authority,
                                          Duration::from_secs(1));
                    let _second = dispatch(plan, permit, egress, credential, authority,
                                           Duration::from_secs(1));
                }
            "#,
            control: r#"
                use kovee_effects::*;
                use std::time::Duration;
                pub fn f(plan: &CallPlan, permit: ExecutionPermit, egress: &Egress<'_>,
                         credential: &Credential, authority: &ConsumptionAuthority<'_>) {
                    let _first = dispatch(plan, permit, egress, credential, authority,
                                          Duration::from_secs(1));
                }
            "#,
        },
        // ------------------------------------------------ the receipt ----
        Case {
            what: "a receipt literal (only the authority's `admit` makes one)",
            expect: &["error[E0560]", "struct `ExecutionConsumptionReceipt` has no field named `max_uses`"],
            denied: r#"
                use kovee_effects::ExecutionConsumptionReceipt;
                pub fn f() -> ExecutionConsumptionReceipt {
                    ExecutionConsumptionReceipt { max_uses: 1 }
                }
            "#,
            control: r#"
                use kovee_effects::{serde_json, ConsumptionAuthority,
                                    ExecutionConsumptionReceipt, PermitError};
                pub fn f(authority: &ConsumptionAuthority<'_>, reply: &serde_json::Value)
                    -> Result<ExecutionConsumptionReceipt, PermitError> {
                    authority.admit(reply)
                }
            "#,
        },
        // R3's confirmation, first move: author the receipt JSON yourself and
        // hand it to the parser. There is no longer a public parser.
        Case {
            what: "authoring a receipt out of JSON of one's own (R3's probe, step 1)",
            expect: &["error[E0624]", "associated function `from_result` is private"],
            denied: r#"
                use kovee_effects::{serde_json, ExecutionConsumptionReceipt};
                pub fn f(mine: &serde_json::Value) {
                    let _ = ExecutionConsumptionReceipt::from_result(mine);
                }
            "#,
            control: r#"
                use kovee_effects::{serde_json, ConsumptionAuthority};
                pub fn f(authority: &ConsumptionAuthority<'_>, reply: &serde_json::Value) {
                    let _ = authority.admit(reply);
                }
            "#,
        },
        Case {
            what: "deserializing a receipt from JSON of one's own",
            expect: &["error[E0277]", "the trait bound `ExecutionConsumptionReceipt: serde::Deserialize<'de>` is not satisfied"],
            denied: r#"
                use kovee_effects::{serde_json, ExecutionConsumptionReceipt};
                pub fn f(text: &str) -> ExecutionConsumptionReceipt {
                    serde_json::from_str::<ExecutionConsumptionReceipt>(text).unwrap()
                }
            "#,
            control: r#"
                use kovee_effects::{serde_json, ExecutionConsumptionReceipt};
                pub fn f(receipt: &ExecutionConsumptionReceipt) -> String {
                    serde_json::to_string(receipt).unwrap()
                }
            "#,
        },
        // R3's confirmation, second move: attest it under a key you chose.
        // The attestation no longer takes a key at all.
        Case {
            what: "attesting a receipt under a secret of one's own (R3's probe, step 2)",
            expect: &[
                "error[E0599]",
                "no function or associated item named `attest` found for struct `ConsumedReceipt",
            ],
            denied: r#"
                use kovee_effects::{ConsumedReceipt, ExecutionConsumptionReceipt, RecordDigestKey};
                pub fn f(receipt: &ExecutionConsumptionReceipt) {
                    let mine = [0xffu8; 32];
                    let _ = ConsumedReceipt::attest(receipt, "eac-forged",
                        RecordDigestKey::Object { key_ref: "mine", secret: &mine });
                }
            "#,
            control: r#"
                use kovee_effects::{ConsumptionAuthority, ExecutionConsumptionReceipt};
                pub fn f(authority: &ConsumptionAuthority<'_>,
                         receipt: &ExecutionConsumptionReceipt) {
                    let _ = authority.attest(receipt, "eac-1");
                }
            "#,
        },
        // R3's confirmation, third move: mint the permit. There is no
        // free-standing gate to call any more; only an authority has one.
        Case {
            what: "minting a permit without an authority (R3's probe, step 3)",
            expect: &["error[E0432]", "unresolved import `kovee_effects::authorize`"],
            denied: r#"
                use kovee_effects::authorize;
                use kovee_effects::{ConsumedReceipt, ExecutionPermit, Expectation, PermitError};
                pub fn f(consumed: ConsumedReceipt<'_>, expect: &Expectation<'_>)
                    -> Result<ExecutionPermit, PermitError> {
                    authorize(Some(consumed), expect)
                }
            "#,
            control: r#"
                use kovee_effects::{ConsumedReceipt, ConsumptionAuthority, ExecutionPermit,
                                    Expectation, PermitError};
                pub fn f(authority: &ConsumptionAuthority<'_>, consumed: ConsumedReceipt<'_>,
                         expect: &Expectation<'_>) -> Result<ExecutionPermit, PermitError> {
                    authority.authorize(Some(consumed), expect)
                }
            "#,
        },
        // R3's confirmation, fourth move: dispatch it against a ledger that
        // forgets. `dispatch` has no ledger parameter.
        Case {
            what: "supplying a spent ledger of one's own at the dispatch call site (R3's probe, step 4)",
            expect: &["error[E0308]", "mismatched types"],
            denied: r#"
                use kovee_effects::*;
                use std::time::Duration;
                pub fn f(plan: &CallPlan, permit: ExecutionPermit, egress: &Egress<'_>,
                         credential: &Credential, forgetful: &dyn SpentLedger) {
                    let _ = dispatch(plan, permit, egress, credential, forgetful,
                                     Duration::from_secs(1));
                }
            "#,
            control: r#"
                use kovee_effects::*;
                use std::time::Duration;
                pub fn f(plan: &CallPlan, permit: ExecutionPermit, egress: &Egress<'_>,
                         credential: &Credential, authority: &ConsumptionAuthority<'_>) {
                    let _ = dispatch(plan, permit, egress, credential, authority,
                                     Duration::from_secs(1));
                }
            "#,
        },
        // R3's confirmation, third round: it stopped forging the pieces and
        // built the AUTHORITY, with a secret of its own and a ledger that
        // forgets, then handed that same authority to `dispatch`. Two permits
        // completed, two claims, two sends. The constructor is gone.
        Case {
            what: "constructing the consumption authority (R3's third probe, the whole of it)",
            expect: &[
                "error[E0599]",
                "no function or associated item named `new` found for struct `ConsumptionAuthority<'a>`",
            ],
            denied: r#"
                use kovee_effects::{ConsumptionAuthority, SpentLedger};
                pub fn f(mine: &dyn SpentLedger) -> ConsumptionAuthority<'_> {
                    ConsumptionAuthority::new("kovee-consumption-object:mine", [0xffu8; 32], mine)
                }
            "#,
            control: r#"
                use kovee_effects::ConsumptionAuthority;
                pub fn f(authority: &ConsumptionAuthority<'_>) -> String {
                    authority.key_ref().to_owned()
                }
            "#,
        },
        // The whole of R3's third-confirmation probe as one program, exactly
        // as it was written: caller-authored receipt JSON, a caller-selected
        // secret, a ledger that forgets, and that same authority handed to
        // `dispatch`. On the build it was run against this printed "2 permits
        // completed, 2 claims, 2 sends". It now fails at both of the two lines
        // that made it possible.
        Case {
            what: "R3's third-confirmation probe, verbatim (authority + forgetful ledger + dispatch)",
            expect: &[
                "error[E0277]",
                "the trait bound `Forgetful: kovee_effects::sealed::LedgerSeal` is not satisfied",
                "error[E0599]",
                "no function or associated item named `new` found for struct `kovee_effects::ConsumptionAuthority<'a>`",
            ],
            denied: r#"
                use kovee_effects::*;
                use std::time::Duration;
                pub struct Forgetful;
                impl SpentLedger for Forgetful {
                    fn claim_single_use(&self, _p: &ExecutionPermit) -> Result<Claim, String> {
                        Ok(Claim::Claimed)
                    }
                }
                pub fn probe(plan: &CallPlan, egress: &Egress<'_>, credential: &Credential,
                             reply: &kovee_effects::serde_json::Value,
                             expect: &Expectation<'_>) -> Outcome {
                    let forgetful = Forgetful;
                    let mine = ConsumptionAuthority::new(
                        "kovee-consumption-object:mine", [0xffu8; 32], &forgetful);
                    let receipt = mine.admit(reply).unwrap();
                    let consumed = mine.attest(&receipt, "eac-forged").unwrap();
                    let permit = mine.authorize(Some(consumed), expect).unwrap();
                    dispatch(plan, permit, egress, credential, &mine, Duration::from_secs(1))
                }
            "#,
            control: r#"
                use kovee_effects::*;
                use std::time::Duration;
                pub fn probe(plan: &CallPlan, egress: &Egress<'_>, credential: &Credential,
                             reply: &kovee_effects::serde_json::Value,
                             expect: &Expectation<'_>,
                             daemon: &ConsumptionAuthority<'_>) -> Outcome {
                    let receipt = daemon.admit(reply).unwrap();
                    let consumed = daemon.attest(&receipt, "eac-1").unwrap();
                    let permit = daemon.authorize(Some(consumed), expect).unwrap();
                    dispatch(plan, permit, egress, credential, daemon, Duration::from_secs(1))
                }
            "#,
        },
        // …and the other half of that probe: being the ledger. `SpentLedger`
        // is sealed, so "a ledger that forgets" is not a type an outside crate
        // can define at all.
        Case {
            what: "implementing the spent ledger from outside (the forgetful ledger itself)",
            expect: &[
                "error[E0277]",
                "the trait bound `Forgetful: kovee_effects::sealed::LedgerSeal` is not satisfied",
                "`SpentLedger` is a \"sealed trait\"",
            ],
            denied: r#"
                use kovee_effects::{Claim, ExecutionPermit, SpentLedger};
                pub struct Forgetful;
                impl SpentLedger for Forgetful {
                    fn claim_single_use(&self, _p: &ExecutionPermit) -> Result<Claim, String> {
                        Ok(Claim::Claimed)
                    }
                }
            "#,
            control: r#"
                use kovee_effects::{Claim, ExecutionPermit, SpentLedger};
                pub fn f(ledger: &dyn SpentLedger, permit: &ExecutionPermit)
                    -> Result<Claim, String> {
                    ledger.claim_single_use(permit)
                }
            "#,
        },
        // ---------------------------------------------------- the plan ----
        Case {
            what: "changing a plan's origin after it is sealed",
            expect: &["error[E0616]", "field `origin` of struct `CallPlan` is private"],
            denied: r#"
                use kovee_effects::{CallPlan, Origin};
                pub fn f(mut plan: CallPlan) -> CallPlan {
                    plan.origin = Origin::https("exfil.example", 443);
                    plan
                }
            "#,
            control: r#"
                use kovee_effects::{CallPlan, Origin};
                pub fn f(plan: CallPlan) -> (CallPlan, Origin) {
                    let origin = plan.origin().clone();
                    (plan, origin)
                }
            "#,
        },
        // ---------------------------------------------- the credential ----
        Case {
            what: "reading a credential outside this crate",
            expect: &["error[E0624]", "method `expose` is private"],
            denied: r#"
                use kovee_effects::Credential;
                pub fn f(credential: &Credential) -> String {
                    credential.expose().to_owned()
                }
            "#,
            control: r#"
                use kovee_effects::Credential;
                pub fn f(credential: &Credential) -> String {
                    format!("{credential:?}")
                }
            "#,
        },
        Case {
            what: "making a credential outside this crate",
            expect: &["error[E0624]", "associated function `new` is private"],
            denied: r#"
                use kovee_effects::Credential;
                pub fn f() -> Credential {
                    Credential::new("sk-mine")
                }
            "#,
            control: r#"
                use kovee_effects::{Credential, CredentialError, CredentialRef, resolve};
                pub fn f(reference: &CredentialRef) -> Result<Credential, CredentialError> {
                    resolve(reference, |_| None)
                }
            "#,
        },
        Case {
            what: "copying a resolved credential",
            expect: &["error[E0599]", "no method named `clone` found for struct `Credential`"],
            denied: r#"
                use kovee_effects::Credential;
                pub fn f(credential: Credential) -> (Credential, Credential) {
                    let copy = credential.clone();
                    (credential, copy)
                }
            "#,
            control: r#"
                use kovee_effects::Credential;
                pub fn f(credential: Credential) -> (Credential, bool) {
                    let empty = credential.is_empty();
                    (credential, empty)
                }
            "#,
        },
        // -------------------------------------------------- the egress ----
        // R3-B02's probe: build the live wire and call `send` on it, with a
        // request of one's own and no permit at all.
        Case {
            what: "constructing the live transport (R3-B02's probe, step 1)",
            expect: &["error[E0432]", "unresolved import `kovee_effects::HttpsTransport`"],
            denied: r#"
                use kovee_effects::HttpsTransport;
                pub fn f() -> HttpsTransport {
                    HttpsTransport::new()
                }
            "#,
            control: r#"
                use kovee_effects::Egress;
                pub fn f() -> Egress<'static> {
                    Egress::live()
                }
            "#,
        },
        Case {
            what: "naming the transport trait, to send or to implement (R3-B02's probe, step 2)",
            expect: &["error[E0432]", "unresolved import `kovee_effects::Transport`"],
            denied: r#"
                use kovee_effects::Transport;
                pub fn f(wire: &dyn Transport) -> &'static str {
                    wire.profile()
                }
            "#,
            control: r#"
                use kovee_effects::Egress;
                pub fn f(egress: &Egress<'_>) -> &'static str {
                    egress.profile()
                }
            "#,
        },
        // R3's confirmation, B02: it did not need a root re-export. `transport`
        // was a PUBLIC module, so `pub` on the raw items inside it republished
        // the whole bypass through `kovee_effects::transport::*` — and the gate,
        // which looked only at root re-exports, stayed green while an old
        // no-permit `send` consumer compiled again.
        //
        // Every module is private now, so the nested path is not a second door
        // to check: it is closed by construction. This case is the machine
        // check on that — one fragment per module, so re-publishing ANY of them
        // turns the gate red even if the items inside stay private.
        Case {
            what: "reaching the internals by their nested module paths (R3-B02's second path)",
            expect: &[
                "error[E0603]",
                "module `transport` is private",
                "module `permit` is private",
                "module `broker` is private",
                "module `credential` is private",
                "module `driver` is private",
                "module `egress` is private",
                "module `binding` is private",
                "module `attempt` is private",
                "module `disclosure` is private",
                "module `keying` is private",
                "module `manifest` is private",
            ],
            denied: r#"
                use kovee_effects::transport::Egress;
                use kovee_effects::permit::ExecutionPermit;
                use kovee_effects::broker::dispatch;
                use kovee_effects::credential::Credential;
                use kovee_effects::driver::PreparedRequest;
                use kovee_effects::egress::Origin;
                use kovee_effects::binding::ModelProfile;
                use kovee_effects::attempt::EffectState;
                use kovee_effects::disclosure::DisclosureManifest;
                use kovee_effects::keying::RecordDigestKey;
                use kovee_effects::manifest::Segment;
                pub fn f(_: &Egress<'_>, _: &ExecutionPermit, _: &Credential,
                         _: &PreparedRequest, _: &Origin, _: &ModelProfile,
                         _: EffectState, _: &DisclosureManifest, _: RecordDigestKey<'_>,
                         _: &Segment) {
                    let _ = dispatch;
                }
            "#,
            control: r#"
                use kovee_effects::{dispatch, Credential, DisclosureManifest, EffectState,
                                    Egress, ExecutionPermit, ModelProfile, Origin,
                                    PreparedRequest, RecordDigestKey, Segment};
                pub fn f(_: &Egress<'_>, _: &ExecutionPermit, _: &Credential,
                         _: &PreparedRequest, _: &Origin, _: &ModelProfile,
                         _: EffectState, _: &DisclosureManifest, _: RecordDigestKey<'_>,
                         _: &Segment) {
                    let _ = dispatch;
                }
            "#,
        },
        // The same probe by its most direct route: the raw wire itself, named
        // through the module rather than through the root.
        Case {
            what: "naming the raw transport through the module path (R3-B02's probe, step 3)",
            expect: &["error[E0603]", "module `transport` is private"],
            denied: r#"
                use kovee_effects::transport::{HttpsTransport, RawResponse, Transport,
                                               TransportError};
                pub fn f(wire: &HttpsTransport) -> &dyn Transport { wire }
                pub fn g(_: RawResponse, _: TransportError) {}
            "#,
            control: r#"
                use kovee_effects::Egress;
                pub fn f() -> Egress<'static> {
                    Egress::live()
                }
            "#,
        },
        Case {
            what: "handing the broker a wire of one's own",
            expect: &["error[E0308]", "mismatched types"],
            denied: r#"
                use kovee_effects::*;
                use std::time::Duration;
                pub struct Mine;
                pub fn f(plan: &CallPlan, permit: ExecutionPermit, credential: &Credential,
                         authority: &ConsumptionAuthority<'_>) {
                    let mine = Mine;
                    let _ = dispatch(plan, permit, &mine, credential, authority,
                                     Duration::from_secs(1));
                }
            "#,
            control: r#"
                use kovee_effects::*;
                use std::time::Duration;
                pub fn f(plan: &CallPlan, permit: ExecutionPermit, credential: &Credential,
                         authority: &ConsumptionAuthority<'_>) {
                    let _ = dispatch(plan, permit, &Egress::live(), credential, authority,
                                     Duration::from_secs(1));
                }
            "#,
        },
    ];
    // ------------------------------------------------- the daemon's door ----
    // The last way to an authority is `take_daemon_authority`, and it is
    // compiled only into a build that asks for the `daemon` feature — koveed's,
    // and nothing else in this workspace. This case therefore asserts what THIS
    // build is: without the feature the name does not exist, which is the whole
    // of the external seal; with it, the name exists and the once-per-process
    // grant is what limits it (`the_daemons_grant_is_taken_exactly_once_per_process`).
    //
    // The test binary and the rlib it reads are compiled from the same feature
    // resolution, so this is never a guess about which artifact is on disk.
    #[cfg(not(feature = "daemon"))]
    cases.push(Case {
        what: "taking the daemon's grant from a build that is not the daemon",
        expect: &[
            "error[E0432]",
            "unresolved import `kovee_effects::take_daemon_authority`",
            "unresolved imports `kovee_effects::DaemonGrant`, `kovee_effects::DurableClaim`",
            "the item is gated behind the `daemon` feature",
        ],
        denied: r#"
                use kovee_effects::take_daemon_authority;
                use kovee_effects::{DaemonGrant, DurableClaim};
                pub fn f() -> Option<DaemonGrant> {
                    let _ = DurableClaim::new;
                    take_daemon_authority("kovee-consumption-object:mine", [0xffu8; 32])
                }
            "#,
        control: r#"
                use kovee_effects::ConsumptionAuthority;
                pub fn f(authority: &ConsumptionAuthority<'_>) -> String {
                    authority.key_ref().to_owned()
                }
            "#,
    });
    cases
}

#[test]
fn the_authority_bearing_types_cannot_be_forged_copied_or_mutated() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("kovee-effects-compile-gate");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let rlib = linked_rlib(&dir, &deps_dir());
    let mut proven = 0;
    for case in cases() {
        // The control must compile: that is what makes the refusal
        // attributable to the one line that differs.
        let control = compile(
            &dir,
            &rlib,
            "control",
            &format!("{PRELUDE}{}", case.control),
        );
        assert!(
            control.status,
            "the control for {:?} must compile, but rustc said:\n{}",
            case.what, control.stderr
        );
        let denied = compile(&dir, &rlib, "denied", &format!("{PRELUDE}{}", case.denied));
        assert!(
            !denied.status,
            "{:?} still compiles — the gate is not a gate",
            case.what
        );
        for fragment in case.expect {
            assert!(
                denied.stderr.contains(fragment),
                "{:?} must be refused with {fragment:?}, but rustc said:\n{}",
                case.what,
                denied.stderr
            );
        }
        proven += 1;
    }
    assert_eq!(proven, EXPECTED_CASES, "every case ran");
    let _ = std::fs::remove_dir_all(&dir);
}

struct Compiled {
    status: bool,
    stderr: String,
}

/// Compiles one snippet as a library against the rlib this test was linked
/// with. `serde_json` needs no `--extern`: the crate re-exports the exact one
/// it was built against, so a snippet cannot pick up a different copy either.
fn compile(dir: &Path, rlib: &Path, name: &str, body: &str) -> Compiled {
    let source = dir.join(format!("{name}.rs"));
    std::fs::write(&source, body).unwrap();
    let deps = rlib.parent().expect("deps/");
    let output = Command::new(std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned()))
        .args(["--edition", "2021", "--crate-type", "lib", "--crate-name"])
        .arg(name)
        .arg("--extern")
        .arg(format!("kovee_effects={}", rlib.display()))
        .arg("-L")
        .arg(format!("dependency={}", deps.display()))
        .args(["--out-dir", &dir.to_string_lossy()])
        .arg(&source)
        .output()
        .expect("run rustc");
    Compiled {
        status: output.status.success(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// This test binary lives in the same `deps/` directory as the rlibs it was
/// linked against.
fn deps_dir() -> PathBuf {
    let exe = std::env::current_exe().expect("the test binary's own path");
    exe.parent().expect("deps/").to_path_buf()
}

/// The `libkovee_effects-<hash>.rlib` that Cargo linked into **this** test
/// binary, identified rather than guessed.
///
/// Several may sit in one `deps/` — one per feature set, one per concurrent
/// build, one left over from a source state that no longer exists. The old
/// "newest by mtime" pick is what let R3's `Clone` mutant read a stale
/// artifact and come back green. So each candidate is asked, by rustc, to
/// agree with the [`kovee_effects::SOURCE_FINGERPRINT`] this binary carries;
/// anything else is not this build, and two survivors are an ambiguity the
/// gate refuses to resolve by guessing.
fn linked_rlib(dir: &Path, deps: &Path) -> PathBuf {
    let prefix = "libkovee_effects-";
    let candidates: Vec<PathBuf> = std::fs::read_dir(deps)
        .expect("read deps/")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .map(|f| f.to_string_lossy())
                .is_some_and(|f| f.starts_with(prefix) && f.ends_with(".rlib"))
        })
        .collect();
    assert!(
        !candidates.is_empty(),
        "no {prefix}*.rlib in {}",
        deps.display()
    );
    let witness = format!(
        "{PRELUDE}const _: () = assert!(kovee_effects::SOURCE_FINGERPRINT == {}u64);\n",
        kovee_effects::SOURCE_FINGERPRINT
    );
    let matched: Vec<PathBuf> = candidates
        .iter()
        .filter(|candidate| compile(dir, candidate, "fingerprint", &witness).status)
        .cloned()
        .collect();
    assert_eq!(
        matched.len(),
        1,
        "exactly one of {} candidate rlib(s) in {} must carry this build's \
         SOURCE_FINGERPRINT ({}); {} did. Candidates: {:?}",
        candidates.len(),
        deps.display(),
        kovee_effects::SOURCE_FINGERPRINT,
        matched.len(),
        candidates
    );
    matched.into_iter().next().expect("one match")
}

/// The gate's own oracle: the fingerprint has to actually *change* with the
/// source, or `linked_rlib` would accept any artifact of this crate.
#[test]
fn the_fingerprint_distinguishes_one_build_from_another() {
    // A hand-rolled re-derivation over the same inputs, so a fingerprint that
    // silently degenerated to a constant is caught.
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut names: Vec<String> = std::fs::read_dir(&source)
        .expect("read src/")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".rs"))
        .collect();
    names.sort();
    assert!(names.len() >= 12, "every module counts: {names:?}");
    // Two different byte strings must not collide under the same folding.
    let one = fnv1a(0xcbf2_9ce4_8422_2325, b"permit.rs one");
    let two = fnv1a(0xcbf2_9ce4_8422_2325, b"permit.rs two");
    assert_ne!(one, two);
    assert_ne!(kovee_effects::SOURCE_FINGERPRINT, 0);
    assert_ne!(kovee_effects::SOURCE_FINGERPRINT, one);
}

fn fnv1a(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}
