//! The compile-fail gate (D-R3-1): **proof, from an outside crate, that the
//! authority-bearing types cannot be built, copied or mutated.**
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

fn cases() -> Vec<Case> {
    vec![
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
                use kovee_effects::ExecutionPermit;
                pub fn f(text: &str) -> ExecutionPermit {
                    serde_json::from_str::<ExecutionPermit>(text).unwrap()
                }
            "#,
            control: r#"
                use kovee_effects::ExecutionPermit;
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
                         credential: &Credential, ledger: &dyn SpentLedger) {
                    let _first = dispatch(plan, permit, egress, credential, ledger,
                                          Duration::from_secs(1));
                    let _second = dispatch(plan, permit, egress, credential, ledger,
                                           Duration::from_secs(1));
                }
            "#,
            control: r#"
                use kovee_effects::*;
                use std::time::Duration;
                pub fn f(plan: &CallPlan, permit: ExecutionPermit, egress: &Egress<'_>,
                         credential: &Credential, ledger: &dyn SpentLedger) {
                    let _first = dispatch(plan, permit, egress, credential, ledger,
                                          Duration::from_secs(1));
                }
            "#,
        },
        Case {
            what: "a receipt literal (only the reply parser makes one)",
            expect: &["error[E0560]", "struct `ExecutionConsumptionReceipt` has no field named `max_uses`"],
            denied: r#"
                use kovee_effects::ExecutionConsumptionReceipt;
                pub fn f() -> ExecutionConsumptionReceipt {
                    ExecutionConsumptionReceipt { max_uses: 1 }
                }
            "#,
            control: r#"
                use kovee_effects::{ExecutionConsumptionReceipt, PermitError};
                pub fn f(reply: &serde_json::Value)
                    -> Result<ExecutionConsumptionReceipt, PermitError> {
                    ExecutionConsumptionReceipt::from_result(reply)
                }
            "#,
        },
        Case {
            what: "wrapping something as a receipt",
            expect: &[
                "error[E0423]",
                "cannot initialize a tuple struct which contains private fields",
            ],
            denied: r#"
                use kovee_effects::ExecutionConsumptionReceipt;
                pub fn f(value: serde_json::Value) -> ExecutionConsumptionReceipt {
                    ExecutionConsumptionReceipt(value)
                }
            "#,
            control: r#"
                use kovee_effects::{ExecutionConsumptionReceipt, PermitError};
                pub fn f(value: serde_json::Value)
                    -> Result<ExecutionConsumptionReceipt, PermitError> {
                    ExecutionConsumptionReceipt::from_result(&value)
                }
            "#,
        },
        Case {
            what: "deserializing a receipt from JSON of one's own",
            expect: &["error[E0277]", "the trait bound `ExecutionConsumptionReceipt: serde::Deserialize<'de>` is not satisfied"],
            denied: r#"
                use kovee_effects::ExecutionConsumptionReceipt;
                pub fn f(text: &str) -> ExecutionConsumptionReceipt {
                    serde_json::from_str::<ExecutionConsumptionReceipt>(text).unwrap()
                }
            "#,
            control: r#"
                use kovee_effects::ExecutionConsumptionReceipt;
                pub fn f(receipt: &ExecutionConsumptionReceipt) -> String {
                    serde_json::to_string(receipt).unwrap()
                }
            "#,
        },
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
            what: "handing the broker a transport of one's own",
            expect: &["error[E0308]", "mismatched types"],
            denied: r#"
                use kovee_effects::*;
                use std::time::Duration;
                pub struct Mine;
                impl Transport for Mine {
                    fn profile(&self) -> &'static str { "mine" }
                    fn send(&self, _o: &Origin, _r: &PreparedRequest, _c: &Credential,
                            _t: Duration) -> Result<RawResponse, TransportError> {
                        Err(TransportError::NotSent(String::new()))
                    }
                }
                pub fn f(plan: &CallPlan, permit: ExecutionPermit, credential: &Credential,
                         ledger: &dyn SpentLedger) {
                    let mine = Mine;
                    let _ = dispatch(plan, permit, &mine, credential, ledger,
                                     Duration::from_secs(1));
                }
            "#,
            control: r#"
                use kovee_effects::*;
                use std::time::Duration;
                pub fn f(plan: &CallPlan, permit: ExecutionPermit, credential: &Credential,
                         ledger: &dyn SpentLedger) {
                    let wire = HttpsTransport::new();
                    let _ = dispatch(plan, permit, &Egress::live(&wire), credential, ledger,
                                     Duration::from_secs(1));
                }
            "#,
        },
    ]
}

#[test]
fn the_authority_bearing_types_cannot_be_forged_copied_or_mutated() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("kovee-effects-compile-gate");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let deps = deps_dir();
    let mut proven = 0;
    for case in cases() {
        // The control must compile: that is what makes the refusal
        // attributable to the one line that differs.
        let control = compile(
            &dir,
            &deps,
            "control",
            &format!("{PRELUDE}{}", case.control),
        );
        assert!(
            control.status,
            "the control for {:?} must compile, but rustc said:\n{}",
            case.what, control.stderr
        );
        let denied = compile(&dir, &deps, "denied", &format!("{PRELUDE}{}", case.denied));
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
    assert_eq!(proven, 12, "every case ran");
    let _ = std::fs::remove_dir_all(&dir);
}

struct Compiled {
    status: bool,
    stderr: String,
}

/// Compiles one snippet as a library against this crate's own rlib.
fn compile(dir: &Path, deps: &Path, name: &str, body: &str) -> Compiled {
    let source = dir.join(format!("{name}.rs"));
    std::fs::write(&source, body).unwrap();
    let output = Command::new(std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned()))
        .args(["--edition", "2021", "--crate-type", "lib", "--crate-name"])
        .arg(name)
        .arg("--extern")
        .arg(format!(
            "kovee_effects={}",
            rlib(deps, "kovee_effects").display()
        ))
        .arg("--extern")
        .arg(format!("serde_json={}", rlib(deps, "serde_json").display()))
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

/// The newest `lib<name>-<hash>.rlib` in `deps`. Several may exist (one per
/// feature set); every one of them has the same public gate.
fn rlib(deps: &Path, name: &str) -> PathBuf {
    let prefix = format!("lib{name}-");
    let mut found: Vec<(std::time::SystemTime, PathBuf)> = std::fs::read_dir(deps)
        .expect("read deps/")
        .filter_map(Result::ok)
        .filter(|entry| {
            let file = entry.file_name().to_string_lossy().into_owned();
            file.starts_with(&prefix) && file.ends_with(".rlib")
        })
        .filter_map(|entry| {
            let modified = entry.metadata().ok()?.modified().ok()?;
            Some((modified, entry.path()))
        })
        .collect();
    found.sort_by_key(|(modified, _)| *modified);
    found
        .pop()
        .unwrap_or_else(|| panic!("no {prefix}*.rlib in {}", deps.display()))
        .1
}
