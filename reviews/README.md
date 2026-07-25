# Review records

External review triage records, one dated markdown file per review:
`YYYY-MM-DD-<reviewer>-<scope>.md` (e.g. `2026-07-25-codex-k0.md`). The
convention mirrors akson's `spec/reviews/`; kovee keeps them at the repo
root per the K0 milestone sheet.

Each record states:

- **What was reviewed, pinned.** The reviewer and version (e.g. Codex,
  `codex-cli x.y.z`) and the exact commit range or SHA covered
  (`<from>..<to>`), so the review binds to immutable content. Reviews of
  design/amendment text additionally pin the document sha256 they read.
- **Every finding, with a disposition.** Findings are tabulated by severity
  (high / medium / low); each carries exactly one disposition:
  - **fixed** — addressed in the triage commit, naming the file/test/vector
    that proves it;
  - **tracked → Kx** — a genuine gap whose implementation belongs to a later
    milestone; a plan/sheet note now exists at that milestone;
  - **rejected** — with rationale.
- **The guiding rule applied.** Fix defects in already-shipped code and
  tighten schemas where cheap; do not pull later milestones' engine work
  forward.

A finding without a disposition blocks the milestone's review-evidence line
(the K0 sheet's R0 covers the spec extraction, L1/L4). Dispositions are
append-only: a later reversal is a new dated record, not an edit.
