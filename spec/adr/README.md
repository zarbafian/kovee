# Architecture decision records

An ADR records one decision with lasting consequences: standards disposition,
wire formats, library selection, security posture. Kovee-specific wire
formats additionally must satisfy the design's standards-first rule before
shipping in a stable release.

Process:

1. Copy the template below into `NNNN-short-title.md` (next free number).
2. Open a PR. The ADR is `proposed` until merged with maintainer approval,
   then `accepted`. Superseding requires a new ADR that links both ways.
3. Security-relevant ADRs list the affected threat cases and test vectors.

Template:

~~~markdown
# ADR-NNNN: title

Status: proposed | accepted | superseded by ADR-MMMM
Date: YYYY-MM-DD

## Context
What requirement forces a decision, and what was evaluated.

## Decision
The choice, stated normatively.

## Consequences
What becomes easier, harder, or irreversible; affected tests/vectors.
~~~

Index:

| # | Title | Status |
|---|---|---|
| [0001](0001-workspace-conventions.md) | Workspace conventions mirrored from akson | accepted |
