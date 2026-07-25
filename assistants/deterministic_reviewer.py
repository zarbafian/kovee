#!/usr/bin/env python3
"""The K1 deterministic acceptance assistant (kovee section 26 K1): no
model dependency. It reads the question contribution through the
immutable ContextAssembly and appends EXACTLY ONE synthesis plus one
`addresses` relation — under replay too, because both steps carry fixed
deterministic operation keys.

Run (the k1_acceptance test does exactly this)::

    python3 assistants/deterministic_reviewer.py \
        --project <proj> --space <space> --branch <branch> \
        --question <contrib> --invocation-key review-1

Environment: KOVEE_RUNTIME_DIR selects the socket directory.
"""

import argparse
import hashlib
import json
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "sdk", "python")
)

from kovee_sdk import Assistant, run_one_shot  # noqa: E402


class DeterministicReviewer(Assistant):
    """Derives its synthesis purely from the question's recorded bytes."""

    def run(self, ctx):
        question = ctx.trigger_contribution
        if question is None:
            raise RuntimeError("the assembly carries no trigger contribution")
        text = ""
        for part in question.get("body_parts", []):
            if "text" in part:
                text = part["text"]
                break
        stamp = hashlib.sha256(text.encode()).hexdigest()[:16]
        synthesis = ctx.contribute(
            kind="synthesis",
            parts=[
                {
                    "media_type": "text/plain",
                    "text": (
                        "Deterministic review of the question "
                        f"({len(text)} scalars, fingerprint {stamp}): "
                        "reviewed exactly once."
                    ),
                }
            ],
            operation_key="synthesis-v1",
        )
        ctx.relate(
            "addresses",
            synthesis.ref,
            question["contribution_id"],
            operation_key="addresses-v1",
        )
        ctx.result_ref = synthesis.ref


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True)
    parser.add_argument("--space", required=True)
    parser.add_argument("--branch", required=True)
    parser.add_argument("--question", required=True)
    parser.add_argument("--invocation-key", required=True)
    # Deterministic across retries: a re-run must present byte-identical
    # covered values, so the deadline is an input, not "now + n".
    parser.add_argument("--deadline", default="2027-01-01T00:00:00Z")
    parser.add_argument("--retry-seconds", type=float, default=30.0)
    args = parser.parse_args()

    outcome = run_one_shot(
        DeterministicReviewer(),
        project_id=args.project,
        space_id=args.space,
        branch_id=args.branch,
        question_ref=args.question,
        invocation_key=args.invocation_key,
        deadline=args.deadline,
        retry_seconds=args.retry_seconds,
    )
    print(json.dumps(outcome))


if __name__ == "__main__":
    main()
