"""The minimal K1 Python SDK worker (DESIGN.md section 14.1): a one-shot
direct invocation over the local Unix sockets, with mediated
``ctx.contribute`` / ``ctx.relate`` whose mandatory deterministic
``operation_key`` maps to durable idempotency keys — retries after a lost
reply (or a daemon kill) replay the first result, never a duplicate.

What you write::

    from kovee_sdk import Assistant, run_one_shot

    class Reviewer(Assistant):
        def run(self, ctx):
            question = ctx.trigger_contribution
            synthesis = ctx.contribute(
                kind="synthesis",
                parts=[{"media_type": "text/plain", "text": "..."}],
                operation_key="synthesis-v1",
            )
            ctx.relate("addresses", synthesis.ref,
                       question["contribution_id"],
                       operation_key="addresses-v1")

    run_one_shot(Reviewer(), project_id=..., space_id=..., branch_id=...,
                 question_ref=..., invocation_key="review-1")

Plumbing below: the UDS line protocol, the branch-head fold (the section
10.3 CAS digest any reader can recompute), and the four one-shot steps
(assembly -> invocation -> claim -> run -> complete). Every mutating step
derives its idempotency key from ``invocation_key``/``operation_key``, so
the whole flow is safely re-runnable end to end.

``ctx.model.complete`` (section 16.3) is the K2 addition: the worker names a
logical model PROFILE and gets bounded output back. It cannot name a
provider, a host, a URL, a header, or a credential — the broker resolves the
destination from the profile's provider binding and injects the credential
outside the worker, and no byte leaves without byom's one-shot execution
permit for that exact effect.

Stdlib only; no model or HTTP dependency in the worker (kovee section 26).
"""

import hashlib
import json
import os
import socket
import struct
import time

PROTOCOL_VERSION = "0.1"
REALM = "realm-personal"
_TBD_DOMAIN = b"dev.kovee.typed-bytes-digest.v1"
_BRANCH_HEAD_DOMAIN = b"branch-head"
_BRANCH_HEAD_REF = b"https://kovee.example/kcp/v0/branch-head.v1"


class KoveeProblem(Exception):
    """A section 11.7 problem reply."""

    def __init__(self, problem):
        self.kind = problem.get("type", "")
        self.title = problem.get("title", "")
        self.detail = problem.get("detail")
        super().__init__(f"{self.kind}: {self.title} ({self.detail})")


def _frame(data):
    return struct.pack(">Q", len(data)) + data


def typed_byte_digest(domain, ref, data):
    """The section 11.8 TypedByteDigest (parity with kovee-core)."""
    payload = (
        _frame(_TBD_DOMAIN) + _frame(domain) + _frame(b"0") + _frame(ref) + _frame(data)
    )
    return hashlib.sha256(payload).hexdigest()


def next_head(prev_head, branch_sequence, object_digest):
    """The section 10.3 branch-head fold: the expected-head CAS value
    after appending ``(branch_sequence, object_digest)``."""
    material = f"{prev_head}:{branch_sequence}:{object_digest}".encode()
    return typed_byte_digest(_BRANCH_HEAD_DOMAIN, _BRANCH_HEAD_REF, material)


def socket_dir():
    runtime = os.environ.get("KOVEE_RUNTIME_DIR")
    if runtime:
        return runtime
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if xdg:
        return os.path.join(xdg, "kovee")
    return os.path.join("/tmp", f"kovee-{os.getuid()}")


class Client:
    """One-line-in, one-line-out over a Unix socket, with bounded
    retries so a daemon kill-and-restart mid-flow is survivable: a lost
    reply is retried with the SAME idempotency key and replays the
    stored result."""

    def __init__(self, path, retry_seconds=30.0):
        self.path = path
        self.retry_seconds = retry_seconds

    def request(self, command):
        deadline = time.monotonic() + self.retry_seconds
        last_error = None
        while time.monotonic() < deadline:
            try:
                reply = self._once(command)
            except (ConnectionError, FileNotFoundError, OSError) as exc:
                last_error = exc
                time.sleep(0.2)
                continue
            if reply is None:  # daemon died before replying
                last_error = ConnectionError("no reply line")
                time.sleep(0.2)
                continue
            return reply
        raise TimeoutError(f"kovee daemon unreachable at {self.path}: {last_error}")

    def _once(self, command):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(60.0)
            sock.connect(self.path)
            sock.sendall(json.dumps(command).encode() + b"\n")
            sock.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        raw = b"".join(chunks)
        if not raw.strip():
            return None
        return json.loads(raw.decode())

    def ok(self, command):
        reply = self.request(command)
        if reply.get("outcome") != "ok":
            raise KoveeProblem(reply.get("problem", {}))
        return reply


def _mutation(op, args, idempotency_key, project_id=None):
    command = {
        "version": PROTOCOL_VERSION,
        "op": op,
        "meta": {
            # Deterministic: the request id is derived from the key, so a
            # retry sends byte-identical covered values.
            "request_id": f"req-{idempotency_key}",
            "idempotency_key": idempotency_key,
        },
        "realm_id": REALM,
        "args": args,
    }
    if project_id is not None:
        command["project_id"] = project_id
    return command


class _Ref:
    def __init__(self, ref, record):
        self.ref = ref
        self.record = record


class InvocationContext:
    """The mediated one-shot context (section 14.1): a view over the
    immutable ContextAssembly plus attributed, fenced, idempotent
    ``contribute``/``relate``. Every mutating operation REQUIRES a
    deterministic ``operation_key`` unique within the logical invocation;
    the supervisor scopes it to the invocation id as the durable
    deduplication key."""

    def __init__(self, worker, project_id, claim):
        self._worker = worker
        self.project_id = project_id
        self.invocation = claim["invocation"]
        self.invocation_id = self.invocation["invocation_id"]
        self.attempt_id = claim["attempt_id"]
        self.fence_epoch = claim["fence_epoch"]
        self.assembly = claim.get("assembly")
        self.items = claim.get("items") or []
        frontier = claim.get("frontier") or {}
        self.space_id = self.invocation.get("space_id")
        self.branch_id = (self.assembly or {}).get("branch_id")
        # The expected-head fold starts at the assembly's pinned
        # frontier and advances deterministically with each committed
        # append — so a re-run presents byte-identical CAS values and
        # replays instead of duplicating.
        self._head = frontier.get("branch_head_digest")
        self._pins = {}
        for item in self.items:
            self._pins[item["contribution_id"]] = (
                item["revision"],
                item["content_digest"],
            )
        self.result_ref = None

    @property
    def trigger_contribution(self):
        triggers = (self.assembly or {}).get("trigger_refs") or []
        for item in self.items:
            if item["contribution_id"] in triggers:
                return item
        return self.items[0] if self.items else None

    def _require_key(self, operation_key):
        if not operation_key:
            raise ValueError(
                "operation_key is mandatory and must be derived "
                "deterministically from the logical step (section 14.1)"
            )
        return operation_key

    def contribute(self, kind, parts, operation_key=None, addresses=None, **extra):
        """Appends one attributed typed contribution; with ``addresses``
        it also asserts the reply relation(s), each under a derived
        deterministic key."""
        operation_key = self._require_key(operation_key)
        args = {
            "space_id": self.space_id,
            "branch_id": self.branch_id,
            "expected_head_digest": self._head,
            "kind": kind,
            "body_parts": parts,
            "attempt_id": self.attempt_id,
            "fence_epoch": self.fence_epoch,
        }
        args.update(extra)
        reply = self._worker.ok(
            _mutation(
                "contribution_append",
                args,
                f"{self.invocation_id}.{operation_key}",
                project_id=self.project_id,
            )
        )
        record = reply["result"]
        self._head = next_head(
            self._head, record["origin_branch_sequence"], record["content_digest"]
        )
        self._pins[record["contribution_id"]] = (
            record["revision"],
            record["content_digest"],
        )
        contribution = _Ref(record["contribution_id"], record)
        self.result_ref = contribution.ref
        for index, target in enumerate(addresses or []):
            self.relate(
                "addresses",
                contribution.ref,
                target,
                operation_key=f"{operation_key}.addresses{index}",
            )
        return contribution

    def relate(self, kind, from_ref, to_ref, operation_key=None, rationale_ref=None):
        """Asserts one permitted semantic relation over exact pinned
        endpoint revisions (section 10.2)."""
        operation_key = self._require_key(operation_key)
        args = {
            "space_id": self.space_id,
            "branch_id": self.branch_id,
            "expected_head_digest": self._head,
            "kind": kind,
            "from_ref": self._triple(from_ref),
            "to_ref": self._triple(to_ref),
            "attempt_id": self.attempt_id,
            "fence_epoch": self.fence_epoch,
        }
        if rationale_ref is not None:
            args["rationale_ref"] = rationale_ref
        reply = self._worker.ok(
            _mutation(
                "relation_assert",
                args,
                f"{self.invocation_id}.{operation_key}",
                project_id=self.project_id,
            )
        )
        record = reply["result"]
        self._head = next_head(self._head, record["branch_sequence"], record["digest"])
        self._pins[record["relation_id"]] = (record["revision"], record["digest"])
        return _Ref(record["relation_id"], record)

    def _triple(self, ref):
        if ref not in self._pins:
            raise KeyError(
                f"{ref} is not a pinned object of this invocation context"
            )
        revision, digest = self._pins[ref]
        return {"object_ref": ref, "revision": revision, "digest": digest}

    @property
    def model(self):
        """The mediated model surface (section 16.3): ``ctx.model.complete``.

        There is no way to name a provider, a host, a URL, a header, or a
        credential from here — the broker resolves the destination from the
        model PROFILE's provider binding and injects the credential outside
        the worker. What comes back is bounded output plus the usage that was
        metered.
        """
        return _ModelSurface(self)


class _ModelSurface:
    """``ctx.model`` — one operation, and nothing that widens what leaves."""

    def __init__(self, ctx):
        self._ctx = ctx

    def complete(
        self,
        prompt,
        *,
        authorization,
        model_profile_ref,
        purpose_ref,
        operation_key=None,
        system=None,
        classification_ref="class-public",
        max_output_tokens=1024,
        stable_binding_key=None,
    ):
        """One brokered model call.

        ``authorization`` is byom's notice for the ``model_egress`` act that
        authorizes this disclosure — the intent ref/digest/revision, the
        authorized subject digest, byom's one-shot ``stable_execution_key``,
        and the budget reservation set. It is a set of CLAIMS: byomd
        re-derives every one of them inside ``execution_permit_consume``, and
        the permit-channel token is byomd's own file keyed to that act, so
        naming another act's refs authorizes nothing.

        Returns the section 16.3 result: ``text`` when the call completed,
        ``usage``, the effect/attempt identity, and the two manifest refs an
        auditor can follow. ``state == "ambiguous"`` means a request may have
        been transmitted; ``retry_frozen`` is then true and an operator
        reconciles — never retry it yourself.
        """
        ctx = self._ctx
        operation_key = ctx._require_key(operation_key)
        args = {
            "attempt_id": ctx.attempt_id,
            "fence_epoch": ctx.fence_epoch,
            "model_profile_ref": model_profile_ref,
            "purpose_ref": purpose_ref,
            "classification_ref": classification_ref,
            "prompt": prompt,
            "max_output_tokens": max_output_tokens,
            "act_intent_ref": authorization["act_intent_ref"],
            "act_intent_digest": authorization["act_intent_digest"],
            "act_revision": authorization["act_revision"],
            "subject_digest": authorization["subject_digest"],
            "stable_execution_key": authorization["stable_execution_key"],
            "budget_reservation_set_ref": authorization[
                "budget_reservation_set_ref"
            ],
        }
        if system is not None:
            args["system"] = system
        if stable_binding_key is not None:
            args["stable_binding_key"] = stable_binding_key
        reply = ctx._worker.ok(
            _mutation(
                "model_complete",
                args,
                f"{ctx.invocation_id}.{operation_key}",
                project_id=ctx.project_id,
            )
        )
        return reply["result"]


class Assistant:
    """Subclass and implement ``run(ctx)`` (section 14.1)."""

    def run(self, ctx):
        raise NotImplementedError


def run_one_shot(
    assistant,
    *,
    project_id,
    space_id,
    branch_id,
    question_ref,
    invocation_key,
    deadline,
    deployment_id="dep-local-dev",
    deployment_revision=1,
    runtime_dir=None,
    retry_seconds=30.0,
):
    """The authenticated one-shot direct invocation: create the exact
    explicit-refs ContextAssembly, create the invocation bound to it,
    claim the attempt on the worker socket, run the assistant, complete.
    Deterministic end to end: re-running with the same ``invocation_key``
    (and the same ``deadline``) replays every committed step exactly."""
    base = runtime_dir or socket_dir()
    external = Client(os.path.join(base, "kovee.sock"), retry_seconds)
    worker = Client(os.path.join(base, "kovee-worker.sock"), retry_seconds)

    assembly = external.ok(
        _mutation(
            "context_assembly_create",
            {
                "space_id": space_id,
                "branch_id": branch_id,
                "audience_ref": f"asstdep-{deployment_id}",
                "purpose": "one-shot direct invocation (K1 acceptance)",
                "selection_policy_ref": "explicit_refs_v1",
                "required_refs": [question_ref],
                "trigger_refs": [question_ref],
            },
            f"{invocation_key}.assembly",
            project_id=project_id,
        )
    )["result"]

    invocation = external.ok(
        _mutation(
            "invocation_create",
            {
                "assistant_deployment_id": deployment_id,
                "assistant_deployment_revision": deployment_revision,
                "space_id": space_id,
                "branch_id": branch_id,
                "context_assembly_ref": assembly["assembly_id"],
                "context_assembly_digest": assembly["digest"],
                "deadline": deadline,
            },
            f"{invocation_key}.invoke",
            project_id=project_id,
        )
    )["result"]

    claim = worker.ok(
        _mutation(
            "invocation_claim",
            {"invocation_id": invocation["invocation_id"]},
            f"{invocation_key}.claim",
        )
    )["result"]

    ctx = InvocationContext(worker, project_id, claim)
    assistant.run(ctx)

    complete_args = {
        "invocation_id": ctx.invocation_id,
        "attempt_id": ctx.attempt_id,
        "fence_epoch": ctx.fence_epoch,
    }
    if ctx.result_ref is not None:
        complete_args["result_ref"] = ctx.result_ref
    completed = worker.ok(
        _mutation("invocation_complete", complete_args, f"{invocation_key}.complete")
    )["result"]

    return {
        "invocation": completed,
        "assembly": assembly,
        "result_ref": ctx.result_ref,
    }
