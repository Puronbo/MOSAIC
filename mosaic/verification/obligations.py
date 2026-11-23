"""First-class, request-bound verification obligations.

Obligations describe what must be checked and name the only checker permitted
for that obligation. They are data contracts, not proof certificates.
"""
import hashlib
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from mosaic.core.requests import MathRequest


class VerificationObligation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    obligation_id: str = Field(min_length=1, max_length=120)
    kind: Literal["identity", "transformation", "unsupported"]
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    operation: str
    checker_id: str
    statement: str = Field(min_length=1, max_length=2000)
    assumptions: tuple[str, ...] = ()


def request_fingerprint(request: MathRequest) -> str:
    payload = json.dumps(
        request.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def obligations_for_request(request: MathRequest) -> tuple[VerificationObligation, ...]:
    """Create the minimal explicit obligation set for the supported request.

    This factory intentionally emits one primary obligation. Decomposition
    into multiple proof subgoals will require operation-specific semantics.
    """
    fingerprint = request_fingerprint(request)
    operation = request.operation.value
    if operation == "verify_identity":
        if request.rhs is None:
            kind, checker, statement = (
                "unsupported",
                "none",
                "Identity request is missing its right-hand side.",
            )
        else:
            kind, checker = "identity", "mosaic.symbolic_identity.v1"
            statement = f"Check whether ({request.expression}) = ({request.rhs})."
    elif operation in {"simplify", "expand", "factor", "differentiate"}:
        kind, checker = "transformation", f"mosaic.recompute_{operation}.v1"
        statement = (
            f"Check the {operation} result for ({request.expression}) "
            f"with respect to {request.variable}."
        )
    else:
        kind, checker = "unsupported", "none"
        statement = f"No registered obligation checker supports operation '{operation}'."

    return (VerificationObligation(
        obligation_id=f"request:{fingerprint[:16]}:primary",
        kind=kind,
        request_sha256=fingerprint,
        operation=operation,
        checker_id=checker,
        statement=statement,
    ),)



def verify_obligation_candidate(request: MathRequest, obligation: VerificationObligation, raw: str):
    """Evaluate a candidate only if its obligation matches this exact request.

    The returned TaskBoundCheck retains the conservative status vocabulary of
    the task-bound verifier. No checker name supplied by a model is executed.
    """
    from mosaic.verification.task_bound import TaskBoundCheck, verify_task_bound_candidate

    fingerprint = request_fingerprint(request)
    if obligation.request_sha256 != fingerprint or obligation.operation != request.operation.value:
        candidate_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest() if isinstance(raw, str) else hashlib.sha256(b"").hexdigest()
        return TaskBoundCheck(
            status="INVALID_CERTIFICATE",
            request_sha256=fingerprint,
            candidate_sha256=candidate_hash,
            explanation="Verification obligation is stale or belongs to a different request.",
        )

    expected = obligations_for_request(request)[0]
    if obligation != expected:
        candidate_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest() if isinstance(raw, str) else hashlib.sha256(b"").hexdigest()
        return TaskBoundCheck(
            status="INVALID_CERTIFICATE",
            request_sha256=fingerprint,
            candidate_sha256=candidate_hash,
            explanation="Obligation metadata does not match the registered checker contract.",
        )
    if obligation.kind == "unsupported":
        candidate_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest() if isinstance(raw, str) else hashlib.sha256(b"").hexdigest()
        return TaskBoundCheck(
            status="UNSUPPORTED",
            request_sha256=fingerprint,
            candidate_sha256=candidate_hash,
            explanation="No checker is registered for this obligation.",
        )
    return verify_task_bound_candidate(request, raw)
