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
