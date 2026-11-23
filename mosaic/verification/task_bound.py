"""Bind untrusted candidate claims to the exact mathematical request."""
import hashlib
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from mosaic.core.requests import MathRequest
from mosaic.engines.algebra import ExpressionError, run_algebra
from mosaic.verification.exact_checker import verify_identity
from mosaic.verification.side_conditions import check_domain_preservation


class BoundIdentityClaim(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    operation: Literal["verify_identity"]
    expression: str = Field(min_length=1, max_length=2000)
    rhs: str = Field(min_length=1, max_length=2000)


class BoundTransformClaim(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    operation: Literal["simplify", "expand", "factor", "differentiate"]
    expression: str = Field(min_length=1, max_length=2000)
    variable: str = Field(min_length=1, max_length=32)
    result: str = Field(min_length=1, max_length=2000)


class TaskBoundCheck(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    status: Literal["EXPERIMENTAL", "INCOMPLETE", "INVALID_CERTIFICATE", "UNSUPPORTED"]
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    equal: bool | None = None
    domain_status: Literal["PRESERVED", "EXPANDED", "RESTRICTED", "CHANGED", "UNSUPPORTED", "NOT_CHECKED"] = "NOT_CHECKED"
    domain_explanation: str | None = None
    explanation: str


def _hash_json(value: dict) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def verify_task_bound_candidate(request: MathRequest, raw: str) -> TaskBoundCheck:
    """Check a candidate against a request, never against a self-selected task.

    Supported initially: identity verification and simplify/expand/factor/
    differentiate. Integration is excluded because constants, domains, and
    branch conventions need a richer semantic contract.
    """
    request_hash = _hash_json(request.model_dump(mode="json"))
    if not isinstance(raw, str) or not raw.strip() or len(raw) > 10000:
        raise ValueError("candidate must be non-empty text no longer than 10000 characters")
    candidate_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()

    try:
        decoded = json.loads(raw)
        operation = decoded.get("operation") if isinstance(decoded, dict) else None
        if operation == "verify_identity":
            claim = BoundIdentityClaim.model_validate(decoded)
            if request.operation.value != "verify_identity":
                return TaskBoundCheck(status="INVALID_CERTIFICATE", request_sha256=request_hash,
                    candidate_sha256=candidate_hash, explanation="Candidate operation does not match the request.")
            if request.rhs is None or claim.expression != request.expression or claim.rhs != request.rhs:
                return TaskBoundCheck(status="INVALID_CERTIFICATE", request_sha256=request_hash,
                    candidate_sha256=candidate_hash, explanation="Candidate expressions do not exactly match the requested identity.")
            checked = verify_identity(request.expression, request.rhs)
        elif operation in {"simplify", "expand", "factor", "differentiate"}:
            claim = BoundTransformClaim.model_validate(decoded)
            if request.operation.value != claim.operation:
                return TaskBoundCheck(status="INVALID_CERTIFICATE", request_sha256=request_hash,
                    candidate_sha256=candidate_hash, explanation="Candidate operation does not match the request.")
            if claim.expression != request.expression or claim.variable != request.variable:
                return TaskBoundCheck(status="INVALID_CERTIFICATE", request_sha256=request_hash,
                    candidate_sha256=candidate_hash, explanation="Candidate input or variable does not exactly match the request.")
            if claim.variable not in {"x", "y", "z"}:
                return TaskBoundCheck(status="UNSUPPORTED", request_sha256=request_hash,
                    candidate_sha256=candidate_hash, explanation="The requested differentiation variable is outside the supported symbol set.")
            expected = run_algebra(claim.operation, request.expression, request.variable)
            checked = verify_identity(claim.result, str(expected))
            domain_check = None
            if claim.operation in {"simplify", "expand", "factor"}:
                domain_check = check_domain_preservation(request, claim.result)
                if domain_check.status == "UNSUPPORTED":
                    return TaskBoundCheck(
                        status="UNSUPPORTED", request_sha256=request_hash,
                        candidate_sha256=candidate_hash, equal=checked["equal"],
                        domain_status=domain_check.status,
                        domain_explanation=domain_check.explanation,
                        explanation="Algebraic comparison completed, but domain preservation could not be checked.",
                    )
                if domain_check.status != "PRESERVED":
                    return TaskBoundCheck(
                        status="INCOMPLETE", request_sha256=request_hash,
                        candidate_sha256=candidate_hash, equal=False,
                        domain_status=domain_check.status,
                        domain_explanation=domain_check.explanation,
                        explanation="Candidate is algebraically comparable but does not preserve the original expression domain.",
                    )
        else:
            return TaskBoundCheck(status="UNSUPPORTED", request_sha256=request_hash,
                candidate_sha256=candidate_hash, explanation="Candidate operation is not supported by task-bound checking.")
    except (json.JSONDecodeError, ValidationError, TypeError, AttributeError):
        return TaskBoundCheck(status="INVALID_CERTIFICATE", request_sha256=request_hash,
            candidate_sha256=candidate_hash, explanation="Candidate does not match a supported strict claim schema.")
    except ExpressionError:
        return TaskBoundCheck(status="INVALID_CERTIFICATE", request_sha256=request_hash,
            candidate_sha256=candidate_hash, explanation="Candidate or requested expression is outside MOSAIC's restricted algebra grammar.")

    return TaskBoundCheck(
        status=checked["status"], request_sha256=request_hash,
        candidate_sha256=candidate_hash, equal=checked["equal"],
        domain_status=(
            domain_check.status if "domain_check" in locals() and domain_check is not None
            else "NOT_CHECKED"
        ),
        domain_explanation=(
            domain_check.explanation if "domain_check" in locals() and domain_check is not None
            else None
        ),
        explanation=checked["explanation"],
    )
