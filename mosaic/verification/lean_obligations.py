"""Request-bound Lean checking for the narrow closed-Nat identity obligation.

This adapter never accepts a caller-selected proposition: it derives both sides
from the immutable MathRequest and supports only verify_identity requests.
"""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from mosaic.core.requests import MathRequest
from mosaic.verification.obligations import request_fingerprint
from mosaic.verification.lean_kernel import LeanKernelCheck, verify_closed_nat_equality


class LeanIdentityObligation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    obligation_id: str = Field(min_length=1, max_length=120)
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    checker_id: Literal["lean.kernel.closed_nat_equality.v1", "lean.kernel.linear_int_identity.v1"]
    proposition: str = Field(min_length=1, max_length=1100)
    assumptions: tuple[str, ...] = ()


class LeanIdentityVerification(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal[
        "FORMALLY_VERIFIED", "REJECTED", "UNSUPPORTED",
        "KERNEL_UNAVAILABLE", "KERNEL_ERROR",
    ]
    obligation: LeanIdentityObligation | None = None
    check: LeanKernelCheck | object | None = None
    explanation: str


def verify_request_identity_with_lean(request: MathRequest) -> LeanIdentityVerification:
    """Kernel-check only the exact identity encoded in a verify_identity request."""
    if request.operation.value != "verify_identity" or request.rhs is None:
        return LeanIdentityVerification(
            status="UNSUPPORTED",
            explanation="Lean identity checking requires a verify_identity request with an explicit right-hand side.",
        )

    fingerprint = request_fingerprint(request)
    obligation = LeanIdentityObligation(
        obligation_id=f"request:{fingerprint[:16]}:lean-identity",
        request_sha256=fingerprint,
        checker_id="lean.kernel.closed_nat_equality.v1",
        proposition=f"({request.expression}) = ({request.rhs})",
        assumptions=(),
    )
    check = verify_closed_nat_equality(request.expression, request.rhs)
    if check.status == "UNSUPPORTED":
        from mosaic.verification.lean_linear import verify_linear_int_identity
        linear_check = verify_linear_int_identity(request.expression, request.rhs)
        if linear_check.status != "UNSUPPORTED":
            obligation = obligation.model_copy(update={
                "checker_id": "lean.kernel.linear_int_identity.v1",
            })
            return LeanIdentityVerification(
                status=linear_check.status,
                obligation=obligation,
                check=linear_check,
                explanation=(
                    "The exact request identity was translated to a universally quantified affine Int proposition and checked by Lean."
                    if linear_check.status == "FORMALLY_VERIFIED"
                    else linear_check.explanation
                ),
            )
    return LeanIdentityVerification(
        status=check.status if check.status in {
            "FORMALLY_VERIFIED", "REJECTED", "KERNEL_UNAVAILABLE", "KERNEL_ERROR"
        } else "UNSUPPORTED",
        obligation=obligation,
        check=check,
        explanation=(
            "The exact identity from the request was submitted to the Lean kernel."
            if check.status == "FORMALLY_VERIFIED"
            else check.explanation
        ),
    )
