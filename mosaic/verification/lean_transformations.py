"""Request-bound Lean checks for affine and bounded polynomial transformations.

Only simplify/expand/factor requests are eligible. This checks equivalence,
not canonical simplification or rational-domain preservation.
"""
import hashlib
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from mosaic.core.requests import MathRequest
from mosaic.verification.obligations import request_fingerprint
from mosaic.verification.lean_linear import LeanLinearCheck, verify_linear_int_identity
from mosaic.verification.lean_polynomial import LeanPolynomialCheck, verify_polynomial_int_identity


class LeanTransformationObligation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    obligation_id: str = Field(min_length=1, max_length=120)
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    operation: Literal["simplify", "expand", "factor"]
    checker_id: Literal["lean.kernel.linear_int_identity.v1", "lean.kernel.polynomial_int_identity.v1"]
    proposition: str = Field(min_length=1, max_length=1100)
    variables: tuple[str, ...] = ()
    assumptions: tuple[str, ...] = ()


class LeanTransformationVerification(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal[
        "FORMALLY_VERIFIED", "REJECTED", "UNSUPPORTED",
        "KERNEL_UNAVAILABLE", "KERNEL_ERROR",
    ]
    obligation: LeanTransformationObligation | None = None
    check: LeanLinearCheck | LeanPolynomialCheck | None = None
    explanation: str


def verify_request_transformation_with_lean(
    request: MathRequest, result: str
) -> LeanTransformationVerification:
    """Verify a proposed affine or polynomial result against the exact request."""
    if request.operation.value not in {"simplify", "expand", "factor"}:
        return LeanTransformationVerification(
            status="UNSUPPORTED",
            explanation="Lean transformation checking currently supports simplify, expand, and factor requests only.",
        )
    if not isinstance(result, str) or not result.strip() or len(result) > 512:
        return LeanTransformationVerification(
            status="UNSUPPORTED",
            explanation="The proposed result must be non-empty text within the 512-character bound.",
        )

    check = verify_linear_int_identity(request.expression, result)
    checker_id = "lean.kernel.linear_int_identity.v1"
    if check.status == "UNSUPPORTED":
        check = verify_polynomial_int_identity(request.expression, result)
        checker_id = "lean.kernel.polynomial_int_identity.v1"
    if check.status == "UNSUPPORTED":
        return LeanTransformationVerification(
            status="UNSUPPORTED",
            check=check,
            explanation="The request or proposed result is outside the supported affine or bounded polynomial Int grammars.",
        )

    request_hash = request_fingerprint(request)
    candidate_hash = hashlib.sha256(result.encode("utf-8")).hexdigest()
    variables = check.variables
    binders = " ".join(f"({name} : Int)" for name in variables)
    quantified = f"∀ {binders}, " if binders else ""
    obligation = LeanTransformationObligation(
        obligation_id=f"request:{request_hash[:16]}:lean-transform:{candidate_hash[:12]}",
        request_sha256=request_hash,
        candidate_sha256=candidate_hash,
        operation=request.operation.value,
        checker_id=checker_id,
        proposition=f"{quantified}({request.expression}) = ({result})",
        variables=variables,
        assumptions=(),
    )
    return LeanTransformationVerification(
        status=check.status,
        obligation=obligation,
        check=check,
        explanation=(
            (
                "Lean kernel-checked the proposed polynomial result using pinned Mathlib."
                if checker_id == "lean.kernel.polynomial_int_identity.v1"
                else "Lean kernel-checked the proposed affine result using omega."
            )
            if check.status == "FORMALLY_VERIFIED"
            else check.explanation
        ),
    )
