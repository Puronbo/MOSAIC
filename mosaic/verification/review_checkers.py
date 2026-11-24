"""Request-bound independent checker dispatch for typed review findings.

A reviewer cannot supply Lean source or a proposition. Dispatch is allowed only
when the finding binds to the exact immutable MathRequest fingerprint and to the
registered request-obligation statement.
"""
from typing import Literal

from pydantic import BaseModel, ConfigDict

from mosaic.core.requests import MathRequest
from mosaic.core.orchestration import ReviewObligation
from mosaic.verification.lean_obligations import (
    LeanIdentityVerification,
    verify_request_identity_with_lean,
)
from mosaic.verification.obligations import (
    obligations_for_request,
    request_fingerprint,
)


class ReviewCheckerReceipt(BaseModel):
    """Traceable result of an allow-listed checker attempt."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    obligation_id: str
    request_sha256: str
    checker_id: str
    status: Literal[
        "FORMALLY_VERIFIED", "REJECTED", "UNSUPPORTED",
        "KERNEL_UNAVAILABLE", "KERNEL_ERROR", "INVALID_CERTIFICATE",
    ]
    checker_result: LeanIdentityVerification | None = None
    explanation: str


def check_review_obligation_with_lean(
    obligation: ReviewObligation,
    request: MathRequest,
) -> ReviewCheckerReceipt:
    """Run the pinned request-bound Lean identity checker, never reviewer text.

    The only accepted checker ID is a local allow-list constant. The finding's
    statement must exactly match the registered obligation generated from the
    supplied request; the request fingerprint must also match. No arbitrary
    proposition or source code is accepted from the reviewer.
    """
    fingerprint = request_fingerprint(request)
    checker_id = "mosaic.lean.request_identity.v1"
    finding = obligation.finding

    def rejected(status: str, explanation: str) -> ReviewCheckerReceipt:
        return ReviewCheckerReceipt(
            obligation_id=obligation.obligation_id,
            request_sha256=fingerprint,
            checker_id=checker_id,
            status=status,
            explanation=explanation,
        )

    if finding.checker_id != checker_id or finding.request_sha256 is None:
        return rejected(
            "UNSUPPORTED",
            "Finding does not explicitly request the registered request-bound Lean checker.",
        )
    if finding.request_sha256 != fingerprint:
        return rejected(
            "INVALID_CERTIFICATE",
            "Finding is bound to a different or stale mathematical request.",
        )

    registered = obligations_for_request(request)[0]
    if registered.kind != "identity" or finding.statement != registered.statement:
        return rejected(
            "UNSUPPORTED",
            "Finding statement does not exactly match a supported registered identity obligation.",
        )

    result = verify_request_identity_with_lean(request)
    return ReviewCheckerReceipt(
        obligation_id=obligation.obligation_id,
        request_sha256=fingerprint,
        checker_id=checker_id,
        status=result.status,
        checker_result=result,
        explanation=result.explanation,
    )
