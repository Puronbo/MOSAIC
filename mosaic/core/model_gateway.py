"""Model-facing candidate gateway with independent MOSAIC verification.

Provider identity is provenance only. Candidate text is untrusted, and formal
status requires both task-bound semantic checks and an accepted Lean proof.
"""
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, computed_field

from mosaic.core.requests import MathRequest
from mosaic.verification.lean_obligations import (
    LeanIdentityVerification,
    verify_request_identity_with_lean,
)
from mosaic.verification.lean_transformations import (
    LeanTransformationVerification,
    verify_request_transformation_with_lean,
)
from mosaic.verification.task_bound import (
    TaskBoundCheck,
    verify_task_bound_candidate,
)


class ModelCandidateSubmission(BaseModel):
    """Provider-attributed proposal; attribution never confers trust."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    request: MathRequest
    candidate: str = Field(min_length=1, max_length=10000)
    provider_id: str = Field(default="external", min_length=1, max_length=80)
    model_id: str = Field(default="unspecified", min_length=1, max_length=160)


class ModelCandidateFeedback(BaseModel):
    """Structured revision guidance derived from checker output, not model confidence."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    code: Literal[
        "DOMAIN_RESTRICTION_LOST", "ALGEBRAIC_MISMATCH",
        "INVALID_CANDIDATE", "UNSUPPORTED_CHECK",
        "REVIEW_RESULT", "FORMAL_CHECK_UNAVAILABLE",
    ]
    severity: Literal["error", "warning", "info"]
    message: str
    action: str
    retryable: bool


class ModelCandidateEvaluation(BaseModel):
    """Machine-readable result separating proposal acceptance from proof."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    provider_id: str
    model_id: str
    status: Literal[
        "FORMALLY_VERIFIED", "REJECTED", "UNSUPPORTED",
        "KERNEL_UNAVAILABLE", "KERNEL_ERROR", "EXPERIMENTAL",
        "INCOMPLETE", "INVALID_CANDIDATE",
    ]
    request_sha256: str
    candidate_sha256: str
    task_bound_check: TaskBoundCheck
    lean_check: LeanIdentityVerification | LeanTransformationVerification | None = None
    explanation: str

    @computed_field
    @property
    def feedback(self) -> tuple[ModelCandidateFeedback, ...]:
        """Return actionable next steps without upgrading any verification status."""
        if self.status == "FORMALLY_VERIFIED":
            return ()
        if self.status == "INVALID_CANDIDATE":
            item = ModelCandidateFeedback(
                code="INVALID_CANDIDATE", severity="error",
                message="The candidate is malformed or is not bound to the supplied task.",
                action="Use the strict candidate schema and copy operation, expression, and variable exactly from the original request.",
                retryable=True,
            )
        elif self.status == "UNSUPPORTED":
            item = ModelCandidateFeedback(
                code="UNSUPPORTED_CHECK", severity="warning",
                message="MOSAIC cannot currently evaluate every required condition for this candidate.",
                action="Do not treat this result as accepted; use a checker that supports the missing semantics or narrow the claim.",
                retryable=False,
            )
        elif self.status == "INCOMPLETE":
            item = ModelCandidateFeedback(
                code="DOMAIN_RESTRICTION_LOST", severity="error",
                message="The candidate did not preserve all detected semantic conditions, including the original expression domain.",
                action="Revise the candidate to preserve the original excluded values, then resubmit against the unchanged request.",
                retryable=True,
            )
        elif self.status == "REJECTED":
            item = ModelCandidateFeedback(
                code="ALGEBRAIC_MISMATCH", severity="error",
                message="The candidate did not match the independently recomputed result.",
                action="Recompute the requested operation from the unchanged request and submit a corrected candidate.",
                retryable=True,
            )
        elif self.status in {"KERNEL_UNAVAILABLE", "KERNEL_ERROR"}:
            item = ModelCandidateFeedback(
                code="FORMAL_CHECK_UNAVAILABLE", severity="warning",
                message="The candidate passed task-bound checks, but the formal proof check could not complete.",
                action="Do not claim formal verification; restore or inspect the Lean environment and retry the same request and candidate.",
                retryable=True,
            )
        else:
            item = ModelCandidateFeedback(
                code="REVIEW_RESULT", severity="info",
                message="The candidate passed available task-bound checks, but formal proof has not been established.",
                action="Retain the complete request, candidate, hashes, and checker results; seek a supported formal proof before relying on it as verified.",
                retryable=False,
            )
        return (item,)


def evaluate_model_candidate(
    submission: ModelCandidateSubmission,
) -> ModelCandidateEvaluation:
    """Evaluate a provider proposal without accepting provider-supplied proofs."""
    check = verify_task_bound_candidate(submission.request, submission.candidate)
    request_hash = check.request_sha256
    candidate_hash = check.candidate_sha256

    if check.status == "INVALID_CERTIFICATE":
        return ModelCandidateEvaluation(
            provider_id=submission.provider_id,
            model_id=submission.model_id,
            status="INVALID_CANDIDATE",
            request_sha256=request_hash,
            candidate_sha256=candidate_hash,
            task_bound_check=check,
            explanation="The model output is not a valid claim bound to the exact request.",
        )
    if check.status == "UNSUPPORTED":
        return ModelCandidateEvaluation(
            provider_id=submission.provider_id,
            model_id=submission.model_id,
            status="UNSUPPORTED",
            request_sha256=request_hash,
            candidate_sha256=candidate_hash,
            task_bound_check=check,
            explanation="The submitted claim is outside the currently supported task-bound checks.",
        )
    if check.status == "INCOMPLETE":
        return ModelCandidateEvaluation(
            provider_id=submission.provider_id,
            model_id=submission.model_id,
            status="INCOMPLETE",
            request_sha256=request_hash,
            candidate_sha256=candidate_hash,
            task_bound_check=check,
            explanation="The candidate did not satisfy all semantic conditions, including domain preservation.",
        )
    if check.equal is not True:
        return ModelCandidateEvaluation(
            provider_id=submission.provider_id,
            model_id=submission.model_id,
            status="REJECTED",
            request_sha256=request_hash,
            candidate_sha256=candidate_hash,
            task_bound_check=check,
            explanation="The independently recomputed task-bound check rejected the candidate.",
        )

    lean_check = None
    if submission.request.operation.value == "verify_identity":
        lean_check = verify_request_identity_with_lean(submission.request)
    elif submission.request.operation.value in {"simplify", "expand", "factor"}:
        try:
            decoded = json.loads(submission.candidate)
            result = decoded["result"]
        except (json.JSONDecodeError, KeyError, TypeError):
            result = ""
        lean_check = verify_request_transformation_with_lean(
            submission.request, result
        ) if isinstance(result, str) else None

    if lean_check is None:
        status = "EXPERIMENTAL"
        explanation = "The candidate passed task-bound checks, but no formal checker is available for this operation."
    elif lean_check.status == "FORMALLY_VERIFIED":
        status = "FORMALLY_VERIFIED"
        explanation = (
            "The candidate passed task-bound semantic checks and the exact request-bound proposition "
            "was accepted by the configured Lean kernel."
        )
    else:
        status = lean_check.status
        explanation = (
            "The candidate passed task-bound checks, but formal verification did not complete: "
            + lean_check.explanation
        )

    return ModelCandidateEvaluation(
        provider_id=submission.provider_id,
        model_id=submission.model_id,
        status=status,
        request_sha256=request_hash,
        candidate_sha256=candidate_hash,
        task_bound_check=check,
        lean_check=lean_check,
        explanation=explanation,
    )
