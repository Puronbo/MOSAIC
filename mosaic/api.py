"""FastAPI adapter for MOSAIC mathematical operations and candidate verification."""
from typing import Literal

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from mosaic.core.requests import MathRequest
from mosaic.core.model_gateway import ModelCandidateSubmission, ModelCandidateEvaluation, evaluate_model_candidate
from mosaic.core.tool_schema import mosaic_candidate_tool
from mosaic.core.responses import MathResponse
from mosaic.core.types import Status
from mosaic.engines.algebra import ExpressionError, run_algebra
from mosaic.verification.exact_checker import verify_identity
from mosaic.verification.task_bound import TaskBoundCheck, verify_task_bound_candidate
from mosaic.verification.evidence import EvidenceBundle, evidence_from_check
from mosaic.verification.lean_kernel import LeanKernelCheck, verify_closed_nat_equality
from mosaic.verification.lean_obligations import LeanIdentityVerification, verify_request_identity_with_lean
from mosaic.verification.lean_polynomial import LeanPolynomialCheck, verify_polynomial_int_identity
from mosaic.verification.lean_calculus import (
    LeanPolynomialDerivativeCheck, verify_polynomial_real_derivative,
)
from mosaic.verification.lean_transformations import (
    LeanTransformationVerification, verify_request_transformation_with_lean,
)
from mosaic.verification.sessions import (
    RevisionLimitReached, SessionStore, VerificationSession, VerificationRevision,
)


app = FastAPI(title="MOSAIC API", version="0.9.0")
session_store = SessionStore()


class TaskBoundVerificationRequest(BaseModel):
    """An exact mathematical task paired with an untrusted candidate payload."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    request: MathRequest
    candidate: str = Field(min_length=1, max_length=10000)


class CandidateFeedback(BaseModel):
    """Machine-actionable guidance; never a substitute for checker evidence."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    code: Literal[
        "DOMAIN_RESTRICTION_LOST", "ALGEBRAIC_MISMATCH",
        "INVALID_CANDIDATE", "UNSUPPORTED_CHECK", "REVIEW_RESULT",
    ]
    severity: Literal["error", "warning", "info"]
    message: str
    action: str
    retryable: bool


class TaskBoundVerificationResponse(BaseModel):
    """Versioned machine-readable result and revision guidance."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "1.1"
    checker_id: str = "mosaic.task_bound_candidate.v1"
    check: TaskBoundCheck
    feedback: tuple[CandidateFeedback, ...] = ()
    evidence: EvidenceBundle


def _candidate_feedback(check: TaskBoundCheck) -> tuple[CandidateFeedback, ...]:
    feedback: list[CandidateFeedback] = []
    if check.domain_status in {"EXPANDED", "RESTRICTED", "CHANGED"}:
        missing = ", ".join(check.domain_certificate.missing_factors) if check.domain_certificate else ""
        detail = f" Missing nonzero restrictions: {missing}." if missing else ""
        feedback.append(CandidateFeedback(
            code="DOMAIN_RESTRICTION_LOST", severity="error",
            message="The candidate changes the expression's detected rational domain." + detail,
            action="Revise the candidate so it retains the original excluded values, then resubmit against the same request.",
            retryable=True,
        ))
    if check.equal is False and check.domain_status not in {"EXPANDED", "RESTRICTED", "CHANGED"}:
        feedback.append(CandidateFeedback(
            code="ALGEBRAIC_MISMATCH", severity="error",
            message="The candidate result did not match the independently recomputed result.",
            action="Recompute the requested operation from the unchanged request and submit a corrected result.",
            retryable=True,
        ))
    if check.status == "INVALID_CERTIFICATE":
        feedback.append(CandidateFeedback(
            code="INVALID_CANDIDATE", severity="error",
            message="The candidate is malformed or is not bound to the supplied task.",
            action="Use the supported candidate schema and copy operation, expression, and variable exactly from the request.",
            retryable=True,
        ))
    if check.status == "UNSUPPORTED":
        feedback.append(CandidateFeedback(
            code="UNSUPPORTED_CHECK", severity="warning",
            message="MOSAIC cannot currently evaluate every required condition for this candidate.",
            action="Do not treat this result as accepted; use a checker that supports the missing semantics or narrow the claim.",
            retryable=False,
        ))
    if check.status == "EXPERIMENTAL" and check.equal is True:
        feedback.append(CandidateFeedback(
            code="REVIEW_RESULT", severity="info",
            message="The candidate passed the available experimental checks; this is not a formal proof.",
            action="Retain the request, candidate, hashes, and checker version; seek formal verification when proof-level assurance is required.",
            retryable=False,
        ))
    return tuple(feedback)


class LeanEqualityVerificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    lhs: str = Field(min_length=1, max_length=512)
    rhs: str = Field(min_length=1, max_length=512)


class LeanPolynomialDerivativeRequest(BaseModel):
    """A bounded real-polynomial derivative claim; no caller Lean source."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    expression: str = Field(min_length=1, max_length=512)
    candidate_derivative: str | None = Field(default=None, max_length=512)


class LeanTransformationVerificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    request: MathRequest
    result: str = Field(min_length=1, max_length=512)


class VerificationSessionCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    request: MathRequest


class VerificationSessionRevisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    candidate: str = Field(min_length=1, max_length=10000)


@app.post("/v1/ai/candidate", response_model=ModelCandidateEvaluation)
def evaluate_ai_candidate(payload: ModelCandidateSubmission):
    """Evaluate an external model proposal; provider metadata is provenance only."""
    return evaluate_model_candidate(payload)


@app.get("/v1/ai/tool-schema")
def get_ai_candidate_tool_schema():
    """Return a portable function-tool declaration for AI agent registration."""
    return mosaic_candidate_tool()


@app.post("/v1/verification-sessions", response_model=VerificationSession, status_code=201)
def create_verification_session(payload: VerificationSessionCreateRequest):
    """Create a session whose mathematical request cannot be changed."""
    return session_store.create(payload.request)


@app.get("/v1/verification-sessions/{session_id}", response_model=VerificationSession)
def get_verification_session(session_id: str):
    session = session_store.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Verification session not found.")
    return session


@app.post(
    "/v1/verification-sessions/{session_id}/revisions",
    response_model=VerificationRevision,
    status_code=201,
)
def append_verification_revision(
    session_id: str, payload: VerificationSessionRevisionRequest
):
    """Append a candidate against the session's original, stored request."""
    session = session_store.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Verification session not found.")
    try:
        check = verify_task_bound_candidate(session.request, payload.candidate)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    feedback = _candidate_feedback(check)
    try:
        revision = session_store.append(
            session_id, payload.candidate, check,
            tuple(item.model_dump(mode="json") for item in feedback),
            evidence_from_check(check, session.request, payload.candidate),
        )
    except RevisionLimitReached as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if revision is None:
        raise HTTPException(status_code=404, detail="Verification session not found.")
    return revision


@app.post("/v1/verify/lean/closed-nat-equality", response_model=LeanKernelCheck)
def verify_lean_closed_nat_equality(payload: LeanEqualityVerificationRequest):
    """Kernel-check a bounded, closed Nat equality when Lean is installed."""
    return verify_closed_nat_equality(payload.lhs, payload.rhs)


@app.post(
    "/v1/verify/lean/polynomial-int-identity",
    response_model=LeanPolynomialCheck,
)
def verify_lean_polynomial_int_identity(payload: LeanEqualityVerificationRequest):
    """Kernel-check a bounded polynomial identity using the pinned Mathlib project."""
    return verify_polynomial_int_identity(payload.lhs, payload.rhs)


@app.post(
    "/v1/verify/lean/polynomial-real-derivative",
    response_model=LeanPolynomialDerivativeCheck,
)
def verify_lean_polynomial_real_derivative(payload: LeanPolynomialDerivativeRequest):
    """Prove a bounded real-polynomial derivative, optionally checking a candidate."""
    return verify_polynomial_real_derivative(
        payload.expression, candidate_derivative=payload.candidate_derivative
    )


@app.post("/v1/verify/lean/request-identity", response_model=LeanIdentityVerification)
def verify_lean_request_identity(payload: VerificationSessionCreateRequest):
    """Formally check only the exact identity encoded in the supplied request."""
    return verify_request_identity_with_lean(payload.request)


@app.post("/v1/verify/lean/transformation", response_model=LeanTransformationVerification)
def verify_lean_transformation(payload: LeanTransformationVerificationRequest):
    """Kernel-check a bounded affine result against its exact request input."""
    return verify_request_transformation_with_lean(payload.request, payload.result)


@app.get("/health")
def health():
    return {"status": "ok", "service": "mosaic", "version": "0.8.0"}


@app.post("/v1/math", response_model=MathResponse)
def math_operation(request: MathRequest):
    operation = request.operation.value
    try:
        if operation == "verify_identity":
            if request.rhs is None:
                raise HTTPException(status_code=422, detail="rhs is required for verify_identity.")
            checked = verify_identity(request.expression, request.rhs)
            return MathResponse(status=Status(checked["status"]), operation=operation,
                                result=str(checked["equal"]), certificate=checked["certificate"],
                                explanation=checked["explanation"])
        if operation in {"simplify", "expand", "factor", "differentiate", "integrate"}:
            result = run_algebra(operation, request.expression, request.variable)
            return MathResponse(status=Status.EXPERIMENTAL, operation=operation, result=str(result),
                                explanation="Computed by the SymPy-backed prototype; this is not a formal proof.")
        return MathResponse(status=Status.UNSUPPORTED, operation=operation, result=None,
                            explanation="This operation is registered but not implemented in the initial prototype.")
    except ExpressionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/v1/verify/task-bound", response_model=TaskBoundVerificationResponse)
def verify_task_bound(payload: TaskBoundVerificationRequest):
    """Check a candidate against the supplied request; never trust candidate task fields."""
    try:
        check = verify_task_bound_candidate(payload.request, payload.candidate)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return TaskBoundVerificationResponse(
        check=check, feedback=_candidate_feedback(check),
        evidence=evidence_from_check(check, payload.request, payload.candidate),
    )
