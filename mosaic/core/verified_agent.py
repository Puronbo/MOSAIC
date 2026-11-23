"""Bounded provider -> candidate -> independent verification -> revision loop.

Models only propose JSON claims. The MOSAIC gateway alone assigns mathematical
status; provider text and self-reported confidence are never trusted.
"""
import asyncio
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from mosaic.core.adapters import ModelRequest, ProviderError, invoke_provider
from mosaic.core.model_gateway import (
    ModelCandidateEvaluation,
    ModelCandidateSubmission,
    evaluate_model_candidate,
)
from mosaic.core.orchestration import AgentRole
from mosaic.core.requests import MathRequest


class VerifiedAttempt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    attempt: int = Field(ge=1, le=3)
    provider_id: str
    model_id: str
    prompt_sha256: str
    output_sha256: str
    evaluation: ModelCandidateEvaluation


class VerifiedAgentResult(BaseModel):
    """Complete bounded trace; only FORMALLY_VERIFIED denotes Lean acceptance."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal[
        "FORMALLY_VERIFIED", "REJECTED", "UNSUPPORTED", "KERNEL_UNAVAILABLE",
        "KERNEL_ERROR", "EXPERIMENTAL", "INCOMPLETE", "INVALID_CANDIDATE",
        "PROVIDER_ERROR",
    ]
    attempts: tuple[VerifiedAttempt, ...]
    explanation: str


def _candidate_contract(request: MathRequest) -> str:
    if request.operation.value == "verify_identity":
        shape = {
            "operation": "verify_identity",
            "expression": request.expression,
            "rhs": request.rhs,
        }
    else:
        shape = {
            "operation": request.operation.value,
            "expression": request.expression,
            "variable": request.variable,
            "result": "your proposed result as a string",
        }
    return json.dumps(shape, ensure_ascii=False, sort_keys=True)


def _revision_prompt(
    request: MathRequest,
    previous: ModelCandidateEvaluation | None,
) -> str:
    payload = {
        "task": request.model_dump(mode="json"),
        "required_candidate_json_shape": json.loads(_candidate_contract(request)),
        "instructions": [
            "Return exactly one JSON object and no Markdown fences or extra text.",
            "Copy operation, expression, rhs (if present), and variable exactly from the request.",
            "Return exactly the fields shown in the required candidate shape; copy all task-binding fields verbatim.",
            "For identity claims, provide the exact operation, expression, and rhs fields. For transformations, provide the exact operation, expression, variable, and your proposed result.",
            "Do not include Lean source, tactics, proof claims, or confidence-based status.",
            "The candidate will be independently checked. Never claim it is verified.",
        ],
    }
    if previous is not None:
        payload["previous_checker_feedback"] = [
            item.model_dump(mode="json") for item in previous.feedback
        ]
        payload["previous_checker_status"] = previous.status
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


async def run_verified_agent(
    request: MathRequest,
    provider,
    *,
    max_attempts: int = 3,
) -> VerifiedAgentResult:
    """Ask one allow-listed provider for a candidate, then verify/revise at most 3 times.

    Only candidate defects with actionable retryable checker feedback trigger a
    revision. Kernel outages and unsupported semantics stop immediately; asking
    the model again cannot repair the verifier. Lean checking runs off the event
    loop because the configured checker invokes a local process.
    """
    if not 1 <= max_attempts <= 3:
        raise ValueError("max_attempts must be between 1 and 3")
    capability = provider.capability
    if AgentRole.SOLVER not in capability.supported_roles:
        raise ProviderError("provider does not support the solver role")

    trace: list[VerifiedAttempt] = []
    previous = None
    for index in range(1, max_attempts + 1):
        prompt = _revision_prompt(request, previous)
        model_request = ModelRequest(
            role=AgentRole.SOLVER,
            system_instruction=(
                "You are a MOSAIC mathematical candidate generator. "
                "Return strict JSON only. You do not verify proofs."
            ),
            prompt=prompt,
            max_output_tokens=2000,
            timeout_seconds=30,
        )
        try:
            response = await invoke_provider(provider, model_request)
        except ProviderError as exc:
            return VerifiedAgentResult(
                status="PROVIDER_ERROR",
                attempts=tuple(trace),
                explanation=str(exc),
            )

        submission = ModelCandidateSubmission(
            request=request,
            candidate=response.output,
            provider_id=response.provider_id,
            model_id=response.model_id,
        )
        evaluation = await asyncio.to_thread(evaluate_model_candidate, submission)
        trace.append(VerifiedAttempt(
            attempt=index,
            provider_id=response.provider_id,
            model_id=response.model_id,
            prompt_sha256=response.prompt_sha256,
            output_sha256=response.output_sha256,
            evaluation=evaluation,
        ))
        if evaluation.status == "FORMALLY_VERIFIED":
            return VerifiedAgentResult(
                status="FORMALLY_VERIFIED",
                attempts=tuple(trace),
                explanation="Candidate accepted by task-bound checks and the configured Lean kernel.",
            )
        if evaluation.status in {"KERNEL_UNAVAILABLE", "KERNEL_ERROR", "UNSUPPORTED", "EXPERIMENTAL"}:
            return VerifiedAgentResult(
                status=evaluation.status,
                attempts=tuple(trace),
                explanation=evaluation.explanation,
            )
        if not evaluation.feedback or not evaluation.feedback[0].retryable or index == max_attempts:
            return VerifiedAgentResult(
                status=evaluation.status,
                attempts=tuple(trace),
                explanation=evaluation.explanation,
            )
        previous = evaluation

    raise RuntimeError("unreachable verified-agent state")
