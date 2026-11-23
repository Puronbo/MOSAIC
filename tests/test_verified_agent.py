import asyncio
import json

from mosaic.core.adapters import ModelCapability
from mosaic.core.orchestration import AgentRole
from mosaic.core.requests import MathRequest
from mosaic.core.verified_agent import run_verified_agent
from mosaic.verification.lean_obligations import LeanIdentityVerification


class SequenceProvider:
    def __init__(self, outputs):
        self.outputs = iter(outputs)
        self.prompts = []
        self._capability = ModelCapability(
            provider_id="sequence",
            model_id="sequence-test",
            supported_roles=(AgentRole.SOLVER,),
        )

    @property
    def capability(self):
        return self._capability

    async def generate(self, request):
        self.prompts.append(request.prompt)
        return next(self.outputs)


def identity_candidate(expression="x + 1", rhs="1 + x"):
    return json.dumps({
        "operation": "verify_identity",
        "expression": expression,
        "rhs": rhs,
    })


def test_verified_agent_revises_rejected_candidate_then_accepts(monkeypatch):
    from mosaic.core import model_gateway

    checks = iter([
        model_gateway.ModelCandidateEvaluation(
            provider_id="sequence", model_id="sequence-test",
            status="REJECTED", request_sha256="a" * 64,
            candidate_sha256="b" * 64,
            task_bound_check=model_gateway.TaskBoundCheck(
                status="EXPERIMENTAL", request_sha256="a" * 64,
                candidate_sha256="b" * 64, equal=False, explanation="mismatch",
            ),
            explanation="mismatch",
        ),
        model_gateway.ModelCandidateEvaluation(
            provider_id="sequence", model_id="sequence-test",
            status="FORMALLY_VERIFIED", request_sha256="c" * 64,
            candidate_sha256="d" * 64,
            task_bound_check=model_gateway.TaskBoundCheck(
                status="EXPERIMENTAL", request_sha256="c" * 64,
                candidate_sha256="d" * 64, equal=True, explanation="equal",
            ),
            lean_check=LeanIdentityVerification(
                status="FORMALLY_VERIFIED", explanation="Lean accepted",
            ),
            explanation="accepted",
        ),
    ])
    from mosaic.core import verified_agent\n    monkeypatch.setattr(verified_agent, "evaluate_model_candidate", lambda submission: next(checks))
    provider = SequenceProvider(["not json", identity_candidate()])
    result = asyncio.run(run_verified_agent(
        MathRequest(operation="verify_identity", expression="x + 1", rhs="1 + x"),
        provider,
    ))
    assert result.status == "FORMALLY_VERIFIED"
    assert len(result.attempts) == 2
    assert "previous_checker_feedback" in provider.prompts[1]


def test_verified_agent_stops_on_kernel_outage(monkeypatch):
    from mosaic.core import model_gateway
    from mosaic.verification.task_bound import TaskBoundCheck
    from mosaic.verification.lean_obligations import LeanIdentityVerification

    def unavailable(submission):
        return model_gateway.ModelCandidateEvaluation(
            provider_id=submission.provider_id, model_id=submission.model_id,
            status="KERNEL_UNAVAILABLE", request_sha256="a" * 64,
            candidate_sha256="b" * 64,
            task_bound_check=TaskBoundCheck(
                status="EXPERIMENTAL", request_sha256="a" * 64,
                candidate_sha256="b" * 64, equal=True, explanation="equal",
            ),
            lean_check=LeanIdentityVerification(
                status="KERNEL_UNAVAILABLE", explanation="Lean unavailable",
            ),
            explanation="Lean unavailable",
        )

    from mosaic.core import verified_agent\n    monkeypatch.setattr(verified_agent, "evaluate_model_candidate", unavailable)
    provider = SequenceProvider([identity_candidate(), identity_candidate()])
    result = asyncio.run(run_verified_agent(
        MathRequest(operation="verify_identity", expression="x + 1", rhs="1 + x"),
        provider,
    ))
    assert result.status == "KERNEL_UNAVAILABLE"
    assert len(result.attempts) == 1


def test_verified_agent_bounds_revision_count(monkeypatch):
    from mosaic.core import model_gateway
    from mosaic.verification.task_bound import TaskBoundCheck

    def rejected(submission):
        return model_gateway.ModelCandidateEvaluation(
            provider_id=submission.provider_id, model_id=submission.model_id,
            status="REJECTED", request_sha256="a" * 64,
            candidate_sha256="b" * 64,
            task_bound_check=TaskBoundCheck(
                status="EXPERIMENTAL", request_sha256="a" * 64,
                candidate_sha256="b" * 64, equal=False, explanation="mismatch",
            ),
            explanation="mismatch",
        )

    from mosaic.core import verified_agent\n    monkeypatch.setattr(verified_agent, "evaluate_model_candidate", rejected)
    provider = SequenceProvider([identity_candidate()] * 5)
    result = asyncio.run(run_verified_agent(
        MathRequest(operation="verify_identity", expression="x + 1", rhs="1 + x"),
        provider, max_attempts=2,
    ))
    assert result.status == "REJECTED"
    assert len(result.attempts) == 2
    assert len(provider.prompts) == 2
