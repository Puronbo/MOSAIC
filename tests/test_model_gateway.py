import json

from fastapi.testclient import TestClient

from mosaic.api import app
from mosaic.core.model_gateway import ModelCandidateSubmission, evaluate_model_candidate
from mosaic.core.requests import MathRequest
from mosaic.verification.lean_obligations import LeanIdentityVerification
from mosaic.verification.task_bound import TaskBoundCheck


def _task_check(*, equal=True, status="EXPERIMENTAL"):
    return TaskBoundCheck(
        status=status,
        request_sha256="a" * 64,
        candidate_sha256="b" * 64,
        equal=equal,
        explanation="task-bound check",
    )


def test_gateway_requires_task_bound_and_lean_acceptance(monkeypatch):
    from mosaic.core import model_gateway

    monkeypatch.setattr(
        model_gateway, "verify_task_bound_candidate",
        lambda request, candidate: _task_check(),
    )
    monkeypatch.setattr(
        model_gateway, "verify_request_identity_with_lean",
        lambda request: LeanIdentityVerification(
            status="FORMALLY_VERIFIED",
            explanation="accepted by Lean",
        ),
    )
    submission = ModelCandidateSubmission(
        request=MathRequest(
            operation="verify_identity",
            expression="x + 1",
            rhs="1 + x",
        ),
        candidate=json.dumps({
            "operation": "verify_identity",
            "expression": "x + 1",
            "rhs": "1 + x",
        }),
        provider_id="test-provider",
        model_id="test-model",
    )
    result = evaluate_model_candidate(submission)
    assert result.status == "FORMALLY_VERIFIED"
    assert result.provider_id == "test-provider"
    assert result.request_sha256 == "a" * 64
    assert result.candidate_sha256 == "b" * 64
    serialized = result.model_dump(mode="json")
    assert serialized["lean_check"]["status"] == "FORMALLY_VERIFIED"


def test_gateway_never_promotes_failed_task_bound_candidate(monkeypatch):
    from mosaic.core import model_gateway

    monkeypatch.setattr(
        model_gateway, "verify_task_bound_candidate",
        lambda request, candidate: _task_check(equal=False),
    )
    monkeypatch.setattr(
        model_gateway, "verify_request_identity_with_lean",
        lambda request: (_ for _ in ()).throw(AssertionError("Lean must not run")),
    )
    submission = ModelCandidateSubmission(
        request=MathRequest(
            operation="verify_identity",
            expression="x + 1",
            rhs="1 + x",
        ),
        candidate="untrusted model output",
    )
    result = evaluate_model_candidate(submission)
    assert result.status == "REJECTED"
    assert result.lean_check is None


def test_ai_candidate_endpoint_rejects_unknown_fields():
    client = TestClient(app)
    response = client.post("/v1/ai/candidate", json={
        "request": {
            "operation": "verify_identity",
            "expression": "x + 1",
            "rhs": "1 + x",
        },
        "candidate": "{}",
        "provider_id": "external",
        "model_id": "model",
        "lean_source": "by trivial",
    })
    assert response.status_code == 422


def test_gateway_keeps_kernel_unavailable_distinct_from_proof(monkeypatch):
    from mosaic.core import model_gateway
    from mosaic.verification.lean_obligations import LeanIdentityVerification

    monkeypatch.setattr(
        model_gateway, "verify_task_bound_candidate",
        lambda request, candidate: _task_check(),
    )
    monkeypatch.setattr(
        model_gateway, "verify_request_identity_with_lean",
        lambda request: LeanIdentityVerification(
            status="KERNEL_UNAVAILABLE",
            explanation="Lean executable unavailable",
        ),
    )
    submission = ModelCandidateSubmission(
        request=MathRequest(
            operation="verify_identity",
            expression="x + 1",
            rhs="1 + x",
        ),
        candidate=json.dumps({
            "operation": "verify_identity",
            "expression": "x + 1",
            "rhs": "1 + x",
        }),
    )
    result = evaluate_model_candidate(submission)
    assert result.status == "KERNEL_UNAVAILABLE"
    assert result.status != "FORMALLY_VERIFIED"


def test_gateway_formally_checks_domain_preserving_transformation(monkeypatch):
    from mosaic.core import model_gateway
    from mosaic.verification.lean_transformations import LeanTransformationVerification

    monkeypatch.setattr(
        model_gateway, "verify_task_bound_candidate",
        lambda request, candidate: TaskBoundCheck(
            status="EXPERIMENTAL",
            request_sha256="c" * 64,
            candidate_sha256="d" * 64,
            equal=True,
            domain_status="PRESERVED",
            explanation="equivalent and domain preserved",
        ),
    )
    seen = {}

    def fake_lean(request, result):
        seen["result"] = result
        return LeanTransformationVerification(
            status="FORMALLY_VERIFIED",
            explanation="Lean accepted the request-bound identity",
        )

    monkeypatch.setattr(
        model_gateway, "verify_request_transformation_with_lean", fake_lean
    )
    submission = ModelCandidateSubmission(
        request=MathRequest(
            operation="expand",
            expression="(x + 1)^2",
        ),
        candidate=json.dumps({
            "operation": "expand",
            "expression": "(x + 1)^2",
            "variable": "x",
            "result": "x^2 + 2*x + 1",
        }),
    )
    result = evaluate_model_candidate(submission)
    assert seen["result"] == "x^2 + 2*x + 1"
    assert result.status == "FORMALLY_VERIFIED"
