import json

from fastapi.testclient import TestClient

from mosaic.api import app

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_expand_endpoint():
    response = client.post("/v1/math", json={
        "operation": "expand", "expression": "(x+1)**2"
    })
    assert response.status_code == 200
    assert response.json()["result"] == "x**2 + 2*x + 1"
    assert response.json()["status"] == "EXPERIMENTAL"


def test_identity_requires_rhs():
    response = client.post("/v1/math", json={
        "operation": "verify_identity", "expression": "x+1"
    })
    assert response.status_code == 422


def _candidate(expression: str, result: str) -> str:
    return json.dumps({
        "operation": "simplify",
        "expression": expression,
        "variable": "x",
        "result": result,
    })


def test_task_bound_endpoint_returns_versioned_domain_certificate_and_feedback():
    response = client.post("/v1/verify/task-bound", json={
        "request": {"operation": "simplify", "expression": "(x**2 - 1)/(x - 1)"},
        "candidate": _candidate("(x**2 - 1)/(x - 1)", "(x + 1)*(x - 1)/(x - 1)"),
    })
    assert response.status_code == 200
    body = response.json()
    assert body["schema_version"] == "1.1"
    assert body["checker_id"] == "mosaic.task_bound_candidate.v1"
    assert body["check"]["status"] == "EXPERIMENTAL"
    assert body["check"]["domain_status"] == "PRESERVED"
    assert body["check"]["domain_certificate"]["checker_id"] == "rational_domain_factor_comparison.v1"
    assert body["feedback"][0]["code"] == "REVIEW_RESULT"
    assert body["feedback"][0]["retryable"] is False


def test_task_bound_endpoint_returns_revision_guidance_for_lost_domain():
    expression = "((x**2 - 1)/(x - 1))**2"
    response = client.post("/v1/verify/task-bound", json={
        "request": {"operation": "simplify", "expression": expression},
        "candidate": _candidate(expression, "(x + 1)**2"),
    })
    assert response.status_code == 200
    body = response.json()
    assert body["check"]["status"] == "INCOMPLETE"
    assert body["check"]["domain_status"] == "EXPANDED"
    assert body["check"]["domain_certificate"]["missing_factors"] == ["x - 1"]
    feedback = body["feedback"][0]
    assert feedback["code"] == "DOMAIN_RESTRICTION_LOST"
    assert feedback["retryable"] is True
    assert "x - 1" in feedback["message"]


def test_task_bound_endpoint_reports_algebraic_mismatch():
    expression = "(x + 1)**2"
    response = client.post("/v1/verify/task-bound", json={
        "request": {"operation": "simplify", "expression": expression},
        "candidate": _candidate(expression, "x + 1"),
    })
    assert response.status_code == 200
    body = response.json()
    assert body["check"]["equal"] is False
    assert body["feedback"][0]["code"] == "ALGEBRAIC_MISMATCH"


def test_task_bound_endpoint_rejects_unknown_fields():
    response = client.post("/v1/verify/task-bound", json={
        "request": {"operation": "simplify", "expression": "x"},
        "candidate": "{}",
        "trust_me": True,
    })
    assert response.status_code == 422


def test_task_bound_endpoint_rejects_oversized_candidate():
    response = client.post("/v1/verify/task-bound", json={
        "request": {"operation": "simplify", "expression": "x"},
        "candidate": " " * 10001,
    })
    assert response.status_code == 422
