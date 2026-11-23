import json

from fastapi.testclient import TestClient

from mosaic.api import app
from mosaic.verification.sessions import SessionStore

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
        "operation": "simplify", "expression": expression,
        "variable": "x", "result": result,
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
    assert body["evidence"]["assessment"]["status"] == "MULTI_SOURCE_SUPPORT"
    assert body["evidence"]["assessment"]["independent_support_count"] == 2
    assert body["evidence"]["assessment"]["model_opinion_count"] == 0


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


def test_verification_session_keeps_request_fixed_and_appends_revisions(tmp_path, monkeypatch):
    from mosaic import api as api_module
    monkeypatch.setattr(api_module, "session_store", SessionStore(tmp_path / "sessions.sqlite3"))
    create = client.post("/v1/verification-sessions", json={
        "request": {"operation": "simplify", "expression": "(x**2 - 1)/(x - 1)"}
    })
    assert create.status_code == 201
    session = create.json()
    session_id = session["session_id"]
    original_hash = session["request_sha256"]

    first = client.post(f"/v1/verification-sessions/{session_id}/revisions", json={
        "candidate": _candidate("(x**2 - 1)/(x - 1)", "(x + 1)*(x - 1)/(x - 1)")
    })
    assert first.status_code == 201
    assert first.json()["revision"] == 1
    assert first.json()["check"]["domain_status"] == "PRESERVED"
    assert first.json()["assessment"]["trajectory"] == "FIRST_ATTEMPT"
    assert first.json()["assessment"]["recommendation"] == "STOP_REVIEW"
    assert first.json()["evidence"]["assessment"]["independent_support_count"] == 2

    second = client.post(f"/v1/verification-sessions/{session_id}/revisions", json={
        "candidate": _candidate("(x**2 - 1)/(x - 1)", "(x + 1)*(x - 1)/(x - 1)")
    })
    assert second.status_code == 201
    assert second.json()["revision"] == 2
    assert second.json()["assessment"]["trajectory"] == "UNCHANGED"

    fetched = client.get(f"/v1/verification-sessions/{session_id}")
    assert fetched.status_code == 200
    body = fetched.json()
    assert body["request_sha256"] == original_hash
    assert body["request"]["expression"] == "(x**2 - 1)/(x - 1)"
    assert [item["revision"] for item in body["revisions"]] == [1, 2]
    assert [item["check"]["request_sha256"] for item in body["revisions"]] == [original_hash, original_hash]
    assert all(item["evidence"]["assessment"]["status"] == "MULTI_SOURCE_SUPPORT" for item in body["revisions"])


def test_verification_session_unknown_id_is_not_found():
    response = client.get("/v1/verification-sessions/does-not-exist")
    assert response.status_code == 404


def test_verification_session_rejects_oversized_revision(tmp_path, monkeypatch):
    from mosaic import api as api_module
    monkeypatch.setattr(api_module, "session_store", SessionStore(tmp_path / "oversized.sqlite3"))
    create = client.post("/v1/verification-sessions", json={
        "request": {"operation": "simplify", "expression": "x"}
    })
    session_id = create.json()["session_id"]
    response = client.post(f"/v1/verification-sessions/{session_id}/revisions", json={
        "candidate": "x" * 10001
    })
    assert response.status_code == 422



def test_verification_session_marks_correction_as_improvement(tmp_path, monkeypatch):
    from mosaic import api as api_module
    monkeypatch.setattr(api_module, "session_store", SessionStore(tmp_path / "progress.sqlite3"))
    create = client.post("/v1/verification-sessions", json={
        "request": {"operation": "simplify", "expression": "(x + 1)**2"}
    })
    session_id = create.json()["session_id"]
    bad = client.post(f"/v1/verification-sessions/{session_id}/revisions", json={
        "candidate": _candidate("(x + 1)**2", "x + 1")
    })
    assert bad.status_code == 201
    assert bad.json()["assessment"]["recommendation"] == "CONTINUE"

    corrected = client.post(f"/v1/verification-sessions/{session_id}/revisions", json={
        "candidate": _candidate("(x + 1)**2", "x**2 + 2*x + 1")
    })
    assert corrected.status_code == 201
    assert corrected.json()["assessment"]["trajectory"] == "IMPROVED"
    assert corrected.json()["assessment"]["recommendation"] == "STOP_REVIEW"


def test_verification_session_enforces_revision_limit(tmp_path, monkeypatch):
    from mosaic import api as api_module
    monkeypatch.setattr(api_module, "session_store", SessionStore(
        tmp_path / "bounded.sqlite3", max_revisions=1
    ))
    create = client.post("/v1/verification-sessions", json={
        "request": {"operation": "simplify", "expression": "x"}
    })
    session_id = create.json()["session_id"]
    candidate = _candidate("x", "x")
    first = client.post(f"/v1/verification-sessions/{session_id}/revisions", json={
        "candidate": candidate
    })
    assert first.status_code == 201
    second = client.post(f"/v1/verification-sessions/{session_id}/revisions", json={
        "candidate": candidate
    })
    assert second.status_code == 409


def test_lean_closed_nat_endpoint_returns_explicit_kernel_status(monkeypatch):
    from mosaic import api as api_module
    from mosaic.verification.lean_kernel import LeanKernelCheck
    monkeypatch.setattr(api_module, "verify_closed_nat_equality", lambda lhs, rhs: LeanKernelCheck(
        status="KERNEL_UNAVAILABLE",
        lhs_sha256="a" * 64,
        rhs_sha256="b" * 64,
        explanation="Lean was not found; no formal verification was performed.",
    ))
    response = client.post("/v1/verify/lean/closed-nat-equality", json={
        "lhs": "2 + 3", "rhs": "5"
    })
    assert response.status_code == 200
    assert response.json()["status"] == "KERNEL_UNAVAILABLE"


def test_lean_closed_nat_endpoint_rejects_unexpected_fields():
    response = client.post("/v1/verify/lean/closed-nat-equality", json={
        "lhs": "2 + 3", "rhs": "5", "lean_source": "sorry"
    })
    assert response.status_code == 422
