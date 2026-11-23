from fastapi.testclient import TestClient

from mosaic.api import app
from mosaic.verification.lean_polynomial import LeanPolynomialCheck

client = TestClient(app)


def test_polynomial_identity_endpoint_returns_checker_provenance(monkeypatch):
    from mosaic import api as api_module

    def fake_check(lhs, rhs):
        assert lhs == "(x + 1)^2"
        assert rhs == "x^2 + 2*x + 1"
        return LeanPolynomialCheck(
            status="KERNEL_UNAVAILABLE",
            lhs_sha256="a" * 64,
            rhs_sha256="b" * 64,
            proof_source_sha256="c" * 64,
            variables=("x",),
            explanation="Mathlib unavailable",
        )

    monkeypatch.setattr(api_module, "verify_polynomial_int_identity", fake_check)
    response = client.post("/v1/verify/lean/polynomial-int-identity", json={
        "lhs": "(x + 1)^2",
        "rhs": "x^2 + 2*x + 1",
    })
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "KERNEL_UNAVAILABLE"
    assert body["checker_id"] == "lean.kernel.polynomial_int_identity.v1"
    assert body["mathlib_revision"] == "fc4f59e577feb1a4956671bc04ac18aaaf8cd842"
    assert body["proof_source_sha256"] == "c" * 64
    assert body["variables"] == ["x"]


def test_polynomial_identity_endpoint_rejects_unknown_fields():
    response = client.post("/v1/verify/lean/polynomial-int-identity", json={
        "lhs": "x^2",
        "rhs": "x*x",
        "lean_source": "by trivial",
    })
    assert response.status_code == 422
