import hashlib

from mosaic.core.requests import MathRequest
from mosaic.core.types import Operation
from mosaic.verification.lean_linear import LeanLinearCheck
from mosaic.verification.lean_transformations import verify_request_transformation_with_lean


def test_transformation_obligation_binds_exact_request_and_candidate(monkeypatch):
    def fake_check(lhs, rhs):
        assert (lhs, rhs) == ("2*x + x", "3*x")
        return LeanLinearCheck(
            status="FORMALLY_VERIFIED",
            lhs_sha256="a" * 64,
            rhs_sha256="b" * 64,
            proof_source_sha256="c" * 64,
            variables=("x",),
            explanation="accepted",
        )

    monkeypatch.setattr(
        "mosaic.verification.lean_transformations.verify_linear_int_identity",
        fake_check,
    )
    request = MathRequest(
        operation=Operation.SIMPLIFY,
        expression="2*x + x",
    )
    result = verify_request_transformation_with_lean(request, "3*x")
    assert result.status == "FORMALLY_VERIFIED"
    assert result.obligation.operation == "simplify"
    assert result.obligation.request_sha256
    assert result.obligation.candidate_sha256 == hashlib.sha256(b"3*x").hexdigest()
    assert result.obligation.variables == ("x",)
    assert result.obligation.proposition == "∀ (x : Int), (2*x + x) = (3*x)"
    assert result.obligation.assumptions == ()


def test_transformation_obligation_rejects_unrelated_operations():
    request = MathRequest(
        operation=Operation.DIFFERENTIATE,
        expression="x",
    )
    result = verify_request_transformation_with_lean(request, "1")
    assert result.status == "UNSUPPORTED"
    assert result.obligation is None
    assert result.check is None


def test_transformation_obligation_keeps_unsupported_domain_syntax_out():
    request = MathRequest(
        operation=Operation.SIMPLIFY,
        expression="x / 2",
    )
    result = verify_request_transformation_with_lean(request, "x")
    assert result.status == "UNSUPPORTED"
    assert result.obligation is None
    assert result.check.status == "UNSUPPORTED"
