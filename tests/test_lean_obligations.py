from mosaic.core.requests import MathRequest
from mosaic.core.types import Operation
from mosaic.verification.lean_obligations import verify_request_identity_with_lean


def test_lean_identity_obligation_is_derived_from_exact_request(monkeypatch):
    captured = {}

    def fake_check(lhs, rhs):
        captured.update(lhs=lhs, rhs=rhs)
        from mosaic.verification.lean_kernel import LeanKernelCheck
        return LeanKernelCheck(
            status="FORMALLY_VERIFIED",
            lhs_sha256="a" * 64,
            rhs_sha256="b" * 64,
            lean_version="Lean version test",
            explanation="accepted",
        )

    monkeypatch.setattr(
        "mosaic.verification.lean_obligations.verify_closed_nat_equality",
        fake_check,
    )
    request = MathRequest(
        operation=Operation.VERIFY_IDENTITY,
        expression="2 + 3",
        rhs="5",
    )
    result = verify_request_identity_with_lean(request)
    assert result.status == "FORMALLY_VERIFIED"
    assert captured == {"lhs": "2 + 3", "rhs": "5"}
    assert result.obligation.request_sha256
    assert result.obligation.assumptions == ()
    assert result.obligation.proposition == "(2 + 3) = (5)"


def test_lean_identity_obligation_rejects_non_identity_request_without_running_lean(monkeypatch):
    def should_not_run(*args, **kwargs):
        raise AssertionError("Lean must not run for an unsupported operation")

    monkeypatch.setattr(
        "mosaic.verification.lean_obligations.verify_closed_nat_equality",
        should_not_run,
    )
    request = MathRequest(
        operation=Operation.SIMPLIFY,
        expression="2 + 3",
    )
    result = verify_request_identity_with_lean(request)
    assert result.status == "UNSUPPORTED"
    assert result.obligation is None
    assert result.check is None


def test_lean_identity_obligation_requires_rhs(monkeypatch):
    request = MathRequest(
        operation=Operation.VERIFY_IDENTITY,
        expression="2 + 3",
    )
    result = verify_request_identity_with_lean(request)
    assert result.status == "UNSUPPORTED"


def test_request_identity_routes_symbolic_linear_claim_to_lean(monkeypatch):
    from mosaic.verification.lean_linear import LeanLinearCheck

    captured = {}

    def fake_linear(lhs, rhs):
        captured.update(lhs=lhs, rhs=rhs)
        return LeanLinearCheck(
            status="FORMALLY_VERIFIED",
            lhs_sha256="a" * 64,
            rhs_sha256="b" * 64,
            proof_source_sha256="c" * 64,
            variables=("x", "y"),
            explanation="accepted",
        )

    monkeypatch.setattr(
        "mosaic.verification.lean_linear.verify_linear_int_identity",
        fake_linear,
    )
    request = MathRequest(
        operation=Operation.VERIFY_IDENTITY,
        expression="x + y",
        rhs="y + x",
    )
    result = verify_request_identity_with_lean(request)
    assert result.status == "FORMALLY_VERIFIED"
    assert captured == {"lhs": "x + y", "rhs": "y + x"}
    assert result.obligation.checker_id == "lean.kernel.linear_int_identity.v1"
    assert result.obligation.variables == ("x", "y")
    assert result.obligation.proposition == "∀ (x : Int) (y : Int), (x + y) = (y + x)"
    assert result.obligation.assumptions == ()
    assert result.check.proof_source_sha256 == "c" * 64
