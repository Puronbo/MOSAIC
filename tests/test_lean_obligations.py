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
