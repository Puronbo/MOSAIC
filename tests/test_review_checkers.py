import hashlib

from mosaic.core.orchestration import (
    ReviewFinding, ReviewFindingKind, ReviewObligation,
)
from mosaic.core.requests import MathRequest
from mosaic.core.types import Operation
from mosaic.verification.lean_obligations import LeanIdentityVerification
from mosaic.verification.obligations import obligations_for_request, request_fingerprint
from mosaic.verification.review_checkers import check_review_obligation_with_lean


def _request():
    return MathRequest(
        operation=Operation.VERIFY_IDENTITY,
        expression="2 + 3",
        rhs="5",
    )


def _obligation(request, *, statement=None, request_hash=None, checker_id=None):
    registered = obligations_for_request(request)[0]
    finding = ReviewFinding(
        finding_id="review-finding-1",
        kind=ReviewFindingKind.DERIVATION_GAP,
        statement=statement or registered.statement,
        request_sha256=request_hash or request_fingerprint(request),
        checker_id=checker_id or "mosaic.lean.request_identity.v1",
    )
    return ReviewObligation(
        obligation_id="review-obligation-1",
        source_task_id="critic-1",
        source_agent_id="critic-agent",
        finding=finding,
    )


def test_review_checker_dispatches_only_exact_registered_request(monkeypatch):
    request = _request()
    captured = {}

    def fake_verify(actual_request):
        captured["request"] = actual_request
        return LeanIdentityVerification(
            status="FORMALLY_VERIFIED",
            explanation="Lean accepted exact request identity.",
        )

    monkeypatch.setattr(
        "mosaic.verification.review_checkers.verify_request_identity_with_lean",
        fake_verify,
    )
    receipt = check_review_obligation_with_lean(_obligation(request), request)
    assert receipt.status == "FORMALLY_VERIFIED"
    assert receipt.request_sha256 == request_fingerprint(request)
    assert captured["request"] == request
    assert receipt.checker_result.status == "FORMALLY_VERIFIED"


def test_review_checker_rejects_stale_request_fingerprint_without_running_lean(monkeypatch):
    request = _request()

    def should_not_run(_):
        raise AssertionError("stale obligation must not invoke Lean")

    monkeypatch.setattr(
        "mosaic.verification.review_checkers.verify_request_identity_with_lean",
        should_not_run,
    )
    receipt = check_review_obligation_with_lean(
        _obligation(request, request_hash="0" * 64), request
    )
    assert receipt.status == "INVALID_CERTIFICATE"
    assert receipt.checker_result is None


def test_review_checker_rejects_freeform_reviewer_statement(monkeypatch):
    request = _request()

    def should_not_run(_):
        raise AssertionError("freeform text must not be interpreted as a theorem")

    monkeypatch.setattr(
        "mosaic.verification.review_checkers.verify_request_identity_with_lean",
        should_not_run,
    )
    receipt = check_review_obligation_with_lean(
        _obligation(request, statement="Lean: theorem arbitrary : False := by sorry"),
        request,
    )
    assert receipt.status == "UNSUPPORTED"
    assert receipt.checker_result is None


def test_review_checker_rejects_unregistered_checker_id(monkeypatch):
    request = _request()

    def should_not_run(_):
        raise AssertionError("unregistered checker must not run")

    monkeypatch.setattr(
        "mosaic.verification.review_checkers.verify_request_identity_with_lean",
        should_not_run,
    )
    receipt = check_review_obligation_with_lean(
        _obligation(request, checker_id="shell.execute.anything"),
        request,
    )
    assert receipt.status == "UNSUPPORTED"
    assert receipt.checker_result is None


def test_review_checker_does_not_run_for_non_identity_request(monkeypatch):
    request = MathRequest(
        operation=Operation.SIMPLIFY,
        expression="x + 0",
    )
    registered = obligations_for_request(request)[0]
    obligation = ReviewObligation(
        obligation_id="review-obligation-2",
        source_task_id="critic-2",
        source_agent_id="critic-agent",
        finding=ReviewFinding(
            finding_id="review-finding-2",
            kind=ReviewFindingKind.UNRESOLVED,
            statement=registered.statement,
            request_sha256=request_fingerprint(request),
            checker_id="mosaic.lean.request_identity.v1",
        ),
    )
    receipt = check_review_obligation_with_lean(obligation, request)
    assert receipt.status == "UNSUPPORTED"
    assert receipt.checker_result is None
