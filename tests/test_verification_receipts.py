import pytest

from mosaic.core.orchestration import ReviewFinding, ReviewFindingKind, ReviewObligation
from mosaic.core.requests import MathRequest
from mosaic.core.types import Operation
from mosaic.verification.obligations import obligations_for_request, request_fingerprint
from mosaic.verification.review_checkers import ReviewCheckerReceipt
from mosaic.verification.lean_obligations import LeanIdentityVerification
from mosaic.verification.receipts import (
    VerificationReceipt, load_receipt, serialize_receipt,
    validate_receipt_for_replay,
)


def _request():
    return MathRequest(operation=Operation.VERIFY_IDENTITY, expression="2 + 3", rhs="5")


def _obligation(request):
    finding = ReviewFinding(
        finding_id="finding-1",
        kind=ReviewFindingKind.EVIDENCE_REQUIRED,
        statement=obligations_for_request(request)[0].statement,
        request_sha256=request_fingerprint(request),
        checker_id="mosaic.lean.request_identity.v1",
    )
    return ReviewObligation(
        obligation_id="review-obligation-1",
        source_task_id="critic-1",
        source_agent_id="agent-critic",
        finding=finding,
    )


def _issued():
    request = _request()
    obligation = _obligation(request)
    checked = ReviewCheckerReceipt(
        obligation_id=obligation.obligation_id,
        request_sha256=request_fingerprint(request),
        checker_id="mosaic.lean.request_identity.v1",
        status="FORMALLY_VERIFIED",
        checker_result=LeanIdentityVerification(
            status="FORMALLY_VERIFIED",
            explanation="Lean kernel accepted the exact request identity.",
        ),
        explanation="Exact request-bound checker succeeded.",
    )
    return request, obligation, VerificationReceipt.issue(obligation, checked)


def test_receipt_is_deterministic_and_replayable_without_checker_execution():
    request, obligation, receipt = _issued()
    second = VerificationReceipt.issue(
        obligation,
        ReviewCheckerReceipt(
            obligation_id=receipt.obligation_id,
            request_sha256=receipt.request_sha256,
            checker_id=receipt.checker_id,
            status=receipt.status,
            checker_result=LeanIdentityVerification(
                status="FORMALLY_VERIFIED",
                explanation="Lean kernel accepted the exact request identity.",
            ),
            explanation=receipt.explanation,
        ),
    )
    assert second.receipt_sha256 == receipt.receipt_sha256
    assert validate_receipt_for_replay(receipt, request) == receipt


def test_receipt_rejects_tampered_explanation():
    request, _, receipt = _issued()
    tampered = receipt.model_copy(update={"explanation": "altered after checking"})
    with pytest.raises(ValueError, match="integrity"):
        validate_receipt_for_replay(tampered, request)


def test_receipt_rejects_tampered_checker_result():
    request, _, receipt = _issued()
    altered_result = dict(receipt.checker_result)
    altered_result["explanation"] = "forged result"
    tampered = receipt.model_copy(update={"checker_result": altered_result})
    with pytest.raises(ValueError, match="integrity"):
        validate_receipt_for_replay(tampered, request)


def test_receipt_rejects_different_request():
    _, _, receipt = _issued()
    other = MathRequest(operation=Operation.VERIFY_IDENTITY, expression="2 + 3", rhs="6")
    with pytest.raises(ValueError, match="different or stale"):
        validate_receipt_for_replay(receipt, other)


def test_receipt_issue_rejects_mismatched_obligation():
    request, obligation, _ = _issued()
    other = obligation.model_copy(update={"obligation_id": "other"})
    checked = ReviewCheckerReceipt(
        obligation_id=obligation.obligation_id,
        request_sha256=request_fingerprint(request),
        checker_id="mosaic.lean.request_identity.v1",
        status="UNSUPPORTED",
        explanation="not supported",
    )
    with pytest.raises(ValueError, match="does not match"):
        VerificationReceipt.issue(other, checked)


def test_receipt_model_rejects_unknown_checker_and_inconsistent_status():
    _, _, receipt = _issued()
    values = receipt.model_dump()
    values["checker_id"] = "shell.execute"
    with pytest.raises(ValueError, match="allow-listed"):
        VerificationReceipt(**values)
    values = receipt.model_dump()
    values["status"] = "REJECTED"
    with pytest.raises(ValueError, match="does not match"):
        VerificationReceipt(**values)


def test_non_success_outcome_can_be_recorded_without_promotion():
    request = _request()
    obligation = _obligation(request)
    checked = ReviewCheckerReceipt(
        obligation_id=obligation.obligation_id,
        request_sha256=request_fingerprint(request),
        checker_id="mosaic.lean.request_identity.v1",
        status="UNSUPPORTED",
        explanation="unsupported",
    )
    receipt = VerificationReceipt.issue(obligation, checked)
    assert validate_receipt_for_replay(receipt, request).status == "UNSUPPORTED"


def test_receipt_survives_json_round_trip_and_replay():
    request, _, receipt = _issued()
    restored = load_receipt(serialize_receipt(receipt))
    assert restored == receipt
    assert validate_receipt_for_replay(restored, request) == receipt


def test_receipt_loader_rejects_oversized_and_malformed_records():
    with pytest.raises(ValueError, match="maximum serialized size"):
        load_receipt(b"x" * 65_537)
    with pytest.raises(Exception):
        load_receipt("{not-json}")
