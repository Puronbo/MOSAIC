import pytest

from mosaic.core.orchestration import ReviewFinding, ReviewFindingKind, ReviewObligation
from mosaic.core.requests import MathRequest
from mosaic.core.types import Operation
from mosaic.verification.obligations import obligations_for_request, request_fingerprint
from mosaic.verification.review_checkers import ReviewCheckerReceipt, check_review_obligation_with_lean
from mosaic.verification.lean_obligations import LeanIdentityObligation, LeanIdentityVerification
from mosaic.verification.receipts import (
    AuthenticatedReceipt, ReceiptStore, VerificationReceipt, load_authenticated_receipt, load_receipt, serialize_authenticated_receipt, serialize_receipt,
    validate_receipt_for_replay,
)


def _request():
    return MathRequest(operation=Operation.VERIFY_IDENTITY, expression="2 + 3", rhs="5")



def _verified_result(request):
    fingerprint = request_fingerprint(request)
    return LeanIdentityVerification(
        status="FORMALLY_VERIFIED",
        obligation=LeanIdentityObligation(
            obligation_id=f"request:{fingerprint[:16]}:lean-identity",
            request_sha256=fingerprint,
            checker_id="lean.kernel.closed_nat_equality.v1",
            proposition=f"({request.expression}) = ({request.rhs})",
        ),
        explanation="Lean kernel accepted the exact request identity.",
    )


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
        checker_result=_verified_result(request),
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
            checker_result=_verified_result(request),
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
    altered_result = receipt.checker_result.model_copy(update={"explanation": "forged result"})
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


def test_file_store_persists_and_replays_receipt_after_reconstruction(tmp_path):
    request, _, receipt = _issued()
    store = ReceiptStore(tmp_path / "receipts")
    path = store.save(receipt)
    assert path.exists()
    reconstructed_store = ReceiptStore(tmp_path / "receipts")
    restored = reconstructed_store.load(receipt.receipt_sha256, request)
    assert restored == receipt


def test_file_store_refuses_tampered_disk_record(tmp_path):
    request, _, receipt = _issued()
    store = ReceiptStore(tmp_path / "receipts")
    path = store.save(receipt)
    path.write_bytes(path.read_bytes().replace(b"Exact request", b"Forged request"))
    with pytest.raises(Exception):
        store.load(receipt.receipt_sha256, request)


def test_file_store_rejects_path_injection_identifier(tmp_path):
    store = ReceiptStore(tmp_path / "receipts")
    with pytest.raises(ValueError, match="identifier"):
        store.load("../outside", _request())


def test_end_to_end_request_checker_receipt_persist_and_replay(tmp_path, monkeypatch):
    from mosaic.verification.lean_obligations import LeanIdentityVerification

    request = _request()
    obligation = _obligation(request)

    def fake_lean(actual_request):
        assert actual_request == request
        return _verified_result(actual_request)

    monkeypatch.setattr(
        "mosaic.verification.review_checkers.verify_request_identity_with_lean",
        fake_lean,
    )
    checker_result = check_review_obligation_with_lean(obligation, request)
    receipt = VerificationReceipt.issue(obligation, checker_result)
    store = ReceiptStore(tmp_path / "receipts")
    store.save(receipt)

    replayed = ReceiptStore(tmp_path / "receipts").load(
        receipt.receipt_sha256, request
    )
    assert replayed.status == "FORMALLY_VERIFIED"
    assert replayed.request_sha256 == request_fingerprint(request)
    assert replayed.source_task_id == obligation.source_task_id
    assert replayed.finding_id == obligation.finding.finding_id


def test_receipt_rejects_nested_lean_obligation_for_another_request():
    _, _, receipt = _issued()
    altered_obligation = receipt.checker_result.obligation.model_copy(
        update={"request_sha256": "0" * 64}
    )
    altered_result = receipt.checker_result.model_copy(
        update={"obligation": altered_obligation}
    )
    values = receipt.model_dump()
    values["checker_result"] = altered_result
    with pytest.raises(Exception, match="different request"):
        VerificationReceipt(**values)


def test_receipt_rejects_formal_status_without_lean_obligation():
    _, _, receipt = _issued()
    values = receipt.model_dump()
    values["checker_result"] = LeanIdentityVerification(
        status="FORMALLY_VERIFIED",
        explanation="forged status without a bound obligation",
    )
    with pytest.raises(Exception, match="requires its request-bound"):
        VerificationReceipt(**values)


def test_authenticated_receipt_round_trip_and_key_validation():
    request, _, receipt = _issued()
    key = b"k" * 32
    sealed = AuthenticatedReceipt.seal(receipt, key)
    restored = load_authenticated_receipt(serialize_authenticated_receipt(sealed))
    assert restored.verify(key, request) == receipt
    with pytest.raises(ValueError, match="authentication failed"):
        restored.verify(b"z" * 32, request)
    with pytest.raises(ValueError, match="at least 32 bytes"):
        AuthenticatedReceipt.seal(receipt, b"short")


def test_authenticated_receipt_rejects_modified_tag_and_receipt():
    request, _, receipt = _issued()
    key = b"s" * 32
    sealed = AuthenticatedReceipt.seal(receipt, key)
    altered_tag = sealed.model_copy(update={"hmac_sha256": "0" * 64})
    with pytest.raises(ValueError, match="authentication failed"):
        altered_tag.verify(key, request)
    altered_receipt = receipt.model_copy(update={"explanation": "tampered"})
    envelope = sealed.model_copy(update={"receipt": altered_receipt})
    with pytest.raises(ValueError, match="integrity"):
        envelope.verify(key, request)
