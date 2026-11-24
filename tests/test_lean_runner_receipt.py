import hashlib

import pytest
from pydantic import ValidationError

from mosaic.verification.evidence_envelope import EvidenceEventOutcome
from mosaic.verification.lean_runner_receipt import LeanRunnerReceipt


KEY = b"mosaic-test-runner-secret-material-32-bytes!"


def receipt(**overrides):
    values = dict(
        receipt_id="receipt-1",
        runner_id="ci-lean-runner",
        request_sha256=hashlib.sha256(b"request").hexdigest(),
        artifact_sha256=hashlib.sha256(b"candidate").hexdigest(),
        proof_artifact_sha256=hashlib.sha256(b"proof source").hexdigest(),
        checker_id="lean.kernel.linear_int_identity.v1",
        kernel_version="Lean version 4.test",
        outcome=EvidenceEventOutcome.PASSED,
        signing_key=KEY,
    )
    values.update(overrides)
    return LeanRunnerReceipt.issue(**values)


def test_signed_receipt_authenticates_and_maps_to_kernel_event():
    signed = receipt()
    assert signed.verify(KEY)
    event = signed.to_evidence_event(event_id="event-1", signing_key=KEY)
    assert event.kind.value == "FORMAL_KERNEL_CHECK"
    assert event.outcome == EvidenceEventOutcome.PASSED
    assert event.artifact_sha256 == signed.artifact_sha256
    assert event.proof_artifact_sha256 == signed.proof_artifact_sha256
    assert event.kernel_id == "Lean"


def test_wrong_key_cannot_authenticate_or_emit_event():
    signed = receipt()
    assert not signed.verify(b"x" * 40)
    with pytest.raises(ValueError, match="authentication failed"):
        signed.to_evidence_event(event_id="event-1", signing_key=b"x" * 40)


def test_tampered_receipt_is_rejected():
    signed = receipt()
    tampered = signed.model_copy(update={"outcome": EvidenceEventOutcome.FAILED})
    assert not tampered.verify(KEY)
    with pytest.raises(ValueError, match="authentication failed"):
        tampered.to_evidence_event(event_id="event-1", signing_key=KEY)


def test_only_completed_kernel_outcomes_can_be_signed():
    with pytest.raises(ValueError, match="completed pass or failure"):
        receipt(outcome=EvidenceEventOutcome.INCONCLUSIVE)


@pytest.mark.parametrize("key", [b"short", "not-bytes"])
def test_signing_key_must_be_bytes_of_sufficient_length(key):
    with pytest.raises(ValueError, match="at least 32 bytes"):
        receipt(signing_key=key)


def test_receipt_rejects_malformed_hashes():
    with pytest.raises(ValidationError):
        receipt(artifact_sha256="not-a-digest")
