import hashlib

import pytest
from pydantic import ValidationError

from mosaic.verification.evidence_envelope import EvidenceEventOutcome
from mosaic.verification.lean_runner_receipt import (
    LeanRunnerReceipt, verify_evidence_event_receipt,
)


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
    assert event.runner_id == signed.runner_id
    assert event.runner_mac_sha256 == signed.mac_sha256
    assert verify_evidence_event_receipt(event, KEY)
    tampered_event = event.model_copy(update={"artifact_sha256": hashlib.sha256(b"other").hexdigest()})
    assert not verify_evidence_event_receipt(tampered_event, KEY)


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

def test_receipt_factory_binds_completed_request_bound_lean_result():
    from mosaic.core.requests import MathRequest
    from mosaic.core.types import Operation
    from mosaic.verification.lean_linear import LeanLinearCheck
    from mosaic.verification.lean_transformations import (
        LeanTransformationObligation, LeanTransformationVerification,
    )
    from mosaic.verification.lean_runner_receipt import receipt_from_transformation_result
    from mosaic.verification.obligations import request_fingerprint

    request = MathRequest(operation=Operation.EXPAND, expression="x + 1")
    result = "1 + x"
    artifact_hash = hashlib.sha256(result.encode()).hexdigest()
    check = LeanLinearCheck(
        status="FORMALLY_VERIFIED",
        lhs_sha256=hashlib.sha256(request.expression.encode()).hexdigest(),
        rhs_sha256=artifact_hash,
        lean_version="Lean version 4.test",
        proof_source_sha256=hashlib.sha256(b"generated proof source").hexdigest(),
        variables=("x",),
        explanation="accepted",
    )
    obligation = LeanTransformationObligation(
        obligation_id="obligation-1",
        request_sha256=request_fingerprint(request),
        candidate_sha256=artifact_hash,
        operation="expand",
        checker_id=check.checker_id,
        proposition="x + 1 = 1 + x",
        variables=("x",),
    )
    verification = LeanTransformationVerification(
        status="FORMALLY_VERIFIED", obligation=obligation, check=check,
        explanation="accepted",
    )
    signed = receipt_from_transformation_result(
        verification, request, result, receipt_id="receipt-factory",
        runner_id="trusted-ci", signing_key=KEY,
    )
    assert signed.verify(KEY)
    assert signed.artifact_sha256 == artifact_hash
    assert signed.request_sha256 == request_fingerprint(request)
    assert signed.outcome == EvidenceEventOutcome.PASSED

    with pytest.raises(ValueError, match="candidate"):
        receipt_from_transformation_result(
            verification, request, "different result", receipt_id="receipt-bad",
            runner_id="trusted-ci", signing_key=KEY,
        )

