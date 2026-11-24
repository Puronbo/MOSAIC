import hashlib

import pytest

from mosaic.core.requests import MathRequest
from mosaic.core.types import Operation
from mosaic.verification.evidence_envelope import EvidenceEventOutcome
from mosaic.verification.lean_linear import LeanLinearCheck
from mosaic.verification.lean_transformations import (
    LeanTransformationObligation,
    LeanTransformationVerification,
)
from mosaic.verification.lean_runner_signature import (
    SignedLeanAttestation,
    generate_ed25519_keypair,
    sign_transformation_result,
    verify_evidence_event_signature,
    replay_attested_proof_source,
)
from mosaic.verification.obligations import request_fingerprint


def make_verified_result():
    proof_source = "import Lean\\ntheorem mosaic_certificate (x : Int) : x + 1 = 1 + x := by omega\\n"
    request = MathRequest(operation=Operation.EXPAND, expression="x + 1")
    result = "1 + x"
    artifact_hash = hashlib.sha256(result.encode()).hexdigest()
    check = LeanLinearCheck(
        status="FORMALLY_VERIFIED",
        lhs_sha256=hashlib.sha256(request.expression.encode()).hexdigest(),
        rhs_sha256=artifact_hash,
        lean_version="Lean version 4.test",
        proof_source_sha256=hashlib.sha256(proof_source.encode()).hexdigest(),
        proof_source=proof_source,
        variables=("x",),
        explanation="accepted by configured Lean runner",
    )
    obligation = LeanTransformationObligation(
        obligation_id="obligation-signed-1",
        request_sha256=request_fingerprint(request),
        candidate_sha256=artifact_hash,
        operation="expand",
        checker_id=check.checker_id,
        proposition="x + 1 = 1 + x",
        variables=("x",),
    )
    verification = LeanTransformationVerification(
        status="FORMALLY_VERIFIED",
        obligation=obligation,
        check=check,
        explanation="completed Lean result",
    )
    return request, result, verification


def test_ed25519_signed_attestation_verifies_with_public_key_only():
    private, public = generate_ed25519_keypair()
    request, result, verification = make_verified_result()
    signed = sign_transformation_result(
        verification, request, result, receipt_id="signed-1",
        runner_id="isolated-lean-runner", key_id="ci-key-2026-01",
        private_key=private,
    )
    assert signed.verify(public)
    event = signed.to_evidence_event(event_id="signed-event-1", public_key=public)
    assert event.outcome == EvidenceEventOutcome.PASSED
    assert event.runner_signature_algorithm == "Ed25519"
    assert event.runner_proof_source == verification.check.proof_source
    assert hashlib.sha256(event.runner_proof_source.encode()).hexdigest() == event.proof_artifact_sha256
    assert event.runner_key_id == "ci-key-2026-01"
    assert verify_evidence_event_signature(
        event, {"ci-key-2026-01": public}
    )
    assert not verify_evidence_event_signature(event, {})


def test_ed25519_attestation_tampering_and_wrong_key_are_rejected():
    private, public = generate_ed25519_keypair()
    _, _, verification = make_verified_result()
    request, result, _ = make_verified_result()
    signed = sign_transformation_result(
        verification, request, result, receipt_id="signed-2",
        runner_id="runner", key_id="key-1", private_key=private,
    )
    other_private, other_public = generate_ed25519_keypair()
    assert not signed.verify(other_public)
    tampered = signed.model_copy(update={"outcome": EvidenceEventOutcome.FAILED})
    assert not tampered.verify(public)
    with pytest.raises(ValueError, match="signature is invalid"):
        tampered.to_evidence_event(event_id="event-tampered", public_key=public)


def test_ed25519_signer_rejects_candidate_mismatch():
    private, _ = generate_ed25519_keypair()
    request, result, verification = make_verified_result()
    with pytest.raises(ValueError, match="candidate"):
        sign_transformation_result(
            verification, request, "altered candidate", receipt_id="bad",
            runner_id="runner", key_id="key-1", private_key=private,
        )


def test_ed25519_signer_rejects_incomplete_runner_result():
    private, _ = generate_ed25519_keypair()
    request, result, _ = make_verified_result()
    incomplete = LeanTransformationVerification(
        status="KERNEL_UNAVAILABLE", explanation="Lean is not installed"
    )
    with pytest.raises(ValueError, match="no completed Lean"):
        sign_transformation_result(
            incomplete, request, result, receipt_id="none",
            runner_id="runner", key_id="key-1", private_key=private,
        )


@pytest.mark.parametrize("bad_key", [b"short", "not-bytes"])
def test_ed25519_signer_requires_raw_private_key_bytes(bad_key):
    with pytest.raises(ValueError, match="exactly 32 raw bytes"):
        SignedLeanAttestation.sign(
            receipt_id="r", runner_id="runner", key_id="key",
            request_sha256=hashlib.sha256(b"r").hexdigest(),
            artifact_sha256=hashlib.sha256(b"a").hexdigest(),
            proof_artifact_sha256=hashlib.sha256(b"p").hexdigest(),
            proof_source="proof",
            checker_id="checker", kernel_version="Lean 4",
            outcome=EvidenceEventOutcome.PASSED, private_key=bad_key,
        )

def test_isolated_runner_entrypoint_executes_verifier_then_signs(monkeypatch):
    from mosaic.verification import lean_transformations
    from mosaic.verification.lean_runner_signature import run_and_sign_transformation

    private, public = generate_ed25519_keypair()
    request, result, verification = make_verified_result()
    calls = []

    def fake_runner(actual_request, actual_result):
        calls.append((actual_request, actual_result))
        return verification

    monkeypatch.setattr(
        lean_transformations, "verify_request_transformation_with_lean", fake_runner
    )
    returned, attestation = run_and_sign_transformation(
        request, result, receipt_id="runner-entrypoint",
        runner_id="isolated-runner", key_id="trusted-key",
        private_key=private,
    )
    assert returned is verification
    assert calls == [(request, result)]
    assert attestation.verify(public)



def test_signed_attestation_rejects_proof_source_tampering():
    private, public = generate_ed25519_keypair()
    request, result, verification = make_verified_result()
    signed = sign_transformation_result(
        verification, request, result, receipt_id="proof-source-tamper",
        runner_id="runner", key_id="key", private_key=private,
    )
    altered = signed.model_copy(update={"proof_source": signed.proof_source + "-- altered"})
    assert not altered.verify(public)


def test_evidence_event_rejects_proof_source_digest_mismatch():
    from mosaic.verification.evidence_envelope import EvidenceEvent

    private, public = generate_ed25519_keypair()
    request, result, verification = make_verified_result()
    signed = sign_transformation_result(
        verification, request, result, receipt_id="proof-source-event",
        runner_id="runner", key_id="key", private_key=private,
    )
    event = signed.to_evidence_event(event_id="proof-event", public_key=public)
    with pytest.raises(ValueError, match="proof source"):
        EvidenceEvent.model_validate({
            **event.model_dump(),
            "runner_proof_source": "forged source",
        })


def test_replay_uses_exact_signed_source_and_public_key(monkeypatch, tmp_path):
    from mosaic.verification import lean_runner_signature

    private, public = generate_ed25519_keypair()
    request, result, verification = make_verified_result()
    signed = sign_transformation_result(
        verification, request, result, receipt_id="replay-test",
        runner_id="runner", key_id="key", private_key=private,
    )
    observed = {}

    class Completed:
        returncode = 0

    def fake_run(command, **kwargs):
        observed["command"] = command
        observed["source"] = Path(command[-1]).read_text(encoding="utf-8")
        observed["cwd"] = kwargs["cwd"]
        return Completed()

    import shutil
    from pathlib import Path

    monkeypatch.setattr(shutil, "which", lambda _: "/usr/bin/lake")
    monkeypatch.setattr(lean_runner_signature.subprocess, "run", fake_run)
    assert replay_attested_proof_source(signed, public) is True
    assert observed["source"] == signed.proof_source
    assert observed["command"][:3] == ["/usr/bin/lake", "env", "lean"]
