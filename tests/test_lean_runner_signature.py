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
    verify_attested_environment_manifest,
    verify_lean_proof_receipt_bundle,
    LeanTrustedKey,
    verify_with_keyring,
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


def test_ed25519_attestation_binds_environment_manifest_and_ci_identity():
    private, public = generate_ed25519_keypair()
    request, result, verification = make_verified_result()
    signed = sign_transformation_result(
        verification, request, result, receipt_id="environment-bound",
        runner_id="github-hosted-lean-runner", key_id="ci-key",
        private_key=private,
        environment_manifest_sha256="a" * 64,
        source_commit="b" * 40,
        workflow_run_id="45299999999",
        lean_toolchain="leanprover/lean4:v4.36.0",
        mathlib_revision="c" * 40,
    )
    assert signed.verify(public)
    event = signed.to_evidence_event(event_id="environment-event", public_key=public)
    assert event.runner_environment_manifest_sha256 == "a" * 64
    assert event.runner_source_commit == "b" * 40
    assert event.runner_workflow_run_id == "45299999999"
    assert event.runner_lean_toolchain == "leanprover/lean4:v4.36.0"
    assert event.runner_mathlib_revision == "c" * 40
    assert verify_evidence_event_signature(event, {"ci-key": public})
    altered = event.model_copy(update={"runner_source_commit": "d" * 40})
    assert not verify_evidence_event_signature(altered, {"ci-key": public})


def test_ed25519_environment_binding_must_be_complete():
    private, _ = generate_ed25519_keypair()
    request, result, verification = make_verified_result()
    with pytest.raises(ValueError, match="complete set"):
        sign_transformation_result(
            verification, request, result, receipt_id="partial-environment",
            runner_id="runner", key_id="key", private_key=private,
            environment_manifest_sha256="a" * 64,
        )


def test_environment_manifest_verification_requires_exact_signed_bytes():
    import json

    private, public = generate_ed25519_keypair()
    request, result, verification = make_verified_result()
    manifest = {
        "source": {"commit": "b" * 40},
        "execution": {"run_id": "12345"},
        "environment": {
            "lean_toolchain": "leanprover/lean4:v4.36.0",
            "mathlib_revision": "c" * 40,
        },
    }
    manifest_bytes = json.dumps(manifest, sort_keys=True).encode()
    signed = sign_transformation_result(
        verification, request, result, receipt_id="manifest-verification",
        runner_id="runner", key_id="key", private_key=private,
        environment_manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        source_commit="b" * 40, workflow_run_id="12345",
        lean_toolchain="leanprover/lean4:v4.36.0",
        mathlib_revision="c" * 40,
    )
    assert verify_attested_environment_manifest(signed, public, manifest_bytes)
    assert not verify_attested_environment_manifest(signed, public, manifest_bytes + b" ")
    altered = {**manifest, "source": {"commit": "d" * 40}}
    assert not verify_attested_environment_manifest(
        signed, public, json.dumps(altered, sort_keys=True).encode()
    )


def test_portable_receipt_bundle_verifies_all_external_bindings():
    import base64
    import json

    private, public = generate_ed25519_keypair()
    request, result, verification = make_verified_result()
    manifest = {
        "source": {"commit": "b" * 40},
        "execution": {"run_id": "12345"},
        "environment": {
            "lean_toolchain": "leanprover/lean4:v4.36.0",
            "mathlib_revision": "c" * 40,
        },
    }
    manifest_bytes = json.dumps(manifest, sort_keys=True).encode()
    manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
    signed = sign_transformation_result(
        verification, request, result, receipt_id="portable-receipt",
        runner_id="runner", key_id="key", private_key=private,
        environment_manifest_sha256=manifest_digest,
        source_commit="b" * 40, workflow_run_id="12345",
        lean_toolchain="leanprover/lean4:v4.36.0",
        mathlib_revision="c" * 40,
    )
    bundle = {
        "schema_version": "mosaic.signed-lean-proof-receipt.v1",
        "attestation": signed.model_dump(mode="json"),
        "public_key_b64": base64.b64encode(public).decode("ascii"),
        "environment_manifest_sha256": manifest_digest,
        "replay": {"exact_signed_source_replayed": True},
    }
    assert verify_lean_proof_receipt_bundle(
        bundle, manifest=manifest_bytes, trusted_public_key=public,
        request_sha256=request_fingerprint(request), candidate=result.encode(),
    )
    assert not verify_lean_proof_receipt_bundle(
        bundle, manifest=manifest_bytes, trusted_public_key=public,
        request_sha256=request_fingerprint(request), candidate=b"altered",
    )
    assert not verify_lean_proof_receipt_bundle(
        bundle, manifest=manifest_bytes, trusted_public_key=public,
        request_sha256="0" * 64, candidate=result.encode(),
    )
    assert not verify_lean_proof_receipt_bundle(
        bundle, manifest=manifest_bytes + b" ", trusted_public_key=public,
        request_sha256=request_fingerprint(request), candidate=result.encode(),
    )
    other_public = generate_ed25519_keypair()[1]
    assert not verify_lean_proof_receipt_bundle(
        bundle, manifest=manifest_bytes, trusted_public_key=other_public,
        request_sha256=request_fingerprint(request), candidate=result.encode(),
    )


def test_fixed_v1_signature_conformance_vector():
    import base64
    import json
    from pathlib import Path
    from mosaic.verification.lean_runner_signature import _canonical

    vector = json.loads(
        (Path(__file__).parent / "fixtures" / "lean_receipt_v1_vector.json").read_text()
    )
    attestation = SignedLeanAttestation.model_validate(vector["attestation"])
    public_key = base64.b64decode(vector["public_key_b64"], validate=True)
    private_key = base64.b64decode(vector["private_key_b64"], validate=True)
    assert attestation.verify(public_key)
    assert hashlib.sha256(_canonical(attestation.model_dump(mode="json", exclude={"signature_b64"}))).hexdigest() == vector["canonical_sha256"]
    regenerated = SignedLeanAttestation.sign(
        **attestation.model_dump(mode="python", exclude={"signature_b64", "schema_version", "kernel_id"}),
        private_key=private_key,
    )
    assert regenerated.signature_b64 == attestation.signature_b64


def test_trusted_keyring_rotation_and_revocation():
    import base64

    private, public = generate_ed25519_keypair()
    request, result, verification = make_verified_result()
    attestation = sign_transformation_result(
        verification, request, result, receipt_id="keyring-test",
        runner_id="runner", key_id="rotated-key", private_key=private,
    )
    encoded = base64.b64encode(public).decode("ascii")
    active = {"rotated-key": LeanTrustedKey(
        key_id="rotated-key", public_key_b64=encoded, status="active"
    )}
    retired = {"rotated-key": LeanTrustedKey(
        key_id="rotated-key", public_key_b64=encoded, status="retired"
    )}
    revoked = {"rotated-key": LeanTrustedKey(
        key_id="rotated-key", public_key_b64=encoded, status="revoked"
    )}
    assert verify_with_keyring(attestation, active)
    assert verify_with_keyring(attestation, retired)
    assert not verify_with_keyring(attestation, revoked)
    assert not verify_with_keyring(attestation, {})
    wrong_id = {"other-key": LeanTrustedKey(
        key_id="other-key", public_key_b64=encoded, status="active"
    )}
    assert not verify_with_keyring(attestation, wrong_id)


def test_attestation_rejects_unknown_schema_version_and_bad_signature_length():
    import base64

    private, public = generate_ed25519_keypair()
    request, result, verification = make_verified_result()
    attestation = sign_transformation_result(
        verification, request, result, receipt_id="strict-schema",
        runner_id="runner", key_id="key", private_key=private,
    )
    with pytest.raises(ValueError):
        SignedLeanAttestation.model_validate({**attestation.model_dump(), "schema_version": "2.0"})
    assert not attestation.model_copy(update={
        "signature_b64": base64.b64encode(b"short").decode("ascii")
    }).verify(public)


def test_strict_json_rejects_duplicate_keys():
    from mosaic.verification.lean_runner_signature import _strict_json_loads

    with pytest.raises(ValueError, match="duplicate JSON object key"):
        _strict_json_loads('{"schema_version":"1.0","schema_version":"2.0"}')
    with pytest.raises(ValueError, match="duplicate JSON object key"):
        _strict_json_loads('{"outer":{"value":1,"value":2}}')


def test_manifest_verifier_rejects_duplicate_environment_fields():
    private, public = generate_ed25519_keypair()
    request, result, verification = make_verified_result()
    manifest = (
        '{"source":{"commit":"' + "b" * 40 + '"},'
        '"execution":{"run_id":"12345"},'
        '"environment":{"lean_toolchain":"leanprover/lean4:v4.36.0",'
        '"lean_toolchain":"attacker-toolchain",'
        '"mathlib_revision":"' + "c" * 40 + '"}}'
    )
    raw = manifest.encode()
    signed = sign_transformation_result(
        verification, request, result, receipt_id="duplicate-manifest",
        runner_id="runner", key_id="key", private_key=private,
        environment_manifest_sha256=hashlib.sha256(raw).hexdigest(),
        source_commit="b" * 40, workflow_run_id="12345",
        lean_toolchain="leanprover/lean4:v4.36.0",
        mathlib_revision="c" * 40,
    )
    assert not verify_attested_environment_manifest(signed, public, raw)


def test_strict_json_rejects_nonstandard_constants_and_lone_surrogates():
    from mosaic.verification.lean_runner_signature import _strict_json_loads

    with pytest.raises(ValueError, match="non-standard JSON constant"):
        _strict_json_loads('{"value":NaN}')
    with pytest.raises(ValueError, match="Unicode scalar"):
        _strict_json_loads('{"value":"\\ud800"}')


def test_unicode_v1_conformance_vector_matches_python_canonical_bytes():
    import base64
    import json
    from pathlib import Path
    from mosaic.verification.lean_runner_signature import _canonical

    vector = json.loads(
        (Path(__file__).parent / "fixtures" / "lean_receipt_v1_unicode_vector.json").read_text()
    )
    attestation = SignedLeanAttestation.model_validate(vector["attestation"])
    canonical = _canonical(attestation.model_dump(mode="json", exclude={"signature_b64"}))
    assert hashlib.sha256(canonical).hexdigest() == vector["canonical_sha256"]
    assert attestation.verify(base64.b64decode(vector["public_key_b64"], validate=True))


def test_portable_bundle_conformance_vector_verifies_and_binds_all_inputs():
    import base64
    import json
    from pathlib import Path
    from mosaic.core.requests import MathRequest
    from mosaic.verification.lean_runner_signature import verify_lean_proof_receipt_bundle
    from mosaic.verification.obligations import request_fingerprint

    vector = json.loads(
        (Path(__file__).parent / "fixtures" / "lean_receipt_v1_bundle_vector.json").read_text()
    )
    manifest = base64.b64decode(vector["manifest_b64"], validate=True)
    candidate = base64.b64decode(vector["candidate_b64"], validate=True)
    public_key = base64.b64decode(vector["public_key_b64"], validate=True)
    request = MathRequest.model_validate(vector["request"])
    arguments = {
        "manifest": manifest,
        "trusted_public_key": public_key,
        "request_sha256": request_fingerprint(request),
        "candidate": candidate,
    }
    assert verify_lean_proof_receipt_bundle(vector["receipt"], **arguments)
    assert not verify_lean_proof_receipt_bundle(vector["receipt"], **{**arguments, "candidate": candidate + b" "})
    assert not verify_lean_proof_receipt_bundle(vector["receipt"], **{**arguments, "manifest": manifest + b" "})
    assert not verify_lean_proof_receipt_bundle(vector["receipt"], **{**arguments, "request_sha256": "0" * 64})
    changed = {**vector["receipt"], "replay": {"exact_signed_source_replayed": False}}
    assert not verify_lean_proof_receipt_bundle(changed, **arguments)
