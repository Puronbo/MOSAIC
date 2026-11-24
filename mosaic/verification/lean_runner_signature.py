"""Public-key signed attestations for isolated MOSAIC Lean runners.

The runner signs with an Ed25519 private key. Envelope consumers verify with
the public key only; they cannot mint receipts from that public key.
Key provisioning, rotation, revocation, and runner isolation remain deployment
responsibilities.
"""
import base64
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from mosaic.verification.evidence_envelope import (
    EvidenceEvent,
    EvidenceEventKind,
    EvidenceEventOutcome,
)
from mosaic.verification.obligations import request_fingerprint


class SignedLeanAttestation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "1.0"
    receipt_id: str = Field(min_length=1, max_length=120)
    runner_id: str = Field(min_length=1, max_length=160)
    key_id: str = Field(min_length=1, max_length=160)
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    proof_artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    proof_source: str = Field(min_length=1, max_length=10000)
    checker_id: str = Field(min_length=1, max_length=160)
    kernel_id: str = "Lean"
    kernel_version: str = Field(min_length=1, max_length=160)
    outcome: EvidenceEventOutcome
    signature_b64: str = Field(min_length=1, max_length=256)

    @classmethod
    def sign(
        cls,
        *,
        receipt_id: str,
        runner_id: str,
        key_id: str,
        request_sha256: str,
        artifact_sha256: str,
        proof_artifact_sha256: str,
        proof_source: str,
        checker_id: str,
        kernel_version: str,
        outcome: EvidenceEventOutcome,
        private_key: bytes,
    ) -> "SignedLeanAttestation":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        if outcome not in {EvidenceEventOutcome.PASSED, EvidenceEventOutcome.FAILED}:
            raise ValueError("signed attestations require a completed pass or failure")
        if not isinstance(private_key, bytes) or len(private_key) != 32:
            raise ValueError("Ed25519 private key must be exactly 32 raw bytes")
        if hashlib.sha256(proof_source.encode("utf-8")).hexdigest() != proof_artifact_sha256:
            raise ValueError("proof source does not match its SHA-256 digest")
        payload = {
            "schema_version": "1.0",
            "receipt_id": receipt_id,
            "runner_id": runner_id,
            "key_id": key_id,
            "request_sha256": request_sha256,
            "artifact_sha256": artifact_sha256,
            "proof_artifact_sha256": proof_artifact_sha256,
            "proof_source": proof_source,
            "checker_id": checker_id,
            "kernel_id": "Lean",
            "kernel_version": kernel_version,
            "outcome": outcome.value,
        }
        key = Ed25519PrivateKey.from_private_bytes(private_key)
        signature = key.sign(_canonical(payload))
        return cls(**payload, signature_b64=base64.b64encode(signature).decode("ascii"))

    def verify(self, public_key: bytes) -> bool:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        if not isinstance(public_key, bytes) or len(public_key) != 32:
            return False
        try:
            signature = base64.b64decode(self.signature_b64, validate=True)
            Ed25519PublicKey.from_public_bytes(public_key).verify(
                signature, _canonical(_unsigned(self))
            )
            return True
        except (ValueError, InvalidSignature):
            return False

    def to_evidence_event(self, *, event_id: str, public_key: bytes) -> EvidenceEvent:
        if not self.verify(public_key):
            raise ValueError("Ed25519 Lean attestation signature is invalid")
        return EvidenceEvent(
            event_id=event_id,
            kind=EvidenceEventKind.FORMAL_KERNEL_CHECK,
            outcome=self.outcome,
            artifact_sha256=self.artifact_sha256,
            method=f"Ed25519-signed Lean runner attestation {self.receipt_id}",
            tool_id=self.checker_id,
            tool_version=self.kernel_version,
            kernel_id=self.kernel_id,
            kernel_version=self.kernel_version,
            proof_artifact_sha256=self.proof_artifact_sha256,
            runner_proof_source=self.proof_source,
            runner_id=self.runner_id,
            runner_receipt_id=self.receipt_id,
            runner_request_sha256=self.request_sha256,
            runner_signature_b64=self.signature_b64,
            runner_signature_algorithm="Ed25519",
            runner_key_id=self.key_id,
        )


def verify_evidence_event_signature(event: EvidenceEvent, public_keys: dict[str, bytes]) -> bool:
    """Verify an event's signature using a key selected by its trusted key ID."""
    if (
        event.kind != EvidenceEventKind.FORMAL_KERNEL_CHECK
        or event.runner_signature_algorithm != "Ed25519"
        or not event.runner_signature_b64
        or not event.runner_key_id
        or not event.runner_id
        or not event.runner_receipt_id
        or not event.runner_request_sha256
        or not event.kernel_id
        or not event.kernel_version
        or not event.proof_artifact_sha256
        or not event.runner_proof_source
    ):
        return False
    public_key = public_keys.get(event.runner_key_id)
    if public_key is None:
        return False
    try:
        attestation = SignedLeanAttestation(
            receipt_id=event.runner_receipt_id,
            runner_id=event.runner_id,
            key_id=event.runner_key_id,
            request_sha256=event.runner_request_sha256,
            artifact_sha256=event.artifact_sha256,
            proof_artifact_sha256=event.proof_artifact_sha256,
            proof_source=event.runner_proof_source,
            checker_id=event.tool_id,
            kernel_version=event.kernel_version,
            outcome=event.outcome,
            signature_b64=event.runner_signature_b64,
        )
    except ValueError:
        return False
    return attestation.verify(public_key)


def sign_transformation_result(
    verification,
    request,
    result: str,
    *,
    receipt_id: str,
    runner_id: str,
    key_id: str,
    private_key: bytes,
) -> SignedLeanAttestation:
    """Sign only a completed request-bound result from the trusted Lean runner."""
    check = verification.check
    obligation = verification.obligation
    if (
        check is None
        or obligation is None
        or verification.status not in {"FORMALLY_VERIFIED", "REJECTED"}
        or check.status != verification.status
        or not check.proof_source_sha256
        or not check.proof_source
        or not check.lean_version
    ):
        raise ValueError("no completed Lean kernel outcome is available")
    request_hash = request_fingerprint(request)
    artifact_hash = hashlib.sha256(result.encode("utf-8")).hexdigest()
    if obligation.request_sha256 != request_hash:
        raise ValueError("Lean obligation is not bound to this request")
    if obligation.candidate_sha256 != artifact_hash:
        raise ValueError("Lean obligation is not bound to this candidate")
    if check.lhs_sha256 != hashlib.sha256(request.expression.encode("utf-8")).hexdigest():
        raise ValueError("Lean check left-hand hash does not match the request expression")
    if check.rhs_sha256 != artifact_hash:
        raise ValueError("Lean check right-hand hash does not match the candidate")
    if check.checker_id != obligation.checker_id:
        raise ValueError("Lean checker identity does not match the obligation")
    version = check.lean_version
    mathlib_revision = getattr(check, "mathlib_revision", None)
    if mathlib_revision:
        version = f"{version}; Mathlib {mathlib_revision}"
    return SignedLeanAttestation.sign(
        receipt_id=receipt_id,
        runner_id=runner_id,
        key_id=key_id,
        request_sha256=request_hash,
        artifact_sha256=artifact_hash,
        proof_artifact_sha256=check.proof_source_sha256,
        proof_source=check.proof_source,
        checker_id=check.checker_id,
        kernel_version=version,
        outcome=(
            EvidenceEventOutcome.PASSED
            if verification.status == "FORMALLY_VERIFIED"
            else EvidenceEventOutcome.FAILED
        ),
        private_key=private_key,
    )


def generate_ed25519_keypair() -> tuple[bytes, bytes]:
    """Generate raw 32-byte (private, public) Ed25519 keys for provisioning."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private = Ed25519PrivateKey.generate()
    private_bytes = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_bytes, public_bytes


def _unsigned(attestation: SignedLeanAttestation) -> dict:
    return attestation.model_dump(mode="json", exclude={"signature_b64"})


def _canonical(payload: dict) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")

def run_and_sign_transformation(
    request,
    result: str,
    *,
    receipt_id: str,
    runner_id: str,
    key_id: str,
    private_key: bytes,
) -> tuple[object, SignedLeanAttestation]:
    """Execute MOSAIC's request-bound Lean verifier and sign its completed result.

    Deploy this function only inside the isolated runner process that owns the
    Ed25519 private key. The caller receives the verification result and its
    signed attestation; consumers need only the corresponding public key.
    """
    from mosaic.verification.lean_transformations import (
        verify_request_transformation_with_lean,
    )

    verification = verify_request_transformation_with_lean(request, result)
    attestation = sign_transformation_result(
        verification,
        request,
        result,
        receipt_id=receipt_id,
        runner_id=runner_id,
        key_id=key_id,
        private_key=private_key,
    )
    return verification, attestation



def replay_attested_proof_source(
    attestation: SignedLeanAttestation,
    public_key: bytes,
    *,
    timeout_seconds: float = 30.0,
    lake_executable: str = "lake",
) -> bool | None:
    """Re-run the exact signed proof source in the pinned Mathlib Lake project.

    Returns True when the observed Lean exit status matches the signed outcome,
    False when it does not, and None when the replay environment is unavailable
    or execution times out. A successful replay independently checks the
    retained source in the current environment; it does not attest the original
    runner host.
    """
    import shutil

    if not attestation.verify(public_key):
        return False
    if not math_is_finite_positive(timeout_seconds):
        return None
    executable = shutil.which(lake_executable)
    project_dir = Path(__file__).resolve().parents[2] / "formal" / "polynomial"
    if executable is None or not (project_dir / "lakefile.lean").is_file():
        return None
    try:
        with tempfile.TemporaryDirectory(prefix="mosaic-proof-replay-") as directory:
            source_path = Path(directory) / "AttestedCertificate.lean"
            source_path.write_text(attestation.proof_source, encoding="utf-8")
            completed = subprocess.run(
                [executable, "env", "lean", str(source_path)],
                cwd=project_dir,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        expected_pass = attestation.outcome == EvidenceEventOutcome.PASSED
        return (completed.returncode == 0) == expected_pass
    except (OSError, subprocess.TimeoutExpired):
        return None


def math_is_finite_positive(value: float) -> bool:
    import math

    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(value)
        and 0 < value <= 120
    )
