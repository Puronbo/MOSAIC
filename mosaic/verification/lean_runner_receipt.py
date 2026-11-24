"""Authenticated receipts for a separately trusted MOSAIC Lean runner.

Receipts use HMAC-SHA256 with a deployment-managed shared secret. This gives
message authentication between parties that protect the same secret; it is
not a public-key signature, and any verifier holding the secret can also sign.
Keep the signing secret inside the runner service and do not expose it to
untrusted callers or model-facing processes.
"""
import hashlib
import hmac
import json

from pydantic import BaseModel, ConfigDict, Field

from mosaic.verification.evidence_envelope import (
    EvidenceEvent,
    EvidenceEventKind,
    EvidenceEventOutcome,
)
from mosaic.verification.obligations import request_fingerprint


class LeanRunnerReceipt(BaseModel):
    """A MAC-authenticated statement emitted by a trusted Lean runner."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "1.0"
    receipt_id: str = Field(min_length=1, max_length=120)
    runner_id: str = Field(min_length=1, max_length=160)
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    proof_artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    checker_id: str = Field(min_length=1, max_length=160)
    kernel_id: str = "Lean"
    kernel_version: str = Field(min_length=1, max_length=160)
    outcome: EvidenceEventOutcome
    mac_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def issue(
        cls,
        *,
        receipt_id: str,
        runner_id: str,
        request_sha256: str,
        artifact_sha256: str,
        proof_artifact_sha256: str,
        checker_id: str,
        kernel_version: str,
        outcome: EvidenceEventOutcome,
        signing_key: bytes,
    ) -> "LeanRunnerReceipt":
        if outcome not in {EvidenceEventOutcome.PASSED, EvidenceEventOutcome.FAILED}:
            raise ValueError("runner receipts require a completed pass or failure")
        if not isinstance(signing_key, bytes) or len(signing_key) < 32:
            raise ValueError("runner signing key must contain at least 32 bytes")
        unsigned = {
            "schema_version": "1.0",
            "receipt_id": receipt_id,
            "runner_id": runner_id,
            "request_sha256": request_sha256,
            "artifact_sha256": artifact_sha256,
            "proof_artifact_sha256": proof_artifact_sha256,
            "checker_id": checker_id,
            "kernel_id": "Lean",
            "kernel_version": kernel_version,
            "outcome": outcome.value,
        }
        mac = hmac.new(signing_key, _canonical(unsigned), hashlib.sha256).hexdigest()
        return cls(**unsigned, mac_sha256=mac)

    def verify(self, signing_key: bytes) -> bool:
        if not isinstance(signing_key, bytes) or len(signing_key) < 32:
            return False
        expected = hmac.new(signing_key, _canonical(_unsigned(self)), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, self.mac_sha256)

    def to_evidence_event(self, *, event_id: str, signing_key: bytes) -> EvidenceEvent:
        if not self.verify(signing_key):
            raise ValueError("Lean runner receipt authentication failed")
        return EvidenceEvent(
            event_id=event_id,
            kind=EvidenceEventKind.FORMAL_KERNEL_CHECK,
            outcome=self.outcome,
            artifact_sha256=self.artifact_sha256,
            method=f"Authenticated Lean runner receipt {self.receipt_id}",
            tool_id=self.checker_id,
            tool_version=self.kernel_version,
            kernel_id=self.kernel_id,
            kernel_version=self.kernel_version,
            proof_artifact_sha256=self.proof_artifact_sha256,
            runner_id=self.runner_id,
            runner_receipt_id=self.receipt_id,
            runner_request_sha256=self.request_sha256,
            runner_mac_sha256=self.mac_sha256,
        )


def verify_evidence_event_receipt(event: EvidenceEvent, signing_key: bytes) -> bool:
    """Verify the HMAC retained on an event converted from a runner receipt."""
    if (
        event.kind != EvidenceEventKind.FORMAL_KERNEL_CHECK
        or not event.runner_id
        or not event.runner_receipt_id
        or not event.runner_request_sha256
        or not event.runner_mac_sha256
        or not event.kernel_id
        or not event.kernel_version
        or not event.proof_artifact_sha256
    ):
        return False
    try:
        receipt = LeanRunnerReceipt(
            receipt_id=event.runner_receipt_id,
            runner_id=event.runner_id,
            request_sha256=event.runner_request_sha256,
            artifact_sha256=event.artifact_sha256,
            proof_artifact_sha256=event.proof_artifact_sha256,
            checker_id=event.tool_id,
            kernel_version=event.kernel_version,
            outcome=event.outcome,
            mac_sha256=event.runner_mac_sha256,
        )
    except ValueError:
        return False
    return receipt.verify(signing_key)


def _unsigned(receipt: LeanRunnerReceipt) -> dict:
    return receipt.model_dump(mode="json", exclude={"mac_sha256"})


def _canonical(payload: dict) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def receipt_from_transformation_result(
    verification,
    request,
    result: str,
    *,
    receipt_id: str,
    runner_id: str,
    signing_key: bytes,
) -> LeanRunnerReceipt:
    """Create a runner receipt from the result of the actual Lean invocation.

    This function must execute only inside the trusted runner boundary. It
    binds the receipt to the exact request, candidate bytes, proof-source
    digest, checker identity, and reported Lean version.
    """
    import hashlib

    check = verification.check
    obligation = verification.obligation
    if (
        check is None
        or obligation is None
        or verification.status not in {"FORMALLY_VERIFIED", "REJECTED"}
        or check.status != verification.status
        or not check.proof_source_sha256
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
    return LeanRunnerReceipt.issue(
        receipt_id=receipt_id,
        runner_id=runner_id,
        request_sha256=request_hash,
        artifact_sha256=artifact_hash,
        proof_artifact_sha256=check.proof_source_sha256,
        checker_id=check.checker_id,
        kernel_version=version,
        outcome=(
            EvidenceEventOutcome.PASSED
            if verification.status == "FORMALLY_VERIFIED"
            else EvidenceEventOutcome.FAILED
        ),
        signing_key=signing_key,
    )
