"""Integrity-checked, request-bound verification receipts.

Receipts make checker outcomes replayable without rerunning providers. Their
SHA-256 digest detects modification; it is not a signature, proof, or substitute
for re-running a trusted proof kernel when policy requires fresh verification.
"""
import hashlib
import hmac
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mosaic.core.orchestration import ReviewObligation
from mosaic.core.requests import MathRequest
from mosaic.verification.obligations import request_fingerprint
from mosaic.verification.lean_obligations import LeanIdentityVerification
from mosaic.verification.review_checkers import ReviewCheckerReceipt

RECEIPT_SCHEMA_VERSION = 1
MAX_RECEIPT_BYTES = 65_536
_ALLOWED_CHECKERS = frozenset({"mosaic.lean.request_identity.v1"})


class VerificationReceipt(BaseModel):
    """Immutable record of one allow-listed checker outcome and its provenance."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = RECEIPT_SCHEMA_VERSION
    obligation_id: str = Field(min_length=1, max_length=160)
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    checker_id: str = Field(min_length=1, max_length=120)
    source_task_id: str = Field(min_length=1, max_length=80)
    source_agent_id: str = Field(min_length=1, max_length=120)
    finding_id: str = Field(min_length=1, max_length=80)
    status: Literal[
        "FORMALLY_VERIFIED", "REJECTED", "UNSUPPORTED",
        "KERNEL_UNAVAILABLE", "KERNEL_ERROR", "INVALID_CERTIFICATE",
    ]
    checker_result: LeanIdentityVerification | None = None
    explanation: str = Field(max_length=4000)
    receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_result_consistency(self):
        if self.checker_id not in _ALLOWED_CHECKERS:
            raise ValueError("receipt checker is not allow-listed")
        if self.checker_result is not None:
            if self.checker_result.get("status") != self.status:
                raise ValueError("receipt status does not match nested checker result")
        elif self.status in {"FORMALLY_VERIFIED", "REJECTED", "KERNEL_UNAVAILABLE", "KERNEL_ERROR"}:
            raise ValueError("checker outcome requires its structured result")
        return self

    @classmethod
    def issue(cls, obligation: ReviewObligation, checker_receipt: ReviewCheckerReceipt):
        """Create a deterministic integrity digest over the complete receipt."""
        if checker_receipt.obligation_id != obligation.obligation_id:
            raise ValueError("checker receipt does not match review obligation")
        if checker_receipt.request_sha256 != obligation.finding.request_sha256:
            raise ValueError("checker receipt does not match finding request binding")
        if checker_receipt.checker_id != obligation.finding.checker_id:
            raise ValueError("checker receipt does not match finding checker binding")
        result = checker_receipt.checker_result
        provisional = cls(
            obligation_id=obligation.obligation_id,
            request_sha256=checker_receipt.request_sha256,
            checker_id=checker_receipt.checker_id,
            source_task_id=obligation.source_task_id,
            source_agent_id=obligation.source_agent_id,
            finding_id=obligation.finding.finding_id,
            status=checker_receipt.status,
            checker_result=result,
            explanation=checker_receipt.explanation,
            receipt_sha256="0" * 64,
        )
        return provisional.model_copy(update={"receipt_sha256": _receipt_digest(provisional)})


def _canonical_receipt_payload(receipt: VerificationReceipt) -> bytes:
    payload = receipt.model_dump(mode="json", exclude={"receipt_sha256"})
    return json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _receipt_digest(receipt: VerificationReceipt) -> str:
    payload = _canonical_receipt_payload(receipt)
    if len(payload) > MAX_RECEIPT_BYTES:
        raise ValueError("receipt exceeds the maximum serialized size")
    return hashlib.sha256(payload).hexdigest()


def serialize_receipt(receipt: VerificationReceipt) -> bytes:
    """Return the canonical, bounded JSON representation for durable storage."""
    payload = receipt.model_dump(mode="json")
    encoded = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    if len(encoded) > MAX_RECEIPT_BYTES:
        raise ValueError("receipt exceeds the maximum serialized size")
    return encoded


def load_receipt(data: bytes | str) -> VerificationReceipt:
    """Parse one bounded receipt record; integrity is checked during replay."""
    if isinstance(data, str):
        encoded = data.encode("utf-8")
    elif isinstance(data, bytes):
        encoded = data
    else:
        raise TypeError("receipt data must be bytes or text")
    if len(encoded) > MAX_RECEIPT_BYTES:
        raise ValueError("receipt exceeds the maximum serialized size")
    return VerificationReceipt.model_validate_json(encoded)


def validate_receipt_for_replay(
    receipt: VerificationReceipt, request: MathRequest
) -> VerificationReceipt:
    """Validate integrity and request binding before replaying a stored result.

    This function deliberately does not invoke a checker. A valid receipt proves
    only that the recorded data matches its digest and request binding.
    """
    expected_digest = _receipt_digest(receipt)
    if not hmac.compare_digest(receipt.receipt_sha256, expected_digest):
        raise ValueError("receipt integrity check failed")
    if receipt.request_sha256 != request_fingerprint(request):
        raise ValueError("receipt belongs to a different or stale request")
    if receipt.checker_id not in _ALLOWED_CHECKERS:
        raise ValueError("receipt checker is not allow-listed")
    return receipt
