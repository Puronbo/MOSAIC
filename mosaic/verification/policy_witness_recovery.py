"""Signed operator authorization for recovering a quarantined policy witness."""
from __future__ import annotations

import base64
import hashlib
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field

from mosaic.verification.lean_runner_signature import _canonical
from mosaic.verification.policy_governance import PolicyPublisherKey
from mosaic.verification.policy_registry import _canonical_timestamp


class SignedPolicyWitnessRecoveryAuthorization(BaseModel):
    """Operator-signed approval bound to one snapshot and one incident history."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["1.0"] = "1.0"
    log_id: str = Field(min_length=1, max_length=200)
    selected_snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    incident_history_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reason: str = Field(min_length=20, max_length=2000)
    operator_key_id: str = Field(min_length=1, max_length=160)
    approved_at_utc: str = Field(min_length=20, max_length=40)
    signature_b64: str = Field(min_length=1, max_length=128)

    @classmethod
    def sign(
        cls, *, log_id: str, selected_snapshot_sha256: str,
        incident_history_sha256: str, evidence_sha256: str, reason: str,
        operator_key_id: str, approved_at_utc: str, private_key: bytes,
    ) -> "SignedPolicyWitnessRecoveryAuthorization":
        if not isinstance(private_key, bytes) or len(private_key) != 32:
            raise ValueError("Ed25519 private key must be exactly 32 raw bytes")
        payload = {
            "schema_version": "1.0", "log_id": log_id,
            "selected_snapshot_sha256": selected_snapshot_sha256,
            "incident_history_sha256": incident_history_sha256,
            "evidence_sha256": evidence_sha256, "reason": reason,
            "operator_key_id": operator_key_id,
            "approved_at_utc": _canonical_timestamp(approved_at_utc),
        }
        signature = Ed25519PrivateKey.from_private_bytes(private_key).sign(_canonical(payload))
        return cls(**payload, signature_b64=base64.b64encode(signature).decode("ascii"))

    def digest(self) -> str:
        return hashlib.sha256(_canonical(self.model_dump(mode="json"))).hexdigest()

    def verify(self, keyring: dict[str, PolicyPublisherKey]) -> bool:
        record = keyring.get(self.operator_key_id) if isinstance(keyring, dict) else None
        if (record is None or not record.permits(self.operator_key_id, self.approved_at_utc)):
            return False
        try:
            if _canonical_timestamp(self.approved_at_utc) != self.approved_at_utc:
                return False
            key = record.public_key()
            signature = base64.b64decode(self.signature_b64, validate=True)
            if key is None or len(signature) != 64:
                return False
            payload = self.model_dump(mode="json", exclude={"signature_b64"})
            Ed25519PublicKey.from_public_bytes(key).verify(signature, _canonical(payload))
            return True
        except (ValueError, TypeError, InvalidSignature):
            return False
