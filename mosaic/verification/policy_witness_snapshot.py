"""Portable signed snapshots of independent policy-witness state."""
from __future__ import annotations

import base64
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

from mosaic.verification.lean_runner_signature import _canonical
from mosaic.verification.policy_governance import PolicyPublisherKey
from mosaic.verification.policy_registry import _canonical_timestamp
from mosaic.verification.policy_transparency import PolicyRegistryCheckpoint


class PolicyWitnessSnapshotIncident(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    sequence: int = Field(ge=0)
    retained_checkpoint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    conflicting_checkpoint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reason: str = Field(min_length=1, max_length=2000)
    observed_at_utc: str = Field(min_length=20, max_length=40)


class SignedPolicyWitnessSnapshot(BaseModel):
    """Signed snapshot; trust still depends on an independently provisioned key."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["1.0"] = "1.0"
    log_id: str = Field(min_length=1, max_length=200)
    checkpoint: PolicyRegistryCheckpoint
    quarantined: bool
    incidents: tuple[PolicyWitnessSnapshotIncident, ...] = ()
    witness_key_id: str = Field(min_length=1, max_length=160)
    exported_at_utc: str = Field(min_length=20, max_length=40)
    signature_b64: str = Field(min_length=1, max_length=128)

    @classmethod
    def sign(
        cls, *, log_id: str, checkpoint: PolicyRegistryCheckpoint,
        quarantined: bool, incidents: list[dict], witness_key_id: str,
        exported_at_utc: str, private_key: bytes,
    ) -> "SignedPolicyWitnessSnapshot":
        if not isinstance(private_key, bytes) or len(private_key) != 32:
            raise ValueError("Ed25519 private key must be exactly 32 raw bytes")
        canonical_time = _canonical_timestamp(exported_at_utc)
        normalized = [PolicyWitnessSnapshotIncident.model_validate(item)
                      for item in incidents]
        payload = {
            "schema_version": "1.0", "log_id": log_id,
            "checkpoint": checkpoint.model_dump(mode="json"),
            "quarantined": bool(quarantined),
            "incidents": [item.model_dump(mode="json") for item in normalized],
            "witness_key_id": witness_key_id, "exported_at_utc": canonical_time,
        }
        signature = Ed25519PrivateKey.from_private_bytes(private_key).sign(_canonical(payload))
        return cls(**payload, signature_b64=base64.b64encode(signature).decode("ascii"))

    def verify(self, keyring: dict[str, PolicyPublisherKey]) -> bool:
        record = keyring.get(self.witness_key_id) if isinstance(keyring, dict) else None
        if (record is None or not record.permits(self.witness_key_id, self.exported_at_utc)
                or self.log_id != self.checkpoint.log_id):
            return False
        try:
            if _canonical_timestamp(self.exported_at_utc) != self.exported_at_utc:
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
