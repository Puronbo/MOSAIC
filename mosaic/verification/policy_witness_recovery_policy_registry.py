"""Signed, versioned recovery-policy registry with checkpoint-based rollback detection."""
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
from mosaic.verification.policy_witness_recovery_governance import PolicyWitnessRecoveryPolicy


class SignedPolicyWitnessRecoveryPolicyEntry(BaseModel):
    """One append-only signed recovery-policy publication."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["mosaic.policy-witness-recovery-policy-entry.v1"] = "mosaic.policy-witness-recovery-policy-entry.v1"
    registry_id: str = Field(min_length=1, max_length=200)
    sequence: int = Field(ge=0)
    previous_entry_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    policy: PolicyWitnessRecoveryPolicy
    published_at_utc: str = Field(min_length=20, max_length=40)
    publisher_key_id: str = Field(min_length=1, max_length=160)
    signature_b64: str = Field(min_length=1, max_length=128)

    @classmethod
    def sign(cls, *, registry_id: str, sequence: int, previous_entry_sha256: str | None,
             policy: PolicyWitnessRecoveryPolicy, published_at_utc: str,
             publisher_key_id: str, private_key: bytes) -> "SignedPolicyWitnessRecoveryPolicyEntry":
        if not isinstance(private_key, bytes) or len(private_key) != 32 or not policy.valid():
            raise ValueError("a valid recovery policy and 32-byte Ed25519 key are required")
        payload = {
            "schema_version": "mosaic.policy-witness-recovery-policy-entry.v1",
            "registry_id": registry_id, "sequence": sequence,
            "previous_entry_sha256": previous_entry_sha256,
            "policy": policy.model_dump(mode="json"),
            "published_at_utc": _canonical_timestamp(published_at_utc),
            "publisher_key_id": publisher_key_id,
        }
        signature = Ed25519PrivateKey.from_private_bytes(private_key).sign(_canonical(payload))
        return cls(**payload, signature_b64=base64.b64encode(signature).decode("ascii"))

    def verify(self, keyring: dict[str, PolicyPublisherKey]) -> bool:
        record = keyring.get(self.publisher_key_id) if isinstance(keyring, dict) else None
        if (record is None or not self.policy.valid()
                or not record.permits(self.publisher_key_id, self.published_at_utc)):
            return False
        try:
            if _canonical_timestamp(self.published_at_utc) != self.published_at_utc:
                return False
            public = record.public_key()
            signature = base64.b64decode(self.signature_b64, validate=True)
            if public is None or len(signature) != 64:
                return False
            Ed25519PublicKey.from_public_bytes(public).verify(
                signature, _canonical(self.model_dump(mode="json", exclude={"signature_b64"})))
            return True
        except (ValueError, TypeError, InvalidSignature):
            return False

    def digest(self) -> str:
        return hashlib.sha256(_canonical(self.model_dump(mode="json"))).hexdigest()


class SignedPolicyWitnessRecoveryPolicyCheckpoint(BaseModel):
    """Separately persisted signed head used to detect valid-prefix rollback."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["mosaic.policy-witness-recovery-policy-checkpoint.v1"] = "mosaic.policy-witness-recovery-policy-checkpoint.v1"
    registry_id: str = Field(min_length=1, max_length=200)
    sequence: int = Field(ge=0)
    entry_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    issued_at_utc: str = Field(min_length=20, max_length=40)
    signer_key_id: str = Field(min_length=1, max_length=160)
    signature_b64: str = Field(min_length=1, max_length=128)

    @classmethod
    def sign(cls, *, entry: SignedPolicyWitnessRecoveryPolicyEntry,
             issued_at_utc: str, signer_key_id: str, private_key: bytes
             ) -> "SignedPolicyWitnessRecoveryPolicyCheckpoint":
        if not isinstance(private_key, bytes) or len(private_key) != 32:
            raise ValueError("Ed25519 private key must be exactly 32 raw bytes")
        payload = {
            "schema_version": "mosaic.policy-witness-recovery-policy-checkpoint.v1",
            "registry_id": entry.registry_id, "sequence": entry.sequence,
            "entry_sha256": entry.digest(),
            "issued_at_utc": _canonical_timestamp(issued_at_utc),
            "signer_key_id": signer_key_id,
        }
        signature = Ed25519PrivateKey.from_private_bytes(private_key).sign(_canonical(payload))
        return cls(**payload, signature_b64=base64.b64encode(signature).decode("ascii"))

    def verify(self, keyring: dict[str, PolicyPublisherKey]) -> bool:
        record = keyring.get(self.signer_key_id) if isinstance(keyring, dict) else None
        if record is None or not record.permits(self.signer_key_id, self.issued_at_utc):
            return False
        try:
            if _canonical_timestamp(self.issued_at_utc) != self.issued_at_utc:
                return False
            public = record.public_key()
            signature = base64.b64decode(self.signature_b64, validate=True)
            if public is None or len(signature) != 64:
                return False
            Ed25519PublicKey.from_public_bytes(public).verify(
                signature, _canonical(self.model_dump(mode="json", exclude={"signature_b64"})))
            return True
        except (ValueError, TypeError, InvalidSignature):
            return False


def verify_policy_witness_recovery_policy_registry(
    entries: list[SignedPolicyWitnessRecoveryPolicyEntry], *,
    publisher_keyring: dict[str, PolicyPublisherKey],
    trusted_checkpoint: SignedPolicyWitnessRecoveryPolicyCheckpoint,
    checkpoint_keyring: dict[str, PolicyPublisherKey] | None = None,
) -> bool:
    """Verify the entire chain and require its head to match a trusted signed checkpoint.

    The checkpoint must be retained/distributed independently. A signature or
    hash chain alone cannot establish freshness or prevent rollback.
    """
    if not isinstance(entries, list) or not entries or not isinstance(trusted_checkpoint, SignedPolicyWitnessRecoveryPolicyCheckpoint):
        return False
    registry_id = entries[0].registry_id
    previous = None
    for sequence, entry in enumerate(entries):
        if (not isinstance(entry, SignedPolicyWitnessRecoveryPolicyEntry)
                or entry.registry_id != registry_id or entry.sequence != sequence
                or entry.previous_entry_sha256 != previous or not entry.verify(publisher_keyring)):
            return False
        previous = entry.digest()
    ring = checkpoint_keyring if checkpoint_keyring is not None else publisher_keyring
    return (
        trusted_checkpoint.verify(ring)
        and trusted_checkpoint.registry_id == registry_id
        and trusted_checkpoint.sequence == entries[-1].sequence
        and trusted_checkpoint.entry_sha256 == entries[-1].digest()
    )
