"""Signed, externally anchored snapshots of operator-key lifecycle state."""
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


class SignedOperatorLifecycleCheckpoint(BaseModel):
    """Authority-signed, sequence-linked snapshot of operator key records.

    The authority key must be distributed independently. The expected checkpoint
    digest/sequence must be retained outside the database to detect rollback.
    """
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["1.0"] = "1.0"
    registry_id: str = Field(min_length=1, max_length=200)
    sequence: int = Field(ge=0)
    previous_checkpoint_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    issued_at_utc: str = Field(min_length=20, max_length=40)
    authority_key_id: str = Field(min_length=1, max_length=160)
    operator_keys: tuple[PolicyPublisherKey, ...]
    signature_b64: str = Field(min_length=1, max_length=128)

    @classmethod
    def sign(cls, *, registry_id: str, sequence: int,
             previous_checkpoint_sha256: str | None, issued_at_utc: str,
             authority_key_id: str, operator_keys: list[PolicyPublisherKey],
             private_key: bytes) -> "SignedOperatorLifecycleCheckpoint":
        if not isinstance(private_key, bytes) or len(private_key) != 32:
            raise ValueError("Ed25519 private key must be exactly 32 raw bytes")
        records = sorted(operator_keys, key=lambda item: item.key_id)
        if len({item.key_id for item in records}) != len(records):
            raise ValueError("operator key IDs must be unique")
        payload = {
            "schema_version": "1.0", "registry_id": registry_id,
            "sequence": sequence, "previous_checkpoint_sha256": previous_checkpoint_sha256,
            "issued_at_utc": _canonical_timestamp(issued_at_utc),
            "authority_key_id": authority_key_id,
            "operator_keys": [item.model_dump(mode="json") for item in records],
        }
        signature = Ed25519PrivateKey.from_private_bytes(private_key).sign(_canonical(payload))
        return cls(**payload, signature_b64=base64.b64encode(signature).decode("ascii"))

    def digest(self) -> str:
        return hashlib.sha256(_canonical(self.model_dump(mode="json"))).hexdigest()


def verify_operator_lifecycle_checkpoint(
    checkpoint: SignedOperatorLifecycleCheckpoint, *,
    authority_keyring: dict[str, PolicyPublisherKey],
    expected_registry_id: str,
    expected_sequence: int | None = None,
    expected_previous_sha256: str | None = None,
    expected_checkpoint_sha256: str | None = None,
    authorization_time_utc: str | None = None,
) -> bool:
    """Verify authority signature, chain position, canonical time, and key snapshot.

    Supplying an independently retained expected digest detects rollback or
    replacement. Authorization time is explicit and must not precede issuance.
    """
    if not isinstance(checkpoint, SignedOperatorLifecycleCheckpoint):
        return False
    authority = authority_keyring.get(checkpoint.authority_key_id) if isinstance(authority_keyring, dict) else None
    if (authority is None or checkpoint.registry_id != expected_registry_id
            or not authority.permits(checkpoint.authority_key_id, checkpoint.issued_at_utc)
            or (expected_sequence is not None and checkpoint.sequence != expected_sequence)
            or (expected_previous_sha256 is not None
                and checkpoint.previous_checkpoint_sha256 != expected_previous_sha256)
            or (checkpoint.sequence == 0 and checkpoint.previous_checkpoint_sha256 is not None)
            or (checkpoint.sequence > 0 and checkpoint.previous_checkpoint_sha256 is None)
            or (expected_checkpoint_sha256 is not None
                and checkpoint.digest() != expected_checkpoint_sha256)):
        return False
    try:
        if _canonical_timestamp(checkpoint.issued_at_utc) != checkpoint.issued_at_utc:
            return False
        if authorization_time_utc is not None:
            if _canonical_timestamp(authorization_time_utc) != authorization_time_utc:
                return False
            if authorization_time_utc < checkpoint.issued_at_utc:
                return False
        ids = [item.key_id for item in checkpoint.operator_keys]
        if ids != sorted(ids) or len(ids) != len(set(ids)):
            return False
        for item in checkpoint.operator_keys:
            if (not item.public_key() or not item.permits(item.key_id, item.activated_at_utc)
                    or (item.revoked_at_utc is not None
                        and not item.permits(item.key_id, item.activated_at_utc))):
                return False
        signature = base64.b64decode(checkpoint.signature_b64, validate=True)
        if len(signature) != 64:
            return False
        payload = checkpoint.model_dump(mode="json", exclude={"signature_b64"})
        Ed25519PublicKey.from_public_bytes(authority.public_key()).verify(signature, _canonical(payload))
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False


class RecoveryOperatorLifecycleTrustPolicy(BaseModel):
    """Deployment-pinned lifecycle trust anchors for fail-closed recovery."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["1.0"] = "1.0"
    registry_id: str = Field(min_length=1, max_length=200)
    authority_key_id: str = Field(min_length=1, max_length=160)
    minimum_sequence: int = Field(ge=0)
    expected_checkpoint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    def accepts(self, checkpoint: SignedOperatorLifecycleCheckpoint) -> bool:
        return (
            isinstance(checkpoint, SignedOperatorLifecycleCheckpoint)
            and checkpoint.registry_id == self.registry_id
            and checkpoint.authority_key_id == self.authority_key_id
            and checkpoint.sequence >= self.minimum_sequence
            and checkpoint.digest() == self.expected_checkpoint_sha256
        )


class OperatorLifecycleCheckpointAdvanceReport(BaseModel):
    """Result of validating one checkpoint against an externally pinned predecessor."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    accepted: bool
    previous_sequence: int = Field(ge=0)
    candidate_sequence: int = Field(ge=0)
    previous_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    errors: tuple[str, ...] = ()


def verify_operator_lifecycle_checkpoint_advance(
    previous: SignedOperatorLifecycleCheckpoint,
    candidate: SignedOperatorLifecycleCheckpoint, *,
    authority_keyring: dict[str, PolicyPublisherKey],
    expected_previous_sha256: str,
    expected_registry_id: str,
    authorization_time_utc: str | None = None,
) -> OperatorLifecycleCheckpointAdvanceReport:
    """Verify exactly one contiguous, signed advancement from a pinned checkpoint.

    The caller must retain expected_previous_sha256 outside the mutable store.
    This validates a single step, not a distributed consensus or an entire
    unobserved history.
    """
    errors: list[str] = []
    previous_digest = previous.digest() if isinstance(previous, SignedOperatorLifecycleCheckpoint) else "0" * 64
    candidate_digest = candidate.digest() if isinstance(candidate, SignedOperatorLifecycleCheckpoint) else "0" * 64
    if not isinstance(previous, SignedOperatorLifecycleCheckpoint):
        errors.append("previous_checkpoint_invalid")
    elif previous_digest != expected_previous_sha256:
        errors.append("previous_checkpoint_anchor_mismatch")
    elif not verify_operator_lifecycle_checkpoint(
        previous, authority_keyring=authority_keyring,
        expected_registry_id=expected_registry_id,
        expected_checkpoint_sha256=expected_previous_sha256,
        authorization_time_utc=authorization_time_utc,
    ):
        errors.append("previous_checkpoint_signature_or_policy_invalid")
    if not isinstance(candidate, SignedOperatorLifecycleCheckpoint):
        errors.append("candidate_checkpoint_invalid")
    elif isinstance(previous, SignedOperatorLifecycleCheckpoint):
        if candidate.registry_id != previous.registry_id:
            errors.append("registry_changed")
        if candidate.authority_key_id != previous.authority_key_id:
            errors.append("authority_changed")
        if candidate.sequence != previous.sequence + 1:
            errors.append("sequence_not_contiguous")
        if candidate.previous_checkpoint_sha256 != previous_digest:
            errors.append("predecessor_digest_mismatch")
        if candidate.issued_at_utc <= previous.issued_at_utc:
            errors.append("issuance_time_not_monotonic")
        if not verify_operator_lifecycle_checkpoint(
            candidate, authority_keyring=authority_keyring,
            expected_registry_id=expected_registry_id,
            expected_sequence=previous.sequence + 1,
            expected_previous_sha256=previous_digest,
            authorization_time_utc=authorization_time_utc,
        ):
            errors.append("candidate_signature_or_policy_invalid")
    else:
        errors.append("predecessor_unavailable")
    return OperatorLifecycleCheckpointAdvanceReport(
        accepted=not errors,
        previous_sequence=previous.sequence if isinstance(previous, SignedOperatorLifecycleCheckpoint) else 0,
        candidate_sequence=candidate.sequence if isinstance(candidate, SignedOperatorLifecycleCheckpoint) else 0,
        previous_sha256=previous_digest, candidate_sha256=candidate_digest,
        errors=tuple(dict.fromkeys(errors)),
    )
