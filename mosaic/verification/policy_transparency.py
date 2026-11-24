"""Signed registry checkpoints and independent witness verification.

This is a checkpoint/prefix verifier, not a Merkle transparency log or a
network gossip protocol. Callers must persist trusted checkpoints separately.
"""
from __future__ import annotations

import base64
import hashlib
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from mosaic.verification.lean_runner_signature import _canonical
from mosaic.verification.policy_registry import (
    SignedPolicyRegistryEntry,
    _canonical_timestamp,
)
from mosaic.verification.policy_governance import PolicyPublisherKey


class PolicyRegistryCheckpoint(BaseModel):
    """Signed statement of one policy-registry head for a named log."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["mosaic.policy-registry-checkpoint.v1"] = (
        "mosaic.policy-registry-checkpoint.v1"
    )
    log_id: str = Field(min_length=1, max_length=200)
    sequence: int = Field(ge=0)
    head_entry_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    previous_checkpoint_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    issued_at_utc: str = Field(min_length=20, max_length=40)
    signer_key_id: str = Field(min_length=1, max_length=160)
    signature_b64: str = Field(min_length=1, max_length=128)

    @classmethod
    def sign(
        cls, *, log_id: str, sequence: int, head_entry_sha256: str,
        previous_checkpoint_sha256: str | None, issued_at_utc: str,
        signer_key_id: str, private_key: bytes,
    ) -> "PolicyRegistryCheckpoint":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        if not isinstance(private_key, bytes) or len(private_key) != 32:
            raise ValueError("Ed25519 private key must be exactly 32 raw bytes")
        payload = {
            "schema_version": "mosaic.policy-registry-checkpoint.v1",
            "log_id": log_id,
            "sequence": sequence,
            "head_entry_sha256": head_entry_sha256,
            "previous_checkpoint_sha256": previous_checkpoint_sha256,
            "issued_at_utc": _canonical_timestamp(issued_at_utc),
            "signer_key_id": signer_key_id,
        }
        signature = Ed25519PrivateKey.from_private_bytes(private_key).sign(
            _canonical(payload)
        )
        return cls(**payload, signature_b64=base64.b64encode(signature).decode("ascii"))

    def digest(self) -> str:
        return hashlib.sha256(_canonical(self.model_dump(mode="json"))).hexdigest()

    def verify_signature(self, keyring: dict[str, PolicyPublisherKey]) -> bool:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        record = keyring.get(self.signer_key_id)
        if (record is None
                or not record.permits(self.signer_key_id, self.issued_at_utc)):
            return False
        try:
            if _canonical_timestamp(self.issued_at_utc) != self.issued_at_utc:
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


class PolicyCheckpointWitness(BaseModel):
    """Independent witness signature over one exact checkpoint digest."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    checkpoint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    witness_key_id: str = Field(min_length=1, max_length=160)
    witnessed_at_utc: str = Field(min_length=20, max_length=40)
    signature_b64: str = Field(min_length=1, max_length=128)

    @classmethod
    def sign(
        cls, *, checkpoint: PolicyRegistryCheckpoint, witness_key_id: str,
        witnessed_at_utc: str, private_key: bytes,
    ) -> "PolicyCheckpointWitness":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        if not isinstance(private_key, bytes) or len(private_key) != 32:
            raise ValueError("Ed25519 private key must be exactly 32 raw bytes")
        payload = {
            "checkpoint_sha256": checkpoint.digest(),
            "witness_key_id": witness_key_id,
            "witnessed_at_utc": _canonical_timestamp(witnessed_at_utc),
        }
        signature = Ed25519PrivateKey.from_private_bytes(private_key).sign(_canonical(payload))
        return cls(**payload, signature_b64=base64.b64encode(signature).decode("ascii"))

    def verify(
        self, checkpoint: PolicyRegistryCheckpoint,
        witness_keyring: dict[str, PolicyPublisherKey],
    ) -> bool:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        record = witness_keyring.get(self.witness_key_id)
        if (record is None or self.checkpoint_sha256 != checkpoint.digest()
                or not record.permits(self.witness_key_id, self.witnessed_at_utc)):
            return False
        try:
            if _canonical_timestamp(self.witnessed_at_utc) != self.witnessed_at_utc:
                return False
            if self.witnessed_at_utc < checkpoint.issued_at_utc:
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


def verify_policy_checkpoint(
    checkpoint: PolicyRegistryCheckpoint, *,
    entries: list[SignedPolicyRegistryEntry],
    signer_keyring: dict[str, PolicyPublisherKey],
    witnesses: list[PolicyCheckpointWitness] | None = None,
    witness_keyring: dict[str, PolicyPublisherKey] | None = None,
    minimum_witnesses: int = 0,
    previous_checkpoint: PolicyRegistryCheckpoint | None = None,
) -> bool:
    """Verify signed head, witness quorum, and extension of a trusted checkpoint.

    The registry prefix is verified by exact entry digests, not a Merkle proof.
    The caller remains responsible for persisting and distributing trusted heads.
    """
    from mosaic.verification.policy_registry import verify_policy_registry
    if (not isinstance(checkpoint, PolicyRegistryCheckpoint)
            or not isinstance(entries, list) or not entries
            or minimum_witnesses < 0):
        return False
    if checkpoint.sequence != len(entries) - 1:
        return False
    if entries[-1].entry_sha256() != checkpoint.head_entry_sha256:
        return False
    if not verify_policy_registry(
        entries, publisher_public_keys={
            key_id: record.public_key()
            for key_id, record in signer_keyring.items()
            if isinstance(record, PolicyPublisherKey) and record.public_key() is not None
        },
    ):
        return False
    if not checkpoint.verify_signature(signer_keyring):
        return False

    if previous_checkpoint is None:
        if checkpoint.previous_checkpoint_sha256 is not None:
            return False
    else:
        if (not isinstance(previous_checkpoint, PolicyRegistryCheckpoint)
                or checkpoint.log_id != previous_checkpoint.log_id
                or checkpoint.sequence <= previous_checkpoint.sequence
                or checkpoint.previous_checkpoint_sha256 != previous_checkpoint.digest()
                or previous_checkpoint.sequence >= len(entries)
                or entries[previous_checkpoint.sequence].entry_sha256()
                   != previous_checkpoint.head_entry_sha256):
            return False
        # Re-check the old checkpoint's signature and its exact registry prefix.
        if not previous_checkpoint.verify_signature(signer_keyring):
            return False
        if not verify_policy_registry(
            entries[:previous_checkpoint.sequence + 1],
            publisher_public_keys={
                key_id: record.public_key()
                for key_id, record in signer_keyring.items()
                if isinstance(record, PolicyPublisherKey) and record.public_key() is not None
            },
        ):
            return False

    witness_records = witnesses or []
    trusted_witnesses = witness_keyring or {}
    accepted: set[str] = set()
    for witness in witness_records:
        if (not isinstance(witness, PolicyCheckpointWitness)
                or witness.witness_key_id in accepted
                or not witness.verify(checkpoint, trusted_witnesses)):
            return False
        accepted.add(witness.witness_key_id)
    return len(accepted) >= minimum_witnesses


def find_checkpoint_equivocations(
    checkpoints: list[PolicyRegistryCheckpoint],
) -> list[tuple[str, int, str, str]]:
    """Return conflicting (log_id, sequence, first_digest, second_digest) heads."""
    seen: dict[tuple[str, int], str] = {}
    conflicts: list[tuple[str, int, str, str]] = []
    for checkpoint in checkpoints:
        if not isinstance(checkpoint, PolicyRegistryCheckpoint):
            continue
        key = (checkpoint.log_id, checkpoint.sequence)
        digest = checkpoint.head_entry_sha256
        prior = seen.get(key)
        if prior is None:
            seen[key] = digest
        elif prior != digest and not any(
            item[0] == key[0] and item[1] == key[1]
            and {item[2], item[3]} == {prior, digest}
            for item in conflicts
        ):
            conflicts.append((key[0], key[1], prior, digest))
    return conflicts
