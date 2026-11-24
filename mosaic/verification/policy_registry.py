"""Signed, hash-linked historical trust-policy registry.

Signatures authenticate individual registry entries. Hash links detect edits and
reordering. A caller-supplied trusted checkpoint is required to detect rollback
to an older, otherwise-valid prefix.
"""
from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from mosaic.verification.lean_runner_signature import _canonical
from mosaic.verification.trust_policy import (
    HistoricalTrustPolicyRecord,
    verify_policy_record,
)


def _utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _canonical_timestamp(value: str) -> str:
    return _utc(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


class SignedPolicyRegistryEntry(BaseModel):
    """One signed policy publication in an append-only registry chain."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["mosaic.signed-policy-registry-entry.v1"] = (
        "mosaic.signed-policy-registry-entry.v1"
    )
    sequence: int = Field(ge=0)
    previous_entry_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    policy_record: HistoricalTrustPolicyRecord
    published_at_utc: str = Field(min_length=20, max_length=40)
    publisher_key_id: str = Field(min_length=1, max_length=160)
    signature_b64: str = Field(min_length=1, max_length=128)

    @classmethod
    def sign(
        cls,
        *,
        sequence: int,
        previous_entry_sha256: str | None,
        policy_record: HistoricalTrustPolicyRecord,
        published_at_utc: str,
        publisher_key_id: str,
        private_key: bytes,
    ) -> "SignedPolicyRegistryEntry":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        if not isinstance(private_key, bytes) or len(private_key) != 32:
            raise ValueError("Ed25519 private key must be exactly 32 raw bytes")
        if not verify_policy_record(policy_record):
            raise ValueError("policy record digest or lifecycle is invalid")
        published = _canonical_timestamp(published_at_utc)
        payload = {
            "schema_version": "mosaic.signed-policy-registry-entry.v1",
            "sequence": sequence,
            "previous_entry_sha256": previous_entry_sha256,
            "policy_record": policy_record.model_dump(mode="json"),
            "published_at_utc": published,
            "publisher_key_id": publisher_key_id,
        }
        signature = Ed25519PrivateKey.from_private_bytes(private_key).sign(
            _canonical(payload)
        )
        return cls(
            **payload,
            signature_b64=base64.b64encode(signature).decode("ascii"),
        )

    def verify(self, publisher_public_keys: dict[str, bytes]) -> bool:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        key = publisher_public_keys.get(self.publisher_key_id)
        if not isinstance(key, bytes) or len(key) != 32:
            return False
        try:
            if _canonical_timestamp(self.published_at_utc) != self.published_at_utc:
                return False
            if not verify_policy_record(self.policy_record):
                return False
            signature = base64.b64decode(self.signature_b64, validate=True)
            if len(signature) != 64:
                return False
            payload = self.model_dump(mode="json", exclude={"signature_b64"})
            Ed25519PublicKey.from_public_bytes(key).verify(signature, _canonical(payload))
            return True
        except (ValueError, TypeError, InvalidSignature):
            return False

    def entry_sha256(self) -> str:
        """Digest the complete signed entry, including its signature."""
        return hashlib.sha256(_canonical(self.model_dump(mode="json"))).hexdigest()


def verify_policy_registry(
    entries: list[SignedPolicyRegistryEntry],
    *,
    publisher_public_keys: dict[str, bytes],
    expected_head_sequence: int | None = None,
    expected_head_sha256: str | None = None,
) -> bool:
    """Verify signatures, contiguous sequence, hash links, and optional checkpoint.

    The checkpoint must come from a separately trusted/persisted source. Without
    it, a valid older prefix is indistinguishable from the latest registry.
    """
    if not isinstance(entries, list) or not entries:
        return False
    previous_digest = None
    for expected_sequence, entry in enumerate(entries):
        if not isinstance(entry, SignedPolicyRegistryEntry):
            return False
        if (
            entry.sequence != expected_sequence
            or entry.previous_entry_sha256 != previous_digest
            or not entry.verify(publisher_public_keys)
        ):
            return False
        previous_digest = entry.entry_sha256()
    head_sequence = entries[-1].sequence
    if expected_head_sequence is not None and head_sequence != expected_head_sequence:
        return False
    if expected_head_sha256 is not None and previous_digest != expected_head_sha256:
        return False
    if (expected_head_sequence is None) != (expected_head_sha256 is None):
        return False
    return True
