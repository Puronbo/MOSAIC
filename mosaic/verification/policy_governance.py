"""Publisher-key lifecycle and quorum verification for the policy registry."""
from __future__ import annotations

import base64
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field
from mosaic.verification.lean_runner_signature import _canonical
from mosaic.verification.policy_registry import (
    SignedPolicyRegistryEntry, _canonical_timestamp, _utc, verify_policy_registry,
)


class PolicyPublisherKey(BaseModel):
    """Publisher identity with independently provisioned lifecycle boundaries."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    key_id: str = Field(min_length=1, max_length=160)
    public_key_b64: str = Field(min_length=44, max_length=44)
    activated_at_utc: str = Field(min_length=20, max_length=40)
    revoked_at_utc: str | None = Field(default=None, min_length=20, max_length=40)

    def permits(self, key_id: str, signed_at_utc: str) -> bool:
        try:
            if key_id != self.key_id:
                return False
            signed = _utc(signed_at_utc)
            activated = _utc(self.activated_at_utc)
            revoked = _utc(self.revoked_at_utc) if self.revoked_at_utc else None
            return activated <= signed and (revoked is None or signed < revoked)
        except (ValueError, TypeError):
            return False

    def public_key(self) -> bytes | None:
        try:
            key = base64.b64decode(self.public_key_b64, validate=True)
            return key if len(key) == 32 else None
        except (ValueError, TypeError):
            return None


class PolicyPublisherApproval(BaseModel):
    """Independent approval of one exact signed registry entry."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    entry_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    sequence: int = Field(ge=0)
    publisher_key_id: str = Field(min_length=1, max_length=160)
    approved_at_utc: str = Field(min_length=20, max_length=40)
    signature_b64: str = Field(min_length=1, max_length=128)

    @classmethod
    def sign(cls, *, entry: SignedPolicyRegistryEntry, publisher_key_id: str,
             approved_at_utc: str, private_key: bytes) -> "PolicyPublisherApproval":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        if not isinstance(private_key, bytes) or len(private_key) != 32:
            raise ValueError("Ed25519 private key must be exactly 32 raw bytes")
        payload = {
            "entry_sha256": entry.entry_sha256(),
            "sequence": entry.sequence,
            "publisher_key_id": publisher_key_id,
            "approved_at_utc": _canonical_timestamp(approved_at_utc),
        }
        signature = Ed25519PrivateKey.from_private_bytes(private_key).sign(_canonical(payload))
        return cls(**payload, signature_b64=base64.b64encode(signature).decode("ascii"))

    def verify(self, keyring: dict[str, PolicyPublisherKey],
               entry: SignedPolicyRegistryEntry) -> bool:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        record = keyring.get(self.publisher_key_id)
        if (record is None or self.entry_sha256 != entry.entry_sha256()
                or self.sequence != entry.sequence
                or not record.permits(self.publisher_key_id, self.approved_at_utc)):
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


def verify_policy_registry_with_keyring(
    entries: list[SignedPolicyRegistryEntry], *,
    publisher_keyring: dict[str, PolicyPublisherKey],
    minimum_approvals: int = 1,
    approvals_by_entry: dict[str, list[PolicyPublisherApproval]] | None = None,
    expected_head_sequence: int | None = None,
    expected_head_sha256: str | None = None,
) -> bool:
    """Verify lifecycle-authorized signers and independent approval quorum.

    Entry signers count as one approval. Additional approvals bind the complete
    signed entry digest. A trusted head checkpoint is still required for
    rollback protection; keyring and checkpoint distribution are external.
    """
    if minimum_approvals < 1 or not isinstance(publisher_keyring, dict):
        return False
    public_keys = {}
    for key_id, record in publisher_keyring.items():
        if not isinstance(record, PolicyPublisherKey) or key_id != record.key_id:
            return False
        key = record.public_key()
        if key is not None:
            public_keys[key_id] = key
    if not verify_policy_registry(
        entries, publisher_public_keys=public_keys,
        expected_head_sequence=expected_head_sequence,
        expected_head_sha256=expected_head_sha256,
    ):
        return False
    approvals_by_entry = approvals_by_entry or {}
    if any(key not in {entry.entry_sha256() for entry in entries} for key in approvals_by_entry):
        return False
    for entry in entries:
        primary = publisher_keyring.get(entry.publisher_key_id)
        if primary is None or not primary.permits(entry.publisher_key_id, entry.published_at_utc):
            return False
        approved_ids = {entry.publisher_key_id}
        for approval in approvals_by_entry.get(entry.entry_sha256(), []):
            if (approval.publisher_key_id in approved_ids
                    or not approval.verify(publisher_keyring, entry)):
                return False
            approved_ids.add(approval.publisher_key_id)
        if len(approved_ids) < minimum_approvals:
            return False
    return True
