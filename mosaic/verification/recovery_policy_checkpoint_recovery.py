"""Threshold-signed administrative rebootstrap for quarantined recovery-policy registries."""
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
from mosaic.verification.policy_witness_recovery_policy_registry import (
    SignedPolicyWitnessRecoveryPolicyCheckpoint,
    SignedPolicyWitnessRecoveryPolicyEntry,
)
from mosaic.verification.policy_witness_recovery_governance import PolicyWitnessRecoveryPolicy


class RecoveryPolicyCheckpointRebootstrapIntent(BaseModel):
    """Operator proposal bound to the exact quarantined state and selected fork."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["1.0"] = "1.0"
    registry_id: str = Field(min_length=1, max_length=200)
    retained_checkpoint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    incident_history_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    selected_checkpoint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reason: str = Field(min_length=20, max_length=2000)
    operator_key_id: str = Field(min_length=1, max_length=160)
    approved_at_utc: str = Field(min_length=20, max_length=40)
    signature_b64: str = Field(min_length=1, max_length=128)

    @classmethod
    def sign(cls, *, registry_id: str, retained_checkpoint_sha256: str,
             incident_history_sha256: str, selected_checkpoint_sha256: str,
             evidence_sha256: str, reason: str, operator_key_id: str,
             approved_at_utc: str, private_key: bytes):
        if not isinstance(private_key, bytes) or len(private_key) != 32:
            raise ValueError("Ed25519 private key must be exactly 32 raw bytes")
        payload = {
            "schema_version": "1.0", "registry_id": registry_id,
            "retained_checkpoint_sha256": retained_checkpoint_sha256,
            "incident_history_sha256": incident_history_sha256,
            "selected_checkpoint_sha256": selected_checkpoint_sha256,
            "evidence_sha256": evidence_sha256, "reason": reason,
            "operator_key_id": operator_key_id,
            "approved_at_utc": _canonical_timestamp(approved_at_utc),
        }
        sig = Ed25519PrivateKey.from_private_bytes(private_key).sign(_canonical(payload))
        return cls(**payload, signature_b64=base64.b64encode(sig).decode("ascii"))

    def digest(self) -> str:
        return hashlib.sha256(_canonical(self.model_dump(mode="json"))).hexdigest()

    def verify(self, keyring: dict[str, PolicyPublisherKey]) -> bool:
        record = keyring.get(self.operator_key_id) if isinstance(keyring, dict) else None
        if record is None or not record.permits(self.operator_key_id, self.approved_at_utc):
            return False
        try:
            if _canonical_timestamp(self.approved_at_utc) != self.approved_at_utc:
                return False
            public = record.public_key()
            sig = base64.b64decode(self.signature_b64, validate=True)
            if public is None or len(sig) != 64:
                return False
            Ed25519PublicKey.from_public_bytes(public).verify(
                sig, _canonical(self.model_dump(mode="json", exclude={"signature_b64"})))
            return True
        except (ValueError, TypeError, InvalidSignature):
            return False


class RecoveryPolicyCheckpointRebootstrapApproval(BaseModel):
    """Additional operator approval of one exact rebootstrap intent."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["1.0"] = "1.0"
    intent_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    operator_key_id: str = Field(min_length=1, max_length=160)
    approved_at_utc: str = Field(min_length=20, max_length=40)
    signature_b64: str = Field(min_length=1, max_length=128)

    @classmethod
    def sign(cls, *, intent: RecoveryPolicyCheckpointRebootstrapIntent,
             operator_key_id: str, approved_at_utc: str, private_key: bytes):
        if not isinstance(private_key, bytes) or len(private_key) != 32:
            raise ValueError("Ed25519 private key must be exactly 32 raw bytes")
        payload = {"schema_version": "1.0", "intent_sha256": intent.digest(),
                   "operator_key_id": operator_key_id,
                   "approved_at_utc": _canonical_timestamp(approved_at_utc)}
        sig = Ed25519PrivateKey.from_private_bytes(private_key).sign(_canonical(payload))
        return cls(**payload, signature_b64=base64.b64encode(sig).decode("ascii"))

    def verify(self, intent, keyring) -> bool:
        record = keyring.get(self.operator_key_id) if isinstance(keyring, dict) else None
        if (record is None or self.intent_sha256 != intent.digest()
                or not record.permits(self.operator_key_id, self.approved_at_utc)):
            return False
        try:
            if _canonical_timestamp(self.approved_at_utc) != self.approved_at_utc:
                return False
            public = record.public_key()
            sig = base64.b64decode(self.signature_b64, validate=True)
            if public is None or len(sig) != 64:
                return False
            Ed25519PublicKey.from_public_bytes(public).verify(
                sig, _canonical(self.model_dump(mode="json", exclude={"signature_b64"})))
            return True
        except (ValueError, TypeError, InvalidSignature):
            return False


class RecoveryPolicyCheckpointRebootstrapPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["1.0"] = "1.0"
    minimum_approvals: int = Field(default=2, ge=2, le=20)
    required_operator_key_ids: tuple[str, ...] = ()
    prohibited_operator_key_ids: tuple[str, ...] = ()

    def valid(self):
        return (len(set(self.required_operator_key_ids)) == len(self.required_operator_key_ids)
                and len(set(self.prohibited_operator_key_ids)) == len(self.prohibited_operator_key_ids)
                and not set(self.required_operator_key_ids) & set(self.prohibited_operator_key_ids)
                and len(self.required_operator_key_ids) <= self.minimum_approvals
                and all(self.required_operator_key_ids) and all(self.prohibited_operator_key_ids))


def verify_rebootstrap_approvals(intent, *, policy, approvals, operator_keyring,
                                publisher_keyring, checkpoint_keyring) -> bool:
    """Require distinct lifecycle-valid operator identities and public keys."""
    if (not isinstance(intent, RecoveryPolicyCheckpointRebootstrapIntent)
            or not isinstance(policy, RecoveryPolicyCheckpointRebootstrapPolicy)
            or not policy.valid() or not intent.verify(operator_keyring)
            or not isinstance(approvals, list)
            or len(approvals) + 1 < policy.minimum_approvals):
        return False
    rings = (publisher_keyring, checkpoint_keyring)
    forbidden = {r.public_key() for ring in rings for r in ring.values()
                 if isinstance(r, PolicyPublisherKey) and r.public_key() is not None}
    first = operator_keyring.get(intent.operator_key_id)
    if first is None or first.public_key() is None or first.public_key() in forbidden:
        return False
    ids, pubs = {intent.operator_key_id}, {first.public_key()}
    for approval in approvals:
        if (not isinstance(approval, RecoveryPolicyCheckpointRebootstrapApproval)
                or approval.operator_key_id in ids
                or not approval.verify(intent, operator_keyring)):
            return False
        record = operator_keyring.get(approval.operator_key_id)
        public = record.public_key() if record else None
        if public is None or public in pubs or public in forbidden:
            return False
        ids.add(approval.operator_key_id)
        pubs.add(public)
    return (len(ids) >= policy.minimum_approvals
            and set(policy.required_operator_key_ids) <= ids
            and not set(policy.prohibited_operator_key_ids) & ids)


def rebootstrap_recovery_policy_checkpoint_store(
    store, entries: list[SignedPolicyWitnessRecoveryPolicyEntry], *,
    checkpoint: SignedPolicyWitnessRecoveryPolicyCheckpoint,
    publisher_keyring: dict, checkpoint_keyring: dict | None,
    intent: RecoveryPolicyCheckpointRebootstrapIntent,
    approvals: list[RecoveryPolicyCheckpointRebootstrapApproval],
    policy: RecoveryPolicyCheckpointRebootstrapPolicy,
    operator_keyring: dict,
) -> bool:
    """Atomically start a new retained epoch; old histories and incidents remain intact."""
    if not store._verify(entries, checkpoint, publisher_keyring, checkpoint_keyring):
        return False
    if intent.registry_id != checkpoint.registry_id:
        return False
    if not verify_rebootstrap_approvals(
        intent, policy=policy, approvals=approvals, operator_keyring=operator_keyring,
        publisher_keyring=publisher_keyring,
        checkpoint_keyring=checkpoint_keyring or publisher_keyring,
    ):
        return False
    checkpoint_json = checkpoint.model_dump_json()
    checkpoint_hash = hashlib.sha256(checkpoint_json.encode()).hexdigest()
    if intent.selected_checkpoint_sha256 != checkpoint_hash:
        return False
    with store._connection() as db:
        db.execute("BEGIN IMMEDIATE")
        head = db.execute("SELECT checkpoint_sha256, quarantined, epoch FROM recovery_policy_heads WHERE registry_id=?",
                          (checkpoint.registry_id,)).fetchone()
        if head is None or not head["quarantined"]:
            db.rollback()
            return False
        incidents = [dict(r) for r in db.execute(
            "SELECT registry_id, retained_checkpoint_sha256, presented_checkpoint_sha256, reason, observed_at_utc "
            "FROM recovery_policy_incidents WHERE registry_id=? ORDER BY incident_id",
            (checkpoint.registry_id,)).fetchall()]
        incident_hash = hashlib.sha256(_canonical(incidents)).hexdigest()
        if (head["checkpoint_sha256"] != intent.retained_checkpoint_sha256
                or incident_hash != intent.incident_history_sha256):
            db.rollback()
            return False
        if db.execute("SELECT 1 FROM recovery_policy_rebootstrap_audit WHERE intent_sha256=?",
                      (intent.digest(),)).fetchone():
            db.rollback()
            return False
        new_epoch = int(head["epoch"]) + 1
        for entry in entries:
            entry_json = entry.model_dump_json()
            db.execute("INSERT INTO recovery_policy_epoch_entries VALUES (?, ?, ?, ?, ?)",
                       (checkpoint.registry_id, new_epoch, entry.sequence, entry.digest(), entry_json))
        db.execute("UPDATE recovery_policy_heads SET checkpoint_json=?, checkpoint_sha256=?, quarantined=0, epoch=? WHERE registry_id=?",
                   (checkpoint_json, checkpoint_hash, new_epoch, checkpoint.registry_id))
        audit = _canonical({"intent": intent.model_dump(mode="json"),
                            "approvals": [a.model_dump(mode="json") for a in approvals],
                            "epoch": new_epoch, "checkpoint_sha256": checkpoint_hash}).decode()
        db.execute("INSERT INTO recovery_policy_rebootstrap_audit (intent_sha256, registry_id, epoch, audit_json) VALUES (?, ?, ?, ?)",
                   (intent.digest(), checkpoint.registry_id, new_epoch, audit))
        db.commit()
    return True
