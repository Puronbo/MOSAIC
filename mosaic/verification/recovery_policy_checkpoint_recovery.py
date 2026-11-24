"""Threshold-signed administrative rebootstrap for quarantined recovery-policy registries."""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime
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
    verify_policy_witness_recovery_policy_registry,
)
from mosaic.verification.policy_witness_recovery_governance import PolicyWitnessRecoveryPolicy


class RecoveryPolicyCheckpointAuditVerificationReport(BaseModel):
    """Explicit result for verified, empty, legacy, or invalid audit exports."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    status: Literal["verified", "empty", "legacy_unverifiable", "invalid"]
    registry_id: str
    record_count: int = Field(ge=0)
    verified_record_count: int = Field(ge=0)
    legacy_record_count: int = Field(ge=0)
    head_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_head_sha256: str | None = None
    errors: tuple[str, ...] = ()

    @property
    def is_verified(self) -> bool:
        return self.status in ("verified", "empty") and not self.errors


class RecoveryProposalConflictReport(BaseModel):
    """Deterministic attribution of submitted proposal digests to retained audit winners."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    registry_id: str
    proposal_count: int = Field(ge=0)
    distinct_proposal_count: int = Field(ge=0)
    conflicting: bool
    winning_intent_sha256: str | None = None
    losing_intent_sha256: tuple[str, ...] = ()
    unattributed_intent_sha256: tuple[str, ...] = ()


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
    authorization_time_utc: str | None = None,
) -> bool:
    """Atomically start a new retained epoch; old histories and incidents remain intact.

    Supply a trusted authorization_time_utc to enforce current key lifecycle status.
    If omitted, the latest signed approval time is used for backward compatibility.
    """
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
    # Historical signature validity is distinct from authorization at execution.
    # A key revoked after signing remains verifiable, but cannot authorize a
    # new state transition after its revocation time.
    if authorization_time_utc is None:
        authorization_time_utc = max(
            [intent.approved_at_utc] + [approval.approved_at_utc for approval in approvals]
        )
    try:
        if _canonical_timestamp(authorization_time_utc) != authorization_time_utc:
            return False
        authorized_at = datetime.fromisoformat(authorization_time_utc.replace("Z", "+00:00"))
        for key_id in [intent.operator_key_id] + [approval.operator_key_id for approval in approvals]:
            record = operator_keyring.get(key_id)
            if (record is None or not record.permits(key_id, authorization_time_utc)
                    or datetime.fromisoformat(record.activated_at_utc.replace("Z", "+00:00")) > authorized_at):
                return False
    except (ValueError, TypeError):
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
        audit_data = {
            "schema_version": "1.0",
            "intent": intent.model_dump(mode="json"),
            "approvals": [a.model_dump(mode="json") for a in approvals],
            "policy": policy.model_dump(mode="json"),
            "checkpoint": checkpoint.model_dump(mode="json"),
            "entries": [entry.model_dump(mode="json") for entry in entries],
            "epoch": new_epoch,
            "checkpoint_sha256": checkpoint_hash,
        }
        audit = _canonical(audit_data).decode()
        previous = db.execute(
            "SELECT audit_sha256 FROM recovery_policy_rebootstrap_audit "
            "WHERE registry_id=? AND audit_sha256 IS NOT NULL ORDER BY epoch DESC LIMIT 1",
            (checkpoint.registry_id,)
        ).fetchone()
        # Legacy rows are retained but cannot anchor a verified chain.
        previous_hash = previous["audit_sha256"] if previous else "0" * 64
        audit_hash = hashlib.sha256(_canonical({
            "previous_audit_sha256": previous_hash, "audit": audit_data
        })).hexdigest()
        db.execute(
            "INSERT INTO recovery_policy_rebootstrap_audit "
            "(intent_sha256, registry_id, epoch, audit_json, previous_audit_sha256, audit_sha256) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (intent.digest(), checkpoint.registry_id, new_epoch, audit, previous_hash, audit_hash),
        )
        db.commit()
    return True



def export_rebootstrap_audit(store, *, registry_id: str) -> dict:
    """Export retained rebootstrap records and their chain head for independent verification."""
    if not isinstance(registry_id, str) or not registry_id:
        raise ValueError("registry_id must be a non-empty string")
    with store._connection() as db:
        rows = db.execute(
            "SELECT epoch, audit_json, previous_audit_sha256, audit_sha256 "
            "FROM recovery_policy_rebootstrap_audit WHERE registry_id=? ORDER BY epoch",
            (registry_id,),
        ).fetchall()
    records = [{
        "epoch": row["epoch"],
        "audit": json.loads(row["audit_json"]),
        "previous_audit_sha256": row["previous_audit_sha256"],
        "audit_sha256": row["audit_sha256"],
        "record_version": "v1" if row["audit_sha256"] is not None else "legacy-unverifiable",
    } for row in rows]
    return {
        "schema_version": "mosaic.recovery-policy-rebootstrap-audit-export.v1",
        "registry_id": registry_id,
        "record_count": len(records),
        "records": records,
        "head_sha256": next((item["audit_sha256"] for item in reversed(records) if item["audit_sha256"] is not None), "0" * 64),
    }


def report_rebootstrap_proposal_conflicts(
    intents: list[RecoveryPolicyCheckpointRebootstrapIntent], audit_export: dict,
) -> RecoveryProposalConflictReport:
    """Attribute exact submitted intent digests to the single retained audit winner.

    This is an audit comparison, not a proposal-validity check or a winner-selection
    algorithm. Unmatched proposals are explicitly left unattributed.
    """
    if not isinstance(intents, list) or any(
        not isinstance(item, RecoveryPolicyCheckpointRebootstrapIntent) for item in intents
    ):
        raise ValueError("intents must be a list of rebootstrap intent records")
    if not isinstance(audit_export, dict) or not isinstance(audit_export.get("records"), list):
        raise ValueError("audit_export must contain a records list")
    registry_id = audit_export.get("registry_id", "")
    if not isinstance(registry_id, str) or not registry_id:
        raise ValueError("audit_export registry_id must be non-empty")
    submitted = sorted({item.digest() for item in intents})
    audited = []
    for record in audit_export["records"]:
        if not isinstance(record, dict) or record.get("record_version") != "v1":
            continue
        audit = record.get("audit")
        if not isinstance(audit, dict) or not isinstance(audit.get("intent"), dict):
            continue
        try:
            audited.append(RecoveryPolicyCheckpointRebootstrapIntent.model_validate(
                audit["intent"]).digest())
        except (ValueError, TypeError):
            continue
    # The retained audit order is authoritative; do not infer priority from
    # proposal order, timestamps, or digest sorting.
    winning = next((item for item in reversed(audited) if item in submitted), None)
    losing = tuple(item for item in submitted if item in audited and item != winning)
    unattributed = tuple(item for item in submitted if item not in audited)
    return RecoveryProposalConflictReport(
        registry_id=registry_id, proposal_count=len(intents),
        distinct_proposal_count=len(submitted), conflicting=len(submitted) > 1,
        winning_intent_sha256=winning, losing_intent_sha256=losing,
        unattributed_intent_sha256=unattributed,
    )


def _verify_rebootstrap_audit_export_v1(
    export: dict, *, operator_keyring: dict, publisher_keyring: dict,
    checkpoint_keyring: dict | None,
    expected_head_sha256: str | None = None,
) -> bool:
    """Verify audit chain, every operator signature, policy threshold, and saved registry proof."""
    if not isinstance(export, dict) or set(export) != {
        "schema_version", "registry_id", "record_count", "records", "head_sha256"
    }:
        return False
    if (export["schema_version"] != "mosaic.recovery-policy-rebootstrap-audit-export.v1"
            or not isinstance(export["registry_id"], str) or not export["registry_id"]
            or not isinstance(export["records"], list)
            or export["record_count"] != len(export["records"])):
        return False
    if expected_head_sha256 is not None and export["head_sha256"] != expected_head_sha256:
        return False
    previous = "0" * 64
    expected_epoch = None
    for item in export["records"]:
        if not isinstance(item, dict) or set(item) != {
            "epoch", "audit", "previous_audit_sha256", "audit_sha256", "record_version"
        }:
            return False
        if item["record_version"] == "legacy-unverifiable":
            if item["audit_sha256"] is not None or item["previous_audit_sha256"] is not None:
                return False
            if not isinstance(item["audit"], dict) or item["epoch"] != item["audit"].get("epoch"):
                return False
            continue
        if item["record_version"] != "v1":
            return False
        audit = item["audit"]
        if not isinstance(audit, dict) or set(audit) != {
            "schema_version", "intent", "approvals", "policy", "checkpoint",
            "entries", "epoch", "checkpoint_sha256"
        }:
            return False
        if (item["previous_audit_sha256"] != previous
                or item["epoch"] != audit["epoch"]
                or (expected_epoch is not None and item["epoch"] <= expected_epoch)
                or audit["schema_version"] != "1.0"):
            return False
        try:
            intent = RecoveryPolicyCheckpointRebootstrapIntent.model_validate(audit["intent"])
            policy = RecoveryPolicyCheckpointRebootstrapPolicy.model_validate(audit["policy"])
            approvals = [RecoveryPolicyCheckpointRebootstrapApproval.model_validate(x)
                         for x in audit["approvals"]]
            checkpoint = SignedPolicyWitnessRecoveryPolicyCheckpoint.model_validate(audit["checkpoint"])
            entries = [SignedPolicyWitnessRecoveryPolicyEntry.model_validate(x)
                       for x in audit["entries"]]
        except (ValueError, TypeError):
            return False
        checkpoint_hash = hashlib.sha256(checkpoint.model_dump_json().encode()).hexdigest()
        if (intent.registry_id != export["registry_id"]
                or audit["checkpoint_sha256"] != checkpoint_hash
                or intent.selected_checkpoint_sha256 != checkpoint_hash
                or not verify_rebootstrap_approvals(
                    intent, policy=policy, approvals=approvals,
                    operator_keyring=operator_keyring,
                    publisher_keyring=publisher_keyring,
                    checkpoint_keyring=checkpoint_keyring or publisher_keyring,
                )
                or not verify_policy_witness_recovery_policy_registry(
                    entries, publisher_keyring=publisher_keyring,
                    trusted_checkpoint=checkpoint,
                    checkpoint_keyring=checkpoint_keyring,
                )):
            return False
        computed = hashlib.sha256(_canonical({
            "previous_audit_sha256": previous, "audit": audit
        })).hexdigest()
        if item["audit_sha256"] != computed:
            return False
        previous = computed
        expected_epoch = item["epoch"]
    if export["head_sha256"] != previous:
        return False
    # An externally retained head detects complete-record truncation and replacement.
    return expected_head_sha256 is None or expected_head_sha256 == previous


def verify_rebootstrap_audit_export_report(
    export: dict, *, operator_keyring: dict, publisher_keyring: dict,
    checkpoint_keyring: dict | None, expected_head_sha256: str | None = None,
) -> RecoveryPolicyCheckpointAuditVerificationReport:
    """Return diagnostics without treating retained legacy rows as verified."""
    registry_id = export.get("registry_id", "") if isinstance(export, dict) else ""
    records = export.get("records", []) if isinstance(export, dict) and isinstance(export.get("records"), list) else []
    count = len(records)
    head = export.get("head_sha256", "0" * 64) if isinstance(export, dict) else "0" * 64
    if not isinstance(head, str) or len(head) != 64 or any(c not in "0123456789abcdef" for c in head):
        head = "0" * 64
    legacy = sum(1 for item in records if isinstance(item, dict) and item.get("record_version") == "legacy-unverifiable")
    valid = _verify_rebootstrap_audit_export_v1(
        export, operator_keyring=operator_keyring, publisher_keyring=publisher_keyring,
        checkpoint_keyring=checkpoint_keyring, expected_head_sha256=expected_head_sha256,
    )
    verified = sum(1 for item in records if isinstance(item, dict) and item.get("record_version") == "v1") if valid else 0
    status = "invalid" if not valid else "legacy_unverifiable" if legacy else "empty" if not records else "verified"
    errors = () if valid and not legacy else (("One or more legacy rows lack independently verifiable G-EP103 material.",) if valid else ("Audit structure, chain, signatures, registry proof, or expected head failed verification.",))
    return RecoveryPolicyCheckpointAuditVerificationReport(
        status=status, registry_id=registry_id if isinstance(registry_id, str) else "",
        record_count=count, verified_record_count=verified, legacy_record_count=legacy,
        head_sha256=head, expected_head_sha256=expected_head_sha256, errors=errors,
    )


def verify_rebootstrap_audit_export(
    export: dict, *, operator_keyring: dict, publisher_keyring: dict,
    checkpoint_keyring: dict | None, expected_head_sha256: str | None = None,
) -> bool:
    """Strict boolean wrapper; legacy records are deliberately not accepted."""
    return verify_rebootstrap_audit_export_report(
        export, operator_keyring=operator_keyring, publisher_keyring=publisher_keyring,
        checkpoint_keyring=checkpoint_keyring, expected_head_sha256=expected_head_sha256,
    ).is_verified
