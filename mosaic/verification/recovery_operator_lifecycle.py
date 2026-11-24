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


class RecoveryOperatorLifecycleTrustAnchorStore:
    """SQLite CAS store for a deployment-pinned lifecycle checkpoint head.

    The initial anchor must be provisioned from an independent trusted source.
    SQLite transactions serialize writers sharing this database; they do not
    protect against privileged rollback of the database file itself.
    """
    def __init__(self, database_path: str):
        import sqlite3
        self._sqlite3 = sqlite3
        self._database_path = str(database_path)
        with self._connection() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS lifecycle_trust_anchor ("
                "registry_id TEXT PRIMARY KEY, sequence INTEGER NOT NULL, "
                "checkpoint_sha256 TEXT NOT NULL, updated_at_utc TEXT NOT NULL)"
            )

    def _connect(self):
        connection = self._sqlite3.connect(self._database_path, timeout=30, isolation_level=None)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    from contextlib import contextmanager as _contextmanager

    @_contextmanager
    def _connection(self):
        connection = self._connect()
        try:
            yield connection
        finally:
            connection.close()

    def provision(self, *, registry_id: str, sequence: int, checkpoint_sha256: str,
                  updated_at_utc: str) -> bool:
        """Insert an externally trusted starting anchor; never overwrite an existing one."""
        import re
        if (not isinstance(registry_id, str) or not registry_id
                or not isinstance(sequence, int) or sequence < 0
                or not isinstance(checkpoint_sha256, str)
                or re.fullmatch(r"[0-9a-f]{64}", checkpoint_sha256) is None):
            return False
        try:
            timestamp = _canonical_timestamp(updated_at_utc)
            if timestamp != updated_at_utc:
                return False
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                cursor = connection.execute(
                    "INSERT OR IGNORE INTO lifecycle_trust_anchor "
                    "(registry_id, sequence, checkpoint_sha256, updated_at_utc) VALUES (?, ?, ?, ?)",
                    (registry_id, sequence, checkpoint_sha256, timestamp))
                accepted = cursor.rowcount == 1
                connection.commit()
                return accepted
        except (ValueError, TypeError, self._sqlite3.Error):
            return False

    def read(self, registry_id: str) -> dict | None:
        try:
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT registry_id, sequence, checkpoint_sha256, updated_at_utc "
                    "FROM lifecycle_trust_anchor WHERE registry_id=?", (registry_id,)
                ).fetchone()
            if row is None:
                return None
            return {"registry_id": row[0], "sequence": row[1],
                    "checkpoint_sha256": row[2], "updated_at_utc": row[3]}
        except self._sqlite3.Error:
            return None

    def export_receipt(self, *, checkpoint: SignedOperatorLifecycleCheckpoint,
                       issued_at_utc: str, private_key: bytes) -> "SignedOperatorLifecycleTrustAnchorReceipt | None":
        """Sign a portable receipt only when the checkpoint is the retained store head."""
        if not isinstance(checkpoint, SignedOperatorLifecycleCheckpoint):
            return None
        try:
            head = self.read(checkpoint.registry_id)
            if (head is None or head["sequence"] != checkpoint.sequence
                    or head["checkpoint_sha256"] != checkpoint.digest()):
                return None
            return SignedOperatorLifecycleTrustAnchorReceipt.sign(
                checkpoint=checkpoint, issued_at_utc=issued_at_utc,
                private_key=private_key)
        except (ValueError, TypeError):
            return None

    def restore_receipt(self, receipt: "SignedOperatorLifecycleTrustAnchorReceipt",
                        checkpoint: SignedOperatorLifecycleCheckpoint, *,
                        authority_keyring: dict[str, PolicyPublisherKey],
                        expected_registry_id: str,
                        expected_checkpoint_sha256: str,
                        expected_sequence: int,
                        authorization_time_utc: str | None = None,
                        allow_initial: bool = False) -> bool:
        """Restore an externally pinned receipt into an empty store, or accept an exact replay.

        This deliberately does not advance an existing head. Advancing requires the
        complete predecessor checkpoint and the ordinary contiguous-advance verifier.
        """
        if not verify_operator_lifecycle_trust_anchor_receipt(
            receipt, checkpoint, authority_keyring=authority_keyring,
            expected_registry_id=expected_registry_id,
            expected_checkpoint_sha256=expected_checkpoint_sha256,
            expected_sequence=expected_sequence,
            authorization_time_utc=authorization_time_utc):
            return False
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT sequence, checkpoint_sha256 FROM lifecycle_trust_anchor WHERE registry_id=?",
                    (expected_registry_id,)
                ).fetchone()
                if row is not None:
                    accepted = (row[0] == expected_sequence
                                and row[1] == expected_checkpoint_sha256)
                    if accepted:
                        connection.commit()
                    else:
                        connection.rollback()
                    return accepted
                if not allow_initial:
                    connection.rollback()
                    return False
                cursor = connection.execute(
                    "INSERT INTO lifecycle_trust_anchor "
                    "(registry_id, sequence, checkpoint_sha256, updated_at_utc) VALUES (?, ?, ?, ?)",
                    (expected_registry_id, expected_sequence,
                     expected_checkpoint_sha256, receipt.issued_at_utc))
                if cursor.rowcount != 1:
                    connection.rollback()
                    return False
                connection.commit()
                return True
        except (ValueError, TypeError, self._sqlite3.Error):
            return False

    def restore_checkpoint_chain_bundle(
        self, bundle: "OperatorLifecycleCheckpointChainBundle",
        starting_checkpoint: SignedOperatorLifecycleCheckpoint, *,
        authority_keyring: dict[str, PolicyPublisherKey],
        expected_registry_id: str,
        expected_starting_checkpoint_sha256: str,
        expected_ending_checkpoint_sha256: str,
        expected_ending_sequence: int,
        authorization_time_utc: str | None = None,
        allow_initial: bool = False,
    ) -> bool:
        """Atomically restore a fully verified chain, advancing only its exact local head.

        Empty stores require explicit initial-import approval. Existing stores accept
        only an exact idempotent ending head or a chain whose supplied predecessor
        exactly matches the current local head. All writes are rechecked under
        BEGIN IMMEDIATE so concurrent changes cannot be overwritten.
        """
        if (not isinstance(bundle, OperatorLifecycleCheckpointChainBundle)
                or not isinstance(starting_checkpoint, SignedOperatorLifecycleCheckpoint)
                or not isinstance(expected_ending_checkpoint_sha256, str)
                or not isinstance(expected_ending_sequence, int)
                or expected_ending_sequence < 0):
            return False
        report = verify_operator_lifecycle_checkpoint_chain_bundle(
            bundle, starting_checkpoint, authority_keyring=authority_keyring,
            expected_registry_id=expected_registry_id,
            expected_starting_checkpoint_sha256=expected_starting_checkpoint_sha256,
            expected_ending_checkpoint_sha256=expected_ending_checkpoint_sha256,
            expected_ending_sequence=expected_ending_sequence,
            authorization_time_utc=authorization_time_utc)
        if not report.accepted:
            return False
        ending = bundle.checkpoints[-1]
        try:
            timestamp = _canonical_timestamp(ending.issued_at_utc)
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT sequence, checkpoint_sha256 FROM lifecycle_trust_anchor WHERE registry_id=?",
                    (expected_registry_id,)
                ).fetchone()
                if row is None:
                    if not allow_initial:
                        connection.rollback()
                        return False
                    cursor = connection.execute(
                        "INSERT INTO lifecycle_trust_anchor "
                        "(registry_id, sequence, checkpoint_sha256, updated_at_utc) VALUES (?, ?, ?, ?)",
                        (expected_registry_id, ending.sequence, ending.digest(), timestamp))
                    if cursor.rowcount != 1:
                        connection.rollback()
                        return False
                    connection.commit()
                    return True

                # An exact replay is safe and idempotent, even when its verified
                # bundle starts earlier than the already-retained final head.
                if row[0] == expected_ending_sequence and row[1] == expected_ending_checkpoint_sha256:
                    connection.commit()
                    return True

                # Never overwrite a newer head, a fork, or a stale predecessor.
                if (row[0] != starting_checkpoint.sequence
                        or row[1] != expected_starting_checkpoint_sha256
                        or ending.sequence <= row[0]):
                    connection.rollback()
                    return False
                cursor = connection.execute(
                    "UPDATE lifecycle_trust_anchor SET sequence=?, checkpoint_sha256=?, updated_at_utc=? "
                    "WHERE registry_id=? AND sequence=? AND checkpoint_sha256=?",
                    (ending.sequence, ending.digest(), timestamp, expected_registry_id,
                     starting_checkpoint.sequence, expected_starting_checkpoint_sha256))
                if cursor.rowcount != 1:
                    connection.rollback()
                    return False
                connection.commit()
                return True
        except (ValueError, TypeError, self._sqlite3.Error):
            return False

    def restore_checkpoint_chain_bundle_with_receipt(
        self, bundle: "OperatorLifecycleCheckpointChainBundle",
        starting_checkpoint: SignedOperatorLifecycleCheckpoint, *,
        authority_keyring: dict[str, PolicyPublisherKey],
        expected_registry_id: str,
        expected_starting_checkpoint_sha256: str,
        expected_ending_checkpoint_sha256: str,
        expected_ending_sequence: int,
        issued_at_utc: str,
        receipt_private_key: bytes,
        authorization_time_utc: str | None = None,
        allow_initial: bool = False,
    ) -> "SignedOperatorLifecycleCheckpointChainRestoreReceipt | None":
        """Restore a verified bundle and return a signed receipt only on success."""
        if not isinstance(bundle, OperatorLifecycleCheckpointChainBundle):
            return None
        report = verify_operator_lifecycle_checkpoint_chain_bundle(
            bundle, starting_checkpoint, authority_keyring=authority_keyring,
            expected_registry_id=expected_registry_id,
            expected_starting_checkpoint_sha256=expected_starting_checkpoint_sha256,
            expected_ending_checkpoint_sha256=expected_ending_checkpoint_sha256,
            expected_ending_sequence=expected_ending_sequence,
            authorization_time_utc=authorization_time_utc)
        if not report.accepted:
            return None
        try:
            receipt = SignedOperatorLifecycleCheckpointChainRestoreReceipt.sign(
                bundle=bundle, report=report, issued_at_utc=issued_at_utc,
                private_key=receipt_private_key)
        except (ValueError, TypeError):
            return None
        if not verify_operator_lifecycle_checkpoint_chain_restore_receipt(
            receipt, bundle, starting_checkpoint,
            authority_keyring=authority_keyring,
            expected_registry_id=expected_registry_id,
            expected_starting_checkpoint_sha256=expected_starting_checkpoint_sha256,
            expected_ending_checkpoint_sha256=expected_ending_checkpoint_sha256,
            expected_ending_sequence=expected_ending_sequence,
            authorization_time_utc=authorization_time_utc):
            return None
        if not self.restore_checkpoint_chain_bundle(
            bundle, starting_checkpoint, authority_keyring=authority_keyring,
            expected_registry_id=expected_registry_id,
            expected_starting_checkpoint_sha256=expected_starting_checkpoint_sha256,
            expected_ending_checkpoint_sha256=expected_ending_checkpoint_sha256,
            expected_ending_sequence=expected_ending_sequence,
            authorization_time_utc=authorization_time_utc,
            allow_initial=allow_initial):
            return None
        return receipt

    def advance(self, previous: SignedOperatorLifecycleCheckpoint,
                candidate: SignedOperatorLifecycleCheckpoint, *,
                authority_keyring: dict[str, PolicyPublisherKey],
                expected_current_sha256: str,
                authorization_time_utc: str | None = None) -> OperatorLifecycleCheckpointAdvanceReport:
        """Verify and atomically compare-and-swap the current anchor to candidate."""
        fallback = "0" * 64
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT sequence, checkpoint_sha256 FROM lifecycle_trust_anchor WHERE registry_id=?",
                    (previous.registry_id,)
                ).fetchone()
                if row is None or row[1] != expected_current_sha256 or row[1] != previous.digest() or row[0] != previous.sequence:
                    connection.rollback()
                    return OperatorLifecycleCheckpointAdvanceReport(
                        accepted=False, previous_sequence=previous.sequence,
                        candidate_sequence=candidate.sequence, previous_sha256=previous.digest(),
                        candidate_sha256=candidate.digest(), errors=("stored_anchor_compare_failed",))
                report = verify_operator_lifecycle_checkpoint_advance(
                    previous, candidate, authority_keyring=authority_keyring,
                    expected_previous_sha256=expected_current_sha256,
                    expected_registry_id=previous.registry_id,
                    authorization_time_utc=authorization_time_utc)
                if not report.accepted:
                    connection.rollback()
                    return report
                timestamp = _canonical_timestamp(candidate.issued_at_utc)
                connection.execute(
                    "UPDATE lifecycle_trust_anchor SET sequence=?, checkpoint_sha256=?, updated_at_utc=? "
                    "WHERE registry_id=? AND sequence=? AND checkpoint_sha256=?",
                    (candidate.sequence, candidate.digest(), timestamp, previous.registry_id,
                     previous.sequence, expected_current_sha256))
                if connection.total_changes != 1:
                    connection.rollback()
                    return OperatorLifecycleCheckpointAdvanceReport(
                        accepted=False, previous_sequence=previous.sequence,
                        candidate_sequence=candidate.sequence, previous_sha256=previous.digest(),
                        candidate_sha256=candidate.digest(), errors=("compare_and_swap_failed",))
                connection.commit()
                return report
        except (ValueError, TypeError, self._sqlite3.Error):
            return OperatorLifecycleCheckpointAdvanceReport(
                accepted=False,
                previous_sequence=previous.sequence if isinstance(previous, SignedOperatorLifecycleCheckpoint) else 0,
                candidate_sequence=candidate.sequence if isinstance(candidate, SignedOperatorLifecycleCheckpoint) else 0,
                previous_sha256=previous.digest() if isinstance(previous, SignedOperatorLifecycleCheckpoint) else fallback,
                candidate_sha256=candidate.digest() if isinstance(candidate, SignedOperatorLifecycleCheckpoint) else fallback,
                errors=("anchor_store_error",))


class SignedOperatorLifecycleTrustAnchorReceipt(BaseModel):
    """Portable authority-signed attestation of one lifecycle checkpoint head."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["1.0"] = "1.0"
    registry_id: str = Field(min_length=1, max_length=200)
    sequence: int = Field(ge=0)
    checkpoint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    authority_key_id: str = Field(min_length=1, max_length=160)
    issued_at_utc: str = Field(min_length=20, max_length=40)
    signature_b64: str = Field(min_length=1, max_length=128)

    @classmethod
    def sign(cls, *, checkpoint: SignedOperatorLifecycleCheckpoint,
             issued_at_utc: str, private_key: bytes) -> "SignedOperatorLifecycleTrustAnchorReceipt":
        if not isinstance(checkpoint, SignedOperatorLifecycleCheckpoint):
            raise ValueError("a lifecycle checkpoint is required")
        if not isinstance(private_key, bytes) or len(private_key) != 32:
            raise ValueError("Ed25519 private key must be exactly 32 raw bytes")
        payload = {
            "schema_version": "1.0", "registry_id": checkpoint.registry_id,
            "sequence": checkpoint.sequence, "checkpoint_sha256": checkpoint.digest(),
            "authority_key_id": checkpoint.authority_key_id,
            "issued_at_utc": _canonical_timestamp(issued_at_utc),
        }
        signature = Ed25519PrivateKey.from_private_bytes(private_key).sign(_canonical(payload))
        return cls(**payload, signature_b64=base64.b64encode(signature).decode("ascii"))

    def digest(self) -> str:
        return hashlib.sha256(_canonical(self.model_dump(mode="json"))).hexdigest()


def verify_operator_lifecycle_trust_anchor_receipt(
    receipt: SignedOperatorLifecycleTrustAnchorReceipt,
    checkpoint: SignedOperatorLifecycleCheckpoint, *,
    authority_keyring: dict[str, PolicyPublisherKey],
    expected_registry_id: str,
    expected_checkpoint_sha256: str,
    expected_sequence: int | None = None,
    authorization_time_utc: str | None = None,
) -> bool:
    """Verify portable receipt signature and its binding to the signed checkpoint."""
    if (not isinstance(receipt, SignedOperatorLifecycleTrustAnchorReceipt)
            or not isinstance(checkpoint, SignedOperatorLifecycleCheckpoint)):
        return False
    authority = authority_keyring.get(receipt.authority_key_id) if isinstance(authority_keyring, dict) else None
    if (authority is None or receipt.registry_id != expected_registry_id
            or receipt.authority_key_id != checkpoint.authority_key_id
            or receipt.registry_id != checkpoint.registry_id
            or receipt.sequence != checkpoint.sequence
            or (expected_sequence is not None and receipt.sequence != expected_sequence)
            or receipt.checkpoint_sha256 != checkpoint.digest()
            or receipt.checkpoint_sha256 != expected_checkpoint_sha256
            or not authority.permits(receipt.authority_key_id, receipt.issued_at_utc)
            or not verify_operator_lifecycle_checkpoint(
                checkpoint, authority_keyring=authority_keyring,
                expected_registry_id=expected_registry_id,
                expected_sequence=expected_sequence,
                expected_checkpoint_sha256=expected_checkpoint_sha256,
                authorization_time_utc=authorization_time_utc)):
        return False
    try:
        if _canonical_timestamp(receipt.issued_at_utc) != receipt.issued_at_utc:
            return False
        if authorization_time_utc is not None:
            if _canonical_timestamp(authorization_time_utc) != authorization_time_utc:
                return False
            if authorization_time_utc < receipt.issued_at_utc:
                return False
        signature = base64.b64decode(receipt.signature_b64, validate=True)
        if len(signature) != 64:
            return False
        payload = receipt.model_dump(mode="json", exclude={"signature_b64"})
        Ed25519PublicKey.from_public_bytes(authority.public_key()).verify(signature, _canonical(payload))
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False


class OperatorLifecycleCheckpointChainBundle(BaseModel):
    """Portable contiguous checkpoint suffix anchored to a separately held predecessor."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["1.0"] = "1.0"
    registry_id: str = Field(min_length=1, max_length=200)
    starting_sequence: int = Field(ge=0)
    starting_checkpoint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    checkpoints: tuple[SignedOperatorLifecycleCheckpoint, ...] = Field(min_length=1)

    @classmethod
    def from_checkpoints(
        cls, *, starting_checkpoint: SignedOperatorLifecycleCheckpoint,
        checkpoints: list[SignedOperatorLifecycleCheckpoint],
    ) -> "OperatorLifecycleCheckpointChainBundle":
        if not isinstance(starting_checkpoint, SignedOperatorLifecycleCheckpoint):
            raise ValueError("a signed starting checkpoint is required")
        return cls(
            registry_id=starting_checkpoint.registry_id,
            starting_sequence=starting_checkpoint.sequence,
            starting_checkpoint_sha256=starting_checkpoint.digest(),
            checkpoints=tuple(checkpoints),
        )

    def digest(self) -> str:
        return hashlib.sha256(_canonical(self.model_dump(mode="json"))).hexdigest()


class OperatorLifecycleCheckpointChainReport(BaseModel):
    """Deterministic verification result for a portable checkpoint-chain bundle."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    accepted: bool
    registry_id: str
    starting_sequence: int = Field(ge=0)
    ending_sequence: int = Field(ge=0)
    starting_checkpoint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    ending_checkpoint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    verified_transitions: int = Field(ge=0)
    errors: tuple[str, ...] = ()


def verify_operator_lifecycle_checkpoint_chain_bundle(
    bundle: OperatorLifecycleCheckpointChainBundle,
    starting_checkpoint: SignedOperatorLifecycleCheckpoint, *,
    authority_keyring: dict[str, PolicyPublisherKey],
    expected_registry_id: str,
    expected_starting_checkpoint_sha256: str,
    expected_ending_checkpoint_sha256: str | None = None,
    expected_ending_sequence: int | None = None,
    authorization_time_utc: str | None = None,
) -> OperatorLifecycleCheckpointChainReport:
    """Verify every contiguous signed transition from an external pinned checkpoint."""
    errors: list[str] = []
    valid_start = isinstance(starting_checkpoint, SignedOperatorLifecycleCheckpoint)
    start_digest = starting_checkpoint.digest() if valid_start else "0" * 64
    start_sequence = starting_checkpoint.sequence if valid_start else 0
    if not isinstance(bundle, OperatorLifecycleCheckpointChainBundle):
        errors.append("bundle_invalid")
    else:
        if bundle.registry_id != expected_registry_id:
            errors.append("bundle_registry_mismatch")
        if bundle.registry_id != (starting_checkpoint.registry_id if valid_start else None):
            errors.append("starting_registry_mismatch")
        if bundle.starting_sequence != start_sequence:
            errors.append("starting_sequence_mismatch")
        if bundle.starting_checkpoint_sha256 != expected_starting_checkpoint_sha256:
            errors.append("external_start_anchor_mismatch")
        if bundle.starting_checkpoint_sha256 != start_digest:
            errors.append("starting_checkpoint_digest_mismatch")
    if not valid_start:
        errors.append("starting_checkpoint_invalid")
    elif start_digest != expected_starting_checkpoint_sha256:
        errors.append("starting_checkpoint_anchor_mismatch")
    elif not verify_operator_lifecycle_checkpoint(
        starting_checkpoint, authority_keyring=authority_keyring,
        expected_registry_id=expected_registry_id,
        expected_checkpoint_sha256=expected_starting_checkpoint_sha256,
        authorization_time_utc=authorization_time_utc,
    ):
        errors.append("starting_checkpoint_signature_or_policy_invalid")

    current = starting_checkpoint if valid_start else None
    verified = 0
    if isinstance(bundle, OperatorLifecycleCheckpointChainBundle) and valid_start:
        for index, candidate in enumerate(bundle.checkpoints):
            if errors:
                break
            step = verify_operator_lifecycle_checkpoint_advance(
                current, candidate, authority_keyring=authority_keyring,
                expected_previous_sha256=current.digest(),
                expected_registry_id=expected_registry_id,
                authorization_time_utc=authorization_time_utc,
            )
            if not step.accepted:
                errors.extend(f"transition_{index}:{item}" for item in step.errors)
                break
            current = candidate
            verified += 1
    end_digest = current.digest() if isinstance(current, SignedOperatorLifecycleCheckpoint) else "0" * 64
    end_sequence = current.sequence if isinstance(current, SignedOperatorLifecycleCheckpoint) else start_sequence
    if expected_ending_checkpoint_sha256 is not None and end_digest != expected_ending_checkpoint_sha256:
        errors.append("external_end_anchor_mismatch")
    if expected_ending_sequence is not None and end_sequence != expected_ending_sequence:
        errors.append("ending_sequence_mismatch")
    return OperatorLifecycleCheckpointChainReport(
        accepted=not errors and verified == (len(bundle.checkpoints) if isinstance(bundle, OperatorLifecycleCheckpointChainBundle) else 0),
        registry_id=expected_registry_id,
        starting_sequence=start_sequence,
        ending_sequence=end_sequence,
        starting_checkpoint_sha256=start_digest,
        ending_checkpoint_sha256=end_digest,
        verified_transitions=verified,
        errors=tuple(dict.fromkeys(errors)),
    )



class SignedOperatorLifecycleCheckpointChainRestoreReceipt(BaseModel):
    """Authority-signed record of a successfully restored verified chain bundle."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["1.0"] = "1.0"
    registry_id: str = Field(min_length=1, max_length=200)
    bundle_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    starting_sequence: int = Field(ge=0)
    starting_checkpoint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    ending_sequence: int = Field(ge=0)
    ending_checkpoint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    verified_transitions: int = Field(ge=1)
    authority_key_id: str = Field(min_length=1, max_length=160)
    issued_at_utc: str = Field(min_length=20, max_length=40)
    signature_b64: str = Field(min_length=1, max_length=128)

    @classmethod
    def sign(cls, *, bundle: "OperatorLifecycleCheckpointChainBundle",
             report: "OperatorLifecycleCheckpointChainReport",
             issued_at_utc: str, private_key: bytes) -> "SignedOperatorLifecycleCheckpointChainRestoreReceipt":
        if (not isinstance(bundle, OperatorLifecycleCheckpointChainBundle)
                or not isinstance(report, OperatorLifecycleCheckpointChainReport)
                or not report.accepted or not bundle.checkpoints):
            raise ValueError("a fully verified checkpoint-chain bundle is required")
        if not isinstance(private_key, bytes) or len(private_key) != 32:
            raise ValueError("Ed25519 private key must be exactly 32 raw bytes")
        payload = {
            "schema_version": "1.0", "registry_id": report.registry_id,
            "bundle_sha256": bundle.digest(),
            "starting_sequence": report.starting_sequence,
            "starting_checkpoint_sha256": report.starting_checkpoint_sha256,
            "ending_sequence": report.ending_sequence,
            "ending_checkpoint_sha256": report.ending_checkpoint_sha256,
            "verified_transitions": report.verified_transitions,
            "authority_key_id": bundle.checkpoints[-1].authority_key_id,
            "issued_at_utc": _canonical_timestamp(issued_at_utc),
        }
        signature = Ed25519PrivateKey.from_private_bytes(private_key).sign(_canonical(payload))
        return cls(**payload, signature_b64=base64.b64encode(signature).decode("ascii"))

    def digest(self) -> str:
        return hashlib.sha256(_canonical(self.model_dump(mode="json"))).hexdigest()


def verify_operator_lifecycle_checkpoint_chain_restore_receipt(
    receipt: SignedOperatorLifecycleCheckpointChainRestoreReceipt,
    bundle: "OperatorLifecycleCheckpointChainBundle",
    starting_checkpoint: SignedOperatorLifecycleCheckpoint, *,
    authority_keyring: dict[str, PolicyPublisherKey],
    expected_registry_id: str,
    expected_starting_checkpoint_sha256: str,
    expected_ending_checkpoint_sha256: str,
    expected_ending_sequence: int,
    authorization_time_utc: str | None = None,
) -> bool:
    """Independently verify receipt signature, bundle binding, and every chain step."""
    if (not isinstance(receipt, SignedOperatorLifecycleCheckpointChainRestoreReceipt)
            or not isinstance(bundle, OperatorLifecycleCheckpointChainBundle)):
        return False
    report = verify_operator_lifecycle_checkpoint_chain_bundle(
        bundle, starting_checkpoint, authority_keyring=authority_keyring,
        expected_registry_id=expected_registry_id,
        expected_starting_checkpoint_sha256=expected_starting_checkpoint_sha256,
        expected_ending_checkpoint_sha256=expected_ending_checkpoint_sha256,
        expected_ending_sequence=expected_ending_sequence,
        authorization_time_utc=authorization_time_utc)
    authority = authority_keyring.get(receipt.authority_key_id) if isinstance(authority_keyring, dict) else None
    if (not report.accepted or authority is None
            or receipt.registry_id != report.registry_id
            or receipt.bundle_sha256 != bundle.digest()
            or receipt.starting_sequence != report.starting_sequence
            or receipt.starting_checkpoint_sha256 != report.starting_checkpoint_sha256
            or receipt.ending_sequence != report.ending_sequence
            or receipt.ending_checkpoint_sha256 != report.ending_checkpoint_sha256
            or receipt.verified_transitions != report.verified_transitions
            or not bundle.checkpoints
            or receipt.authority_key_id != bundle.checkpoints[-1].authority_key_id
            or receipt.issued_at_utc < bundle.checkpoints[-1].issued_at_utc
            or not authority.permits(receipt.authority_key_id, receipt.issued_at_utc)):
        return False
    try:
        if _canonical_timestamp(receipt.issued_at_utc) != receipt.issued_at_utc:
            return False
        if authorization_time_utc is not None:
            if _canonical_timestamp(authorization_time_utc) != authorization_time_utc:
                return False
            if authorization_time_utc < receipt.issued_at_utc:
                return False
        signature = base64.b64decode(receipt.signature_b64, validate=True)
        if len(signature) != 64:
            return False
        payload = receipt.model_dump(mode="json", exclude={"signature_b64"})
        Ed25519PublicKey.from_public_bytes(authority.public_key()).verify(signature, _canonical(payload))
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False


