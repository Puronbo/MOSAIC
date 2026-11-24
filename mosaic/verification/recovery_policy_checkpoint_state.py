"""Durable monotonic state for trusted recovery-policy registry checkpoints."""
from __future__ import annotations

import hashlib
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from mosaic.verification.policy_witness_recovery_policy_registry import (
    SignedPolicyWitnessRecoveryPolicyCheckpoint,
    SignedPolicyWitnessRecoveryPolicyEntry,
    verify_policy_witness_recovery_policy_registry,
)


class RecoveryPolicyCheckpointStore:
    """Locally pins a recovery-policy head and refuses silent rollback/equivocation.

    Initial pinning is an explicit trust-on-first-use operation. Deployments
    should bootstrap it from an independently authenticated checkpoint.
    """

    def __init__(self, database_path: str | Path):
        self.database_path = str(database_path)
        if self.database_path != ":memory:":
            Path(self.database_path).parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS recovery_policy_heads (
                    registry_id TEXT PRIMARY KEY,
                    checkpoint_json TEXT NOT NULL,
                    checkpoint_sha256 TEXT NOT NULL,
                    quarantined INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS recovery_policy_history (
                    registry_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    checkpoint_sha256 TEXT NOT NULL,
                    checkpoint_json TEXT NOT NULL,
                    PRIMARY KEY (registry_id, sequence)
                );
                CREATE TABLE IF NOT EXISTS recovery_policy_incidents (
                    incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    registry_id TEXT NOT NULL,
                    retained_checkpoint_sha256 TEXT,
                    presented_checkpoint_sha256 TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    observed_at_utc TEXT NOT NULL DEFAULT
                      (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
                );
            """)

    @contextmanager
    def _connection(self):
        db = sqlite3.connect(self.database_path, timeout=30, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA synchronous=FULL")
            yield db
        finally:
            db.close()

    @staticmethod
    def _verify(entries, checkpoint, publisher_keyring, checkpoint_keyring):
        return (
            isinstance(entries, list) and bool(entries)
            and isinstance(checkpoint, SignedPolicyWitnessRecoveryPolicyCheckpoint)
            and verify_policy_witness_recovery_policy_registry(
                entries, publisher_keyring=publisher_keyring,
                trusted_checkpoint=checkpoint,
                checkpoint_keyring=checkpoint_keyring,
            )
        )

    def pin_checkpoint(self, entries: list[SignedPolicyWitnessRecoveryPolicyEntry], *,
                       checkpoint: SignedPolicyWitnessRecoveryPolicyCheckpoint,
                       publisher_keyring: dict, checkpoint_keyring: dict | None = None) -> bool:
        """Explicitly pin a verified checkpoint, or monotonically advance its head."""
        if not self._verify(entries, checkpoint, publisher_keyring, checkpoint_keyring):
            return False
        digest = checkpoint.model_dump_json()
        checkpoint_hash = hashlib.sha256(digest.encode("utf-8")).hexdigest()
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT checkpoint_json, checkpoint_sha256, quarantined FROM recovery_policy_heads WHERE registry_id=?",
                (checkpoint.registry_id,),
            ).fetchone()
            if row is None:
                db.execute(
                    "INSERT INTO recovery_policy_heads VALUES (?, ?, ?, 0)",
                    (checkpoint.registry_id, digest, checkpoint_hash),
                )
                db.execute(
                    "INSERT INTO recovery_policy_history VALUES (?, ?, ?, ?)",
                    (checkpoint.registry_id, checkpoint.sequence, checkpoint_hash, digest),
                )
                db.commit()
                return True
            retained = SignedPolicyWitnessRecoveryPolicyCheckpoint.model_validate_json(row["checkpoint_json"])
            if row["quarantined"]:
                db.rollback()
                return False
            if checkpoint.sequence < retained.sequence:
                db.execute(
                    "INSERT INTO recovery_policy_incidents (registry_id, retained_checkpoint_sha256, presented_checkpoint_sha256, reason) VALUES (?, ?, ?, ?)",
                    (checkpoint.registry_id, row["checkpoint_sha256"], checkpoint_hash, "rollback_attempt"),
                )
                db.commit()
                return False
            if checkpoint.sequence == retained.sequence:
                if checkpoint_hash == row["checkpoint_sha256"]:
                    db.commit()
                    return True
                db.execute(
                    "UPDATE recovery_policy_heads SET quarantined=1 WHERE registry_id=?",
                    (checkpoint.registry_id,),
                )
                db.execute(
                    "INSERT INTO recovery_policy_incidents (registry_id, retained_checkpoint_sha256, presented_checkpoint_sha256, reason) VALUES (?, ?, ?, ?)",
                    (checkpoint.registry_id, row["checkpoint_sha256"], checkpoint_hash, "same_sequence_equivocation"),
                )
                db.commit()
                return False
            # A higher signed sequence is accepted only if every retained
            # sequence remains an exact prefix of the newly verified registry.
            retained_rows = db.execute(
                "SELECT sequence, checkpoint_json FROM recovery_policy_history WHERE registry_id=? ORDER BY sequence",
                (checkpoint.registry_id,),
            ).fetchall()
            for history_row in retained_rows:
                seq = history_row["sequence"]
                if seq >= len(entries) or entries[seq].digest() != SignedPolicyWitnessRecoveryPolicyCheckpoint.model_validate_json(history_row["checkpoint_json"]).entry_sha256:
                    db.execute(
                        "UPDATE recovery_policy_heads SET quarantined=1 WHERE registry_id=?",
                        (checkpoint.registry_id,),
                    )
                    db.execute(
                        "INSERT INTO recovery_policy_incidents (registry_id, retained_checkpoint_sha256, presented_checkpoint_sha256, reason) VALUES (?, ?, ?, ?)",
                        (checkpoint.registry_id, row["checkpoint_sha256"], checkpoint_hash, "history_divergence"),
                    )
                    db.commit()
                    return False
            db.execute(
                "UPDATE recovery_policy_heads SET checkpoint_json=?, checkpoint_sha256=? WHERE registry_id=?",
                (digest, checkpoint_hash, checkpoint.registry_id),
            )
            db.execute(
                "INSERT OR REPLACE INTO recovery_policy_history VALUES (?, ?, ?, ?)",
                (checkpoint.registry_id, checkpoint.sequence, checkpoint_hash, digest),
            )
            db.commit()
            return True

    def matches_trusted_checkpoint(self, checkpoint: SignedPolicyWitnessRecoveryPolicyCheckpoint) -> bool:
        if not isinstance(checkpoint, SignedPolicyWitnessRecoveryPolicyCheckpoint):
            return False
        with self._connection() as db:
            row = db.execute(
                "SELECT checkpoint_sha256, quarantined FROM recovery_policy_heads WHERE registry_id=?",
                (checkpoint.registry_id,),
            ).fetchone()
        if row is None or row["quarantined"]:
            return False
        expected = hashlib.sha256(checkpoint.model_dump_json().encode("utf-8")).hexdigest()
        return expected == row["checkpoint_sha256"]

    def is_quarantined(self, registry_id: str) -> bool:
        with self._connection() as db:
            row = db.execute(
                "SELECT quarantined FROM recovery_policy_heads WHERE registry_id=?",
                (registry_id,),
            ).fetchone()
        return bool(row["quarantined"]) if row else False

    def incidents(self, registry_id: str) -> list[dict]:
        with self._connection() as db:
            rows = db.execute(
                "SELECT registry_id, retained_checkpoint_sha256, presented_checkpoint_sha256, reason, observed_at_utc FROM recovery_policy_incidents WHERE registry_id=? ORDER BY incident_id",
                (registry_id,),
            ).fetchall()
        return [dict(row) for row in rows]
