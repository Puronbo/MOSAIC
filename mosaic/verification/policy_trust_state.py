"""Durable local trust-state for policy-registry checkpoints.

SQLite transactions and FULL synchronous commits protect the local checkpoint
state across process restarts. This is a local persistence primitive, not a
hardware monotonic counter or distributed consensus service.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from mosaic.verification.lean_runner_signature import _canonical
from mosaic.verification.policy_governance import PolicyPublisherKey
from mosaic.verification.policy_registry import SignedPolicyRegistryEntry
from mosaic.verification.policy_transparency import (
    PolicyCheckpointWitness,
    PolicyRegistryCheckpoint,
    verify_policy_checkpoint,
)


class PolicyTrustStateError(RuntimeError):
    """Raised when trust state is quarantined or cannot safely advance."""


class PolicyCheckpointStore:
    """SQLite-backed checkpoint store with atomic compare-and-advance semantics.

    Keep the database on durable local storage and protect it from untrusted
    writers. Backups must preserve the database and its audit tables together.
    """

    def __init__(self, database_path: str | Path):
        self.database_path = str(database_path)
        if self.database_path != ":memory:":
            Path(self.database_path).parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @contextmanager
    def _connection(self):
        connection = sqlite3.connect(self.database_path, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA synchronous=FULL")
            yield connection
        finally:
            connection.close()

    def _initialize(self):
        with self._connection() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS policy_trust_heads (
                    log_id TEXT PRIMARY KEY,
                    checkpoint_json TEXT NOT NULL,
                    checkpoint_sha256 TEXT NOT NULL,
                    quarantined INTEGER NOT NULL DEFAULT 0,
                    updated_at_utc TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS policy_checkpoint_history (
                    log_id TEXT NOT NULL,
                    checkpoint_sha256 TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    checkpoint_json TEXT NOT NULL,
                    accepted INTEGER NOT NULL,
                    observed_at_utc TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                    PRIMARY KEY (log_id, checkpoint_sha256)
                );
                CREATE TABLE IF NOT EXISTS policy_trust_incidents (
                    incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    log_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    existing_head_sha256 TEXT NOT NULL,
                    conflicting_head_sha256 TEXT NOT NULL,
                    checkpoint_sha256 TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    observed_at_utc TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
                );
            """)

    @staticmethod
    def _json(checkpoint: PolicyRegistryCheckpoint) -> str:
        return _canonical(checkpoint.model_dump(mode="json")).decode("utf-8")

    @staticmethod
    def _decode(value: str) -> PolicyRegistryCheckpoint:
        return PolicyRegistryCheckpoint.model_validate_json(value)

    def get_head(self, log_id: str) -> PolicyRegistryCheckpoint | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT checkpoint_json FROM policy_trust_heads WHERE log_id=?",
                (log_id,),
            ).fetchone()
        return self._decode(row["checkpoint_json"]) if row else None

    def is_quarantined(self, log_id: str) -> bool:
        with self._connect() as db:
            row = db.execute(
                "SELECT quarantined FROM policy_trust_heads WHERE log_id=?", (log_id,)
            ).fetchone()
        return bool(row["quarantined"]) if row else False

    def incidents(self, log_id: str) -> list[dict]:
        with self._connect() as db:
            rows = db.execute(
                """SELECT log_id, sequence, existing_head_sha256,
                   conflicting_head_sha256, checkpoint_sha256, reason, observed_at_utc
                   FROM policy_trust_incidents WHERE log_id=? ORDER BY incident_id""",
                (log_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def accept_checkpoint(
        self,
        checkpoint: PolicyRegistryCheckpoint,
        *,
        entries: list[SignedPolicyRegistryEntry],
        signer_keyring: dict[str, PolicyPublisherKey],
        witnesses: list[PolicyCheckpointWitness] | None = None,
        witness_keyring: dict[str, PolicyPublisherKey] | None = None,
        minimum_witnesses: int = 0,
    ) -> bool:
        """Verify and atomically advance; return False for invalid/replayed input.

        A valid same-sequence/different-head checkpoint creates a durable
        incident and quarantines the log. No automatic overwrite is possible.
        """
        if not isinstance(checkpoint, PolicyRegistryCheckpoint):
            return False
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM policy_trust_heads WHERE log_id=?", (checkpoint.log_id,)
            ).fetchone()
            if row and row["quarantined"]:
                db.rollback()
                return False
            previous = self._decode(row["checkpoint_json"]) if row else None

            if previous and checkpoint.sequence == previous.sequence:
                if (checkpoint.head_entry_sha256 != previous.head_entry_sha256
                        and checkpoint.verify_signature(signer_keyring)):
                    db.execute(
                        """INSERT INTO policy_trust_incidents
                        (log_id, sequence, existing_head_sha256,
                         conflicting_head_sha256, checkpoint_sha256, reason)
                        VALUES (?, ?, ?, ?, ?, ?)""",
                        (checkpoint.log_id, checkpoint.sequence,
                         previous.head_entry_sha256, checkpoint.head_entry_sha256,
                         checkpoint.digest(), "same-sequence conflicting signed head"),
                    )
                    db.execute(
                        "UPDATE policy_trust_heads SET quarantined=1 WHERE log_id=?",
                        (checkpoint.log_id,),
                    )
                    db.execute(
                        """INSERT OR IGNORE INTO policy_checkpoint_history
                        (log_id, checkpoint_sha256, sequence, checkpoint_json, accepted)
                        VALUES (?, ?, ?, ?, 0)""",
                        (checkpoint.log_id, checkpoint.digest(), checkpoint.sequence,
                         self._json(checkpoint)),
                    )
                    db.commit()
                else:
                    db.rollback()
                return False

            valid = verify_policy_checkpoint(
                checkpoint, entries=entries, signer_keyring=signer_keyring,
                witnesses=witnesses, witness_keyring=witness_keyring,
                minimum_witnesses=minimum_witnesses,
                previous_checkpoint=previous,
            )
            if not valid:
                db.rollback()
                return False
            encoded = self._json(checkpoint)
            digest = checkpoint.digest()
            db.execute(
                """INSERT OR IGNORE INTO policy_checkpoint_history
                (log_id, checkpoint_sha256, sequence, checkpoint_json, accepted)
                VALUES (?, ?, ?, ?, 1)""",
                (checkpoint.log_id, digest, checkpoint.sequence, encoded),
            )
            db.execute(
                """INSERT INTO policy_trust_heads
                (log_id, checkpoint_json, checkpoint_sha256, quarantined, updated_at_utc)
                VALUES (?, ?, ?, 0, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
                ON CONFLICT(log_id) DO UPDATE SET
                  checkpoint_json=excluded.checkpoint_json,
                  checkpoint_sha256=excluded.checkpoint_sha256,
                  updated_at_utc=excluded.updated_at_utc""",
                (checkpoint.log_id, encoded, digest),
            )
            db.commit()
            return True

    def recover_from_conflict(
        self,
        checkpoint: PolicyRegistryCheckpoint,
        *,
        entries: list[SignedPolicyRegistryEntry],
        signer_keyring: dict[str, PolicyPublisherKey],
        operator_reason: str,
        operator_confirmed: bool,
        witnesses: list[PolicyCheckpointWitness] | None = None,
        witness_keyring: dict[str, PolicyPublisherKey] | None = None,
        minimum_witnesses: int = 0,
    ) -> bool:
        """Explicitly select a verified genesis-rooted view after quarantine.

        This recovery intentionally requires full registry history and a
        checkpoint whose own previous-checkpoint pointer is null. It does not
        infer which fork is truthful; the operator's external investigation
        must decide which view to trust.
        """
        if (operator_confirmed is not True or not isinstance(operator_reason, str)
                or not operator_reason.strip() or not isinstance(checkpoint, PolicyRegistryCheckpoint)
                or checkpoint.previous_checkpoint_sha256 is not None):
            return False
        if not verify_policy_checkpoint(
            checkpoint, entries=entries, signer_keyring=signer_keyring,
            witnesses=witnesses, witness_keyring=witness_keyring,
            minimum_witnesses=minimum_witnesses,
        ):
            return False
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT quarantined, checkpoint_json FROM policy_trust_heads WHERE log_id=?",
                (checkpoint.log_id,),
            ).fetchone()
            if row is None or not row["quarantined"]:
                db.rollback()
                return False
            encoded = self._json(checkpoint)
            digest = checkpoint.digest()
            db.execute(
                """INSERT OR IGNORE INTO policy_checkpoint_history
                (log_id, checkpoint_sha256, sequence, checkpoint_json, accepted)
                VALUES (?, ?, ?, ?, 1)""",
                (checkpoint.log_id, digest, checkpoint.sequence, encoded),
            )
            db.execute(
                """UPDATE policy_trust_heads SET checkpoint_json=?,
                   checkpoint_sha256=?, quarantined=0,
                   updated_at_utc=strftime('%Y-%m-%dT%H:%M:%fZ','now')
                   WHERE log_id=?""",
                (encoded, digest, checkpoint.log_id),
            )
            db.execute(
                """INSERT INTO policy_trust_incidents
                (log_id, sequence, existing_head_sha256, conflicting_head_sha256,
                 checkpoint_sha256, reason)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (checkpoint.log_id, checkpoint.sequence,
                 self._decode(row["checkpoint_json"]).head_entry_sha256,
                 checkpoint.head_entry_sha256, digest,
                 "explicit recovery: " + operator_reason.strip()),
            )
            db.commit()
        return True
