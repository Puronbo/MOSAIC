"""Independent, stateful checkpoint witness.

A witness retains its own last accepted checkpoint and signs only a verified
extension. Its SQLite state is a separate local trust domain; it is not a
distributed consensus or hardware anti-rollback mechanism.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path

from mosaic.verification.policy_governance import PolicyPublisherKey
from mosaic.verification.policy_registry import SignedPolicyRegistryEntry
from mosaic.verification.policy_transparency import (
    PolicyCheckpointWitness, PolicyRegistryCheckpoint, verify_policy_checkpoint,
)


class PolicyWitnessStateStore:
    """Durable single-witness state with atomic endorse-or-quarantine semantics."""

    def __init__(self, database_path: str | Path):
        self.database_path = str(database_path)
        if self.database_path != ":memory:":
            Path(self.database_path).parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS witness_heads (
                    log_id TEXT PRIMARY KEY,
                    checkpoint_json TEXT NOT NULL,
                    checkpoint_sha256 TEXT NOT NULL,
                    quarantined INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS witness_incidents (
                    incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    log_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    retained_checkpoint_sha256 TEXT NOT NULL,
                    conflicting_checkpoint_sha256 TEXT NOT NULL,
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
    def _encode(checkpoint: PolicyRegistryCheckpoint) -> str:
        return checkpoint.model_dump_json()

    @staticmethod
    def _decode(value: str) -> PolicyRegistryCheckpoint:
        return PolicyRegistryCheckpoint.model_validate_json(value)

    def get_head(self, log_id: str) -> PolicyRegistryCheckpoint | None:
        with self._connection() as db:
            row = db.execute(
                "SELECT checkpoint_json FROM witness_heads WHERE log_id=?", (log_id,)
            ).fetchone()
        return self._decode(row["checkpoint_json"]) if row else None

    def is_quarantined(self, log_id: str) -> bool:
        with self._connection() as db:
            row = db.execute(
                "SELECT quarantined FROM witness_heads WHERE log_id=?", (log_id,)
            ).fetchone()
        return bool(row["quarantined"]) if row else False

    def incidents(self, log_id: str) -> list[dict]:
        with self._connection() as db:
            rows = db.execute(
                """SELECT log_id, sequence, retained_checkpoint_sha256,
                   conflicting_checkpoint_sha256, reason, observed_at_utc
                   FROM witness_incidents WHERE log_id=? ORDER BY incident_id""",
                (log_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def endorse(
        self, checkpoint: PolicyRegistryCheckpoint, *,
        entries: list[SignedPolicyRegistryEntry],
        signer_keyring: dict[str, PolicyPublisherKey],
        witness_key: PolicyPublisherKey,
        witness_private_key: bytes,
        witnessed_at_utc: str,
    ) -> PolicyCheckpointWitness | None:
        """Persist a verified new view, then return its signed endorsement.

        A same-sequence conflicting, independently verifiable genesis-rooted
        view quarantines the witness. Invalid packets cannot cause quarantine.
        """
        if (not isinstance(checkpoint, PolicyRegistryCheckpoint)
                or not isinstance(witness_key, PolicyPublisherKey)
                or not witness_key.permits(witness_key.key_id, witnessed_at_utc)):
            return None
        try:
            # Validate private/public key correspondence before changing state.
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
            derived = Ed25519PrivateKey.from_private_bytes(witness_private_key).public_key()
            if derived.public_bytes(Encoding.Raw, PublicFormat.Raw) != witness_key.public_key():
                return None
        except (ValueError, TypeError):
            return None

        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM witness_heads WHERE log_id=?", (checkpoint.log_id,)
            ).fetchone()
            if row and row["quarantined"]:
                db.rollback()
                return None
            previous = self._decode(row["checkpoint_json"]) if row else None

            if previous and checkpoint.sequence == previous.sequence:
                if (checkpoint.head_entry_sha256 != previous.head_entry_sha256
                        and checkpoint.previous_checkpoint_sha256 is None
                        and verify_policy_checkpoint(
                            checkpoint, entries=entries,
                            signer_keyring=signer_keyring,
                        )):
                    db.execute(
                        "UPDATE witness_heads SET quarantined=1 WHERE log_id=?",
                        (checkpoint.log_id,),
                    )
                    db.execute(
                        """INSERT INTO witness_incidents
                        (log_id, sequence, retained_checkpoint_sha256,
                         conflicting_checkpoint_sha256, reason)
                        VALUES (?, ?, ?, ?, ?)""",
                        (checkpoint.log_id, checkpoint.sequence, previous.digest(),
                         checkpoint.digest(), "verified same-sequence conflicting view"),
                    )
                    db.commit()
                else:
                    db.rollback()
                return None

            if not verify_policy_checkpoint(
                checkpoint, entries=entries, signer_keyring=signer_keyring,
                previous_checkpoint=previous,
            ):
                db.rollback()
                return None

            try:
                endorsement = PolicyCheckpointWitness.sign(
                    checkpoint=checkpoint, witness_key_id=witness_key.key_id,
                    witnessed_at_utc=witnessed_at_utc,
                    private_key=witness_private_key,
                )
            except (ValueError, TypeError):
                db.rollback()
                return None
            encoded = self._encode(checkpoint)
            db.execute(
                """INSERT INTO witness_heads
                (log_id, checkpoint_json, checkpoint_sha256, quarantined)
                VALUES (?, ?, ?, 0)
                ON CONFLICT(log_id) DO UPDATE SET
                  checkpoint_json=excluded.checkpoint_json,
                  checkpoint_sha256=excluded.checkpoint_sha256""",
                (checkpoint.log_id, encoded, checkpoint.digest()),
            )
            db.commit()
            return endorsement
