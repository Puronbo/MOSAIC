"""Independent, stateful checkpoint witness.

A witness retains its own last accepted checkpoint and signs only a verified
extension. Its SQLite state is a separate local trust domain; it is not a
distributed consensus or hardware anti-rollback mechanism.
"""
from __future__ import annotations

import hashlib
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from mosaic.verification.lean_runner_signature import _canonical
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
                CREATE TABLE IF NOT EXISTS witness_checkpoint_history (
                    log_id TEXT NOT NULL,
                    checkpoint_sha256 TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    checkpoint_json TEXT NOT NULL,
                    PRIMARY KEY (log_id, checkpoint_sha256)
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
                CREATE TABLE IF NOT EXISTS witness_recoveries (
                    recovery_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    log_id TEXT NOT NULL,
                    selected_checkpoint_sha256 TEXT NOT NULL,
                    authorization_sha256 TEXT NOT NULL UNIQUE,
                    authorization_json TEXT NOT NULL,
                    recovered_at_utc TEXT NOT NULL DEFAULT
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
            db.execute(
                """INSERT OR IGNORE INTO witness_checkpoint_history
                (log_id, checkpoint_sha256, sequence, checkpoint_json)
                VALUES (?, ?, ?, ?)""",
                (checkpoint.log_id, checkpoint.digest(), checkpoint.sequence, encoded),
            )
            db.commit()
            return endorsement

    def export_signed_snapshot(
        self, log_id: str, *, witness_key_id: str,
        witness_private_key: bytes, exported_at_utc: str,
    ) -> "SignedPolicyWitnessSnapshot | None":
        """Create a portable, signed snapshot of one log's retained state."""
        from mosaic.verification.policy_witness_snapshot import SignedPolicyWitnessSnapshot
        head = self.get_head(log_id)
        if head is None:
            return None
        with self._connection() as db:
            rows = db.execute(
                """SELECT checkpoint_json FROM witness_checkpoint_history
                   WHERE log_id=? ORDER BY sequence""", (log_id,)
            ).fetchall()
        history = [self._decode(row["checkpoint_json"]) for row in rows]
        if (not history or history[-1].digest() != head.digest()
                or history[0].sequence != 0
                or any(item.sequence != index for index, item in enumerate(history))):
            # Do not emit an unverifiable partial chain from a pre-snapshot
            # database. Rebuild trust from an authenticated registry history.
            return None
        return SignedPolicyWitnessSnapshot.sign(
            log_id=log_id, checkpoint=head, checkpoint_history=history,
            quarantined=self.is_quarantined(log_id),
            incidents=self.incidents(log_id), witness_key_id=witness_key_id,
            exported_at_utc=exported_at_utc, private_key=witness_private_key,
        )

    def import_signed_snapshot(
        self, snapshot: "SignedPolicyWitnessSnapshot", *,
        witness_keyring: dict[str, PolicyPublisherKey],
        entries: list[SignedPolicyRegistryEntry],
        signer_keyring: dict[str, PolicyPublisherKey],
    ) -> bool:
        """Import only authenticated, non-rollback state.

        An empty store may be bootstrapped from a snapshot whose signing key is
        independently trusted. Existing state accepts only an identical head
        with non-regressing incident history, or a strict verified extension.
        Quarantine is monotonic under import: a snapshot cannot clear it.
        """
        from mosaic.verification.policy_witness_snapshot import SignedPolicyWitnessSnapshot
        if (not isinstance(snapshot, SignedPolicyWitnessSnapshot)
                or not snapshot.verify(witness_keyring)
                or snapshot.log_id != snapshot.checkpoint.log_id
                or not snapshot.checkpoint_history
                or snapshot.checkpoint_history[-1].digest() != snapshot.checkpoint.digest()):
            return False
        prior = None
        for historical in snapshot.checkpoint_history:
            if not verify_policy_checkpoint(
                historical, entries=entries[:historical.sequence + 1],
                signer_keyring=signer_keyring, previous_checkpoint=prior,
            ):
                return False
            prior = historical
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM witness_heads WHERE log_id=?", (snapshot.log_id,)
            ).fetchone()
            previous = self._decode(row["checkpoint_json"]) if row else None
            if row and row["quarantined"] and not snapshot.quarantined:
                db.rollback()
                return False
            if previous:
                if snapshot.checkpoint.sequence == previous.sequence:
                    if snapshot.checkpoint.head_entry_sha256 != previous.head_entry_sha256:
                        db.execute(
                            "UPDATE witness_heads SET quarantined=1 WHERE log_id=?",
                            (snapshot.log_id,),
                        )
                        db.execute(
                            """INSERT INTO witness_incidents
                            (log_id, sequence, retained_checkpoint_sha256,
                             conflicting_checkpoint_sha256, reason)
                            VALUES (?, ?, ?, ?, ?)""",
                            (snapshot.log_id, snapshot.checkpoint.sequence,
                             previous.digest(), snapshot.checkpoint.digest(),
                             "conflicting signed witness snapshot"),
                        )
                        db.commit()
                        return False
                    if snapshot.checkpoint.digest() != previous.digest():
                        db.rollback()
                        return False
                elif (not any(item.digest() == previous.digest()
                               for item in snapshot.checkpoint_history)
                      or snapshot.checkpoint.sequence <= previous.sequence):
                    db.rollback()
                    return False
            encoded = self._encode(snapshot.checkpoint)
            for historical in snapshot.checkpoint_history:
                db.execute(
                    """INSERT OR IGNORE INTO witness_checkpoint_history
                    (log_id, checkpoint_sha256, sequence, checkpoint_json)
                    VALUES (?, ?, ?, ?)""",
                    (snapshot.log_id, historical.digest(), historical.sequence,
                     self._encode(historical)),
                )
            db.execute(
                """INSERT INTO witness_heads
                (log_id, checkpoint_json, checkpoint_sha256, quarantined)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(log_id) DO UPDATE SET
                  checkpoint_json=excluded.checkpoint_json,
                  checkpoint_sha256=excluded.checkpoint_sha256,
                  quarantined=MAX(witness_heads.quarantined, excluded.quarantined)""",
                (snapshot.log_id, encoded, snapshot.checkpoint.digest(),
                 int(snapshot.quarantined)),
            )
            existing = {
                (x["sequence"], x["retained_checkpoint_sha256"],
                 x["conflicting_checkpoint_sha256"], x["reason"], x["observed_at_utc"])
                for x in db.execute(
                    """SELECT sequence, retained_checkpoint_sha256,
                       conflicting_checkpoint_sha256, reason, observed_at_utc
                       FROM witness_incidents WHERE log_id=?""", (snapshot.log_id,)
                ).fetchall()
            }
            for incident in snapshot.incidents:
                identity = (incident.sequence, incident.retained_checkpoint_sha256,
                            incident.conflicting_checkpoint_sha256, incident.reason,
                            incident.observed_at_utc)
                if identity not in existing:
                    db.execute(
                        """INSERT INTO witness_incidents
                        (log_id, sequence, retained_checkpoint_sha256,
                         conflicting_checkpoint_sha256, reason, observed_at_utc)
                        VALUES (?, ?, ?, ?, ?, ?)""",
                        (snapshot.log_id, *identity),
                    )
                    existing.add(identity)
            db.commit()
            return True


    def recovery_records(self, log_id: str) -> list[dict]:
        """Return retained signed recovery authorizations for audit."""
        with self._connection() as db:
            rows = db.execute(
                """SELECT log_id, selected_checkpoint_sha256,
                   authorization_sha256, authorization_json, recovered_at_utc
                   FROM witness_recoveries WHERE log_id=? ORDER BY recovery_id""",
                (log_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def recover_from_signed_snapshot(
        self, snapshot: "SignedPolicyWitnessSnapshot", *,
        witness_keyring: dict[str, PolicyPublisherKey],
        signer_keyring: dict[str, PolicyPublisherKey],
        operator_keyring: dict[str, PolicyPublisherKey],
        authorization: "SignedPolicyWitnessRecoveryAuthorization",
        entries: list[SignedPolicyRegistryEntry],
    ) -> bool:
        """Recover a quarantined witness only with an exact signed approval."""
        from mosaic.verification.policy_witness_snapshot import SignedPolicyWitnessSnapshot
        from mosaic.verification.policy_witness_recovery import SignedPolicyWitnessRecoveryAuthorization
        if (not isinstance(snapshot, SignedPolicyWitnessSnapshot)
                or not isinstance(authorization, SignedPolicyWitnessRecoveryAuthorization)
                or snapshot.quarantined
                or not snapshot.verify(witness_keyring)
                or not authorization.verify(operator_keyring)
                or authorization.operator_key_id in witness_keyring
                or operator_keyring[authorization.operator_key_id].public_key() == witness_keyring[snapshot.witness_key_id].public_key()
                or authorization.operator_key_id in signer_keyring
                or operator_keyring[authorization.operator_key_id].public_key() in {item.public_key() for item in signer_keyring.values()}
                or authorization.log_id != snapshot.log_id
                or authorization.selected_snapshot_sha256 != hashlib.sha256(
                    _canonical(snapshot.model_dump(mode="json"))
                ).hexdigest()
                or not snapshot.checkpoint_history
                or snapshot.checkpoint_history[-1].digest() != snapshot.checkpoint.digest()
                or len(snapshot.checkpoint_history) != snapshot.checkpoint.sequence + 1):
            return False
        prior = None
        for index, historical in enumerate(snapshot.checkpoint_history):
            if historical.sequence != index or historical.log_id != snapshot.log_id:
                return False
            if not verify_policy_checkpoint(
                historical, entries=entries[:index + 1],
                signer_keyring=signer_keyring, previous_checkpoint=prior,
            ):
                return False
            prior = historical

        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT quarantined FROM witness_heads WHERE log_id=?",
                (snapshot.log_id,),
            ).fetchone()
            if row is None or not row["quarantined"]:
                db.rollback()
                return False
            incidents = [dict(item) for item in db.execute(
                """SELECT log_id, sequence, retained_checkpoint_sha256,
                   conflicting_checkpoint_sha256, reason, observed_at_utc
                   FROM witness_incidents WHERE log_id=? ORDER BY incident_id""",
                (snapshot.log_id,),
            ).fetchall()]
            incident_digest = hashlib.sha256(_canonical(incidents)).hexdigest()
            if (not incidents
                    or authorization.incident_history_sha256 != incident_digest
                    or db.execute(
                        "SELECT 1 FROM witness_recoveries WHERE authorization_sha256=?",
                        (authorization.digest(),),
                    ).fetchone()):
                db.rollback()
                return False
            for historical in snapshot.checkpoint_history:
                db.execute(
                    """INSERT OR IGNORE INTO witness_checkpoint_history
                    (log_id, checkpoint_sha256, sequence, checkpoint_json)
                    VALUES (?, ?, ?, ?)""",
                    (snapshot.log_id, historical.digest(), historical.sequence,
                     self._encode(historical)),
                )
            db.execute(
                """UPDATE witness_heads SET checkpoint_json=?,
                   checkpoint_sha256=?, quarantined=0 WHERE log_id=?""",
                (self._encode(snapshot.checkpoint), snapshot.checkpoint.digest(),
                 snapshot.log_id),
            )
            db.execute(
                """INSERT INTO witness_recoveries
                (log_id, selected_checkpoint_sha256, authorization_sha256,
                 authorization_json)
                VALUES (?, ?, ?, ?)""",
                (snapshot.log_id, snapshot.checkpoint.digest(),
                 authorization.digest(), authorization.model_dump_json()),
            )
            db.commit()
            return True
