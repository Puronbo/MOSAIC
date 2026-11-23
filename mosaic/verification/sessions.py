"""Append-only SQLite ledger for task-bound candidate revision sessions."""
import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from mosaic.core.requests import MathRequest
from mosaic.verification.task_bound import TaskBoundCheck


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class VerificationRevision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    revision: int
    candidate: str
    check: TaskBoundCheck
    feedback: tuple[dict[str, Any], ...]
    created_at: str


class VerificationSession(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    session_id: str
    request: MathRequest
    request_sha256: str
    created_at: str
    revisions: tuple[VerificationRevision, ...] = ()


class SessionStore:
    """Small SQLite-backed append-only session store.

    Each operation opens its own connection so FastAPI worker threads do not
    share sqlite connection state. The request row is never updated.
    """

    def __init__(self, database: str | Path | None = None):
        self.database = str(database or os.environ.get("MOSAIC_SESSION_DB", "mosaic_sessions.sqlite3"))
        if self.database != ":memory:":
            Path(self.database).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _initialize(self) -> None:
        with self._connect() as db:
            db.execute("PRAGMA journal_mode = WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS verification_sessions (
                    session_id TEXT PRIMARY KEY,
                    request_json TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS verification_revisions (
                    session_id TEXT NOT NULL REFERENCES verification_sessions(session_id),
                    revision INTEGER NOT NULL CHECK (revision > 0),
                    candidate TEXT NOT NULL,
                    check_json TEXT NOT NULL,
                    feedback_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (session_id, revision)
                );
                CREATE TRIGGER IF NOT EXISTS immutable_session_request
                BEFORE UPDATE OF request_json, request_sha256, created_at
                ON verification_sessions
                BEGIN
                    SELECT RAISE(ABORT, 'verification session request is immutable');
                END;
                CREATE TRIGGER IF NOT EXISTS immutable_revision
                BEFORE UPDATE ON verification_revisions
                BEGIN
                    SELECT RAISE(ABORT, 'verification revisions are append-only');
                END;
            """)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def create(self, request: MathRequest) -> VerificationSession:
        session_id = str(uuid.uuid4())
        request_json = _canonical(request.model_dump(mode="json"))
        import hashlib
        request_hash = hashlib.sha256(request_json.encode("utf-8")).hexdigest()
        created_at = self._now()
        with self._connect() as db:
            db.execute(
                "INSERT INTO verification_sessions VALUES (?, ?, ?, ?)",
                (session_id, request_json, request_hash, created_at),
            )
        return VerificationSession(
            session_id=session_id, request=request, request_sha256=request_hash,
            created_at=created_at,
        )

    def append(
        self, session_id: str, candidate: str, check: TaskBoundCheck,
        feedback: tuple[dict[str, Any], ...],
    ) -> VerificationRevision | None:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            exists = db.execute(
                "SELECT 1 FROM verification_sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
            if exists is None:
                return None
            revision = db.execute(
                "SELECT COALESCE(MAX(revision), 0) + 1 FROM verification_revisions WHERE session_id = ?",
                (session_id,),
            ).fetchone()[0]
            created_at = self._now()
            db.execute(
                "INSERT INTO verification_revisions VALUES (?, ?, ?, ?, ?, ?)",
                (session_id, revision, candidate,
                 _canonical(check.model_dump(mode="json")),
                 _canonical(list(feedback)), created_at),
            )
        return VerificationRevision(
            revision=revision, candidate=candidate, check=check,
            feedback=feedback, created_at=created_at,
        )

    def get(self, session_id: str) -> VerificationSession | None:
        with self._connect() as db:
            session = db.execute(
                "SELECT * FROM verification_sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
            if session is None:
                return None
            rows = db.execute(
                "SELECT * FROM verification_revisions WHERE session_id = ? ORDER BY revision",
                (session_id,),
            ).fetchall()
        request = MathRequest.model_validate(json.loads(session["request_json"]))
        revisions = tuple(
            VerificationRevision(
                revision=row["revision"], candidate=row["candidate"],
                check=TaskBoundCheck.model_validate(json.loads(row["check_json"])),
                feedback=tuple(json.loads(row["feedback_json"])),
                created_at=row["created_at"],
            )
            for row in rows
        )
        return VerificationSession(
            session_id=session["session_id"], request=request,
            request_sha256=session["request_sha256"],
            created_at=session["created_at"], revisions=revisions,
        )
