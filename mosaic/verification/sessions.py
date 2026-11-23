"""Append-only SQLite ledger and progress assessment for verification sessions."""
import hashlib
import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from mosaic.core.requests import MathRequest
from mosaic.verification.task_bound import TaskBoundCheck
from mosaic.verification.evidence import EvidenceBundle


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class RevisionAssessment(BaseModel):
    """Conservative progress signal derived only from checker outputs."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    trajectory: Literal[
        "FIRST_ATTEMPT", "IMPROVED", "REGRESSED", "UNCHANGED", "CHANGED_UNRESOLVED"
    ]
    recommendation: Literal[
        "CONTINUE", "STOP_REVIEW", "STOP_NO_PROGRESS",
        "STOP_NONRETRYABLE", "STOP_REVISION_LIMIT"
    ]
    explanation: str


class VerificationRevision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    revision: int
    candidate: str
    check: TaskBoundCheck
    feedback: tuple[dict[str, Any], ...]
    assessment: RevisionAssessment
    evidence: EvidenceBundle
    created_at: str


class VerificationSession(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    session_id: str
    request: MathRequest
    request_sha256: str
    created_at: str
    revisions: tuple[VerificationRevision, ...] = ()


class RevisionLimitReached(Exception):
    """Raised when a session has reached its configured revision bound."""


def _is_experimentally_consistent(check: TaskBoundCheck) -> bool:
    return (
        check.status == "EXPERIMENTAL"
        and check.equal is True
        and check.domain_status in {"PRESERVED", "NOT_CHECKED"}
    )


def _assessment(
    check: TaskBoundCheck,
    feedback: tuple[dict[str, Any], ...],
    revision: int,
    max_revisions: int,
    previous: sqlite3.Row | None,
    repeated: bool,
) -> RevisionAssessment:
    passed = _is_experimentally_consistent(check)
    if previous is None:
        trajectory = "FIRST_ATTEMPT"
    else:
        prior = TaskBoundCheck.model_validate(json.loads(previous["check_json"]))
        prior_passed = _is_experimentally_consistent(prior)
        if repeated:
            trajectory = "UNCHANGED"
        elif passed and not prior_passed:
            trajectory = "IMPROVED"
        elif prior_passed and not passed:
            trajectory = "REGRESSED"
        elif (
            prior.status == check.status
            and prior.equal == check.equal
            and prior.domain_status == check.domain_status
        ):
            trajectory = "UNCHANGED"
        else:
            trajectory = "CHANGED_UNRESOLVED"

    if passed:
        recommendation = "STOP_REVIEW"
        explanation = (
            "The latest candidate passed available experimental checks. Stop automated retries "
            "and retain the result for human or formal review; this is not a proof."
        )
    elif repeated:
        recommendation = "STOP_NO_PROGRESS"
        explanation = "The exact candidate was already submitted in this session; another identical attempt adds no information."
    elif revision >= max_revisions:
        recommendation = "STOP_REVISION_LIMIT"
        explanation = "The session reached its configured revision limit; escalate or start a deliberately new task."
    elif not any(item.get("retryable") is True for item in feedback):
        recommendation = "STOP_NONRETRYABLE"
        explanation = "The latest checker feedback provides no retryable correction; stop and escalate to a suitable checker or reviewer."
    else:
        recommendation = "CONTINUE"
        explanation = "The checker supplied retryable feedback. Revise only the candidate while keeping the original request fixed."

    return RevisionAssessment(
        trajectory=trajectory, recommendation=recommendation, explanation=explanation
    )


class SessionStore:
    """SQLite-backed append-only session store with bounded revision histories."""

    def __init__(self, database: str | Path | None = None, max_revisions: int = 20):
        if max_revisions < 1:
            raise ValueError("max_revisions must be positive")
        self.database = str(database or os.environ.get("MOSAIC_SESSION_DB", "mosaic_sessions.sqlite3"))
        self.max_revisions = max_revisions
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
            columns = {
                row["name"] for row in db.execute("PRAGMA table_info(verification_revisions)")
            }
            if "assessment_json" not in columns:
                db.execute(
                    "ALTER TABLE verification_revisions ADD COLUMN assessment_json TEXT"
                )
            if "evidence_json" not in columns:
                db.execute(
                    "ALTER TABLE verification_revisions ADD COLUMN evidence_json TEXT"
                )

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def create(self, request: MathRequest) -> VerificationSession:
        session_id = str(uuid.uuid4())
        request_json = _canonical(request.model_dump(mode="json"))
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
        evidence: EvidenceBundle,
    ) -> VerificationRevision | None:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            exists = db.execute(
                "SELECT 1 FROM verification_sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
            if exists is None:
                return None
            previous = db.execute(
                "SELECT * FROM verification_revisions WHERE session_id = ? ORDER BY revision DESC LIMIT 1",
                (session_id,),
            ).fetchone()
            revision = (previous["revision"] + 1) if previous else 1
            if revision > self.max_revisions:
                raise RevisionLimitReached(
                    f"Session revision limit ({self.max_revisions}) has been reached."
                )
            candidate_hash = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
            repeated = db.execute(
                "SELECT 1 FROM verification_revisions WHERE session_id = ? AND check_json LIKE ? LIMIT 1",
                (session_id, f'%"candidate_sha256":"{candidate_hash}"%'),
            ).fetchone() is not None
            assessment = _assessment(
                check, feedback, revision, self.max_revisions, previous, repeated
            )
            created_at = self._now()
            db.execute(
                """INSERT INTO verification_revisions
                   (session_id, revision, candidate, check_json, feedback_json, created_at, assessment_json, evidence_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (session_id, revision, candidate,
                 _canonical(check.model_dump(mode="json")),
                 _canonical(list(feedback)), created_at,
                 _canonical(assessment.model_dump(mode="json")),
                 _canonical(evidence.model_dump(mode="json"))),
            )
        return VerificationRevision(
            revision=revision, candidate=candidate, check=check,
            feedback=feedback, assessment=assessment, evidence=evidence,
            created_at=created_at,
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
                assessment=(
                    RevisionAssessment.model_validate(json.loads(row["assessment_json"]))
                    if row["assessment_json"] else RevisionAssessment(
                        trajectory="FIRST_ATTEMPT", recommendation="CONTINUE",
                        explanation="Legacy revision predates progress assessment.",
                    )
                ),
                evidence=(
                    EvidenceBundle.model_validate(json.loads(row["evidence_json"]))
                    if row["evidence_json"] else EvidenceBundle(
                        items=(), assessment={
                            "status": "NO_CHECKER_EVIDENCE",
                            "explanation": "Legacy revision predates evidence provenance.",
                        },
                    )
                ),
                created_at=row["created_at"],
            )
            for row in rows
        )
        return VerificationSession(
            session_id=session["session_id"], request=request,
            request_sha256=session["request_sha256"],
            created_at=session["created_at"], revisions=revisions,
        )
