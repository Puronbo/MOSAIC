"""Validated, integrity-checked scheduler snapshots for crash recovery.

A snapshot restores recorded task state and proposals; it never dispatches a
provider. Its digest detects modification but is not an authenticated signature.
"""
import hashlib
import hmac
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mosaic.core.orchestration import (
    AgentTask,
    TaskRunRecord,
    TaskStatus,
    validate_task_graph,
)

MAX_SNAPSHOT_BYTES = 262_144


class SchedulerSnapshot(BaseModel):
    """Complete immutable task graph plus the state record for every task."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    tasks: tuple[AgentTask, ...]
    records: tuple[TaskRunRecord, ...]
    snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_snapshot_state(self):
        task_ids = [task.task_id for task in self.tasks]
        record_ids = [record.task_id for record in self.records]
        if len(set(task_ids)) != len(task_ids):
            raise ValueError("snapshot task IDs must be unique")
        if len(set(record_ids)) != len(record_ids):
            raise ValueError("snapshot record IDs must be unique")
        if set(task_ids) != set(record_ids):
            raise ValueError("snapshot records must match task IDs exactly")
        validate_task_graph(list(self.tasks))
        tasks_by_id = {task.task_id: task for task in self.tasks}
        for record in self.records:
            task = tasks_by_id[record.task_id]
            if record.status == TaskStatus.COMPLETED:
                if record.proposal is None:
                    raise ValueError("completed snapshot task requires its proposal")
                if (
                    record.proposal.task_id != task.task_id
                    or record.proposal.role != task.role
                ):
                    raise ValueError("snapshot proposal does not match its task")
            elif record.proposal is not None:
                raise ValueError("only completed snapshot tasks may contain proposals")
        return self

    @classmethod
    def capture(
        cls, tasks: tuple[AgentTask, ...] | list[AgentTask],
        records: tuple[TaskRunRecord, ...],
    ) -> "SchedulerSnapshot":
        provisional = cls(
            tasks=tuple(tasks),
            records=records,
            snapshot_sha256="0" * 64,
        )
        return provisional.model_copy(
            update={"snapshot_sha256": _snapshot_digest(provisional)}
        )


def _snapshot_payload(snapshot: SchedulerSnapshot) -> bytes:
    payload = snapshot.model_dump(mode="json", exclude={"snapshot_sha256"})
    return json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _snapshot_digest(snapshot: SchedulerSnapshot) -> str:
    payload = _snapshot_payload(snapshot)
    if len(payload) > MAX_SNAPSHOT_BYTES:
        raise ValueError("scheduler snapshot exceeds the maximum serialized size")
    return hashlib.sha256(payload).hexdigest()


def serialize_scheduler_snapshot(snapshot: SchedulerSnapshot) -> bytes:
    encoded = json.dumps(
        snapshot.model_dump(mode="json"),
        ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    if len(encoded) > MAX_SNAPSHOT_BYTES:
        raise ValueError("scheduler snapshot exceeds the maximum serialized size")
    return encoded


def load_scheduler_snapshot(data: bytes | str) -> SchedulerSnapshot:
    if isinstance(data, str):
        encoded = data.encode("utf-8")
    elif isinstance(data, bytes):
        encoded = data
    else:
        raise TypeError("scheduler snapshot data must be bytes or text")
    if len(encoded) > MAX_SNAPSHOT_BYTES:
        raise ValueError("scheduler snapshot exceeds the maximum serialized size")
    return SchedulerSnapshot.model_validate_json(encoded)


def validate_scheduler_snapshot(snapshot: SchedulerSnapshot) -> SchedulerSnapshot:
    expected = _snapshot_digest(snapshot)
    if not hmac.compare_digest(snapshot.snapshot_sha256, expected):
        raise ValueError("scheduler snapshot integrity check failed")
    return snapshot


class SchedulerSnapshotStore:
    """Local append-only snapshot store using atomic no-overwrite creation."""

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def save(self, snapshot: SchedulerSnapshot) -> Path:
        validate_scheduler_snapshot(snapshot)
        encoded = serialize_scheduler_snapshot(snapshot)
        target = self.root / f"{snapshot.snapshot_sha256}.json"
        if target.exists():
            if target.read_bytes() != encoded:
                raise ValueError("snapshot ID already exists with different content")
            return target
        temporary_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=self.root, prefix=".snapshot-", delete=False
            ) as temporary:
                temporary_path = Path(temporary.name)
                temporary.write(encoded)
                temporary.flush()
                os.fsync(temporary.fileno())
            try:
                os.link(temporary_path, target)
            except FileExistsError:
                if target.read_bytes() != encoded:
                    raise ValueError("snapshot ID collision with different content")
            return target
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

    def load(self, snapshot_sha256: str) -> SchedulerSnapshot:
        if not re.fullmatch(r"[0-9a-f]{64}", snapshot_sha256):
            raise ValueError("invalid scheduler snapshot identifier")
        snapshot = load_scheduler_snapshot(
            (self.root / f"{snapshot_sha256}.json").read_bytes()
        )
        if not hmac.compare_digest(snapshot.snapshot_sha256, snapshot_sha256):
            raise ValueError("stored snapshot identifier does not match its content")
        return validate_scheduler_snapshot(snapshot)


def quarantine_interrupted_tasks(
    snapshot: SchedulerSnapshot,
) -> SchedulerSnapshot:
    """Mark persisted RUNNING tasks FAILED after restart; never blindly rerun them.

    A process restart cannot establish whether an external provider completed.
    Such tasks are quarantined as FAILED for explicit reconciliation rather than
    being automatically dispatched a second time.
    """
    validate_scheduler_snapshot(snapshot)
    recovered_records = tuple(
        record.model_copy(
            update={
                "status": TaskStatus.FAILED,
                "error": (
                    "process restarted while task was RUNNING; external provider "
                    "outcome is unknown and requires reconciliation"
                ),
            }
        )
        if record.status == TaskStatus.RUNNING else record
        for record in snapshot.records
    )
    return SchedulerSnapshot.capture(snapshot.tasks, recovered_records)
