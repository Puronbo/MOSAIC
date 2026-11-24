import pytest

from mosaic.core.orchestration import (
    AgentProposal,
    AgentRole,
    AgentTask,
    TaskStatus,
    complete_task,
    dispatch_ready_tasks,
    initialize_task_records,
)
from mosaic.core.scheduler_persistence import (
    SchedulerSnapshot,
    SchedulerSnapshotStore,
    quarantine_interrupted_tasks,
    load_scheduler_snapshot,
    serialize_scheduler_snapshot,
)


def _completed_state():
    task = AgentTask(
        task_id="solve-1",
        role=AgentRole.SOLVER,
        goal="Solve 2 + 3",
        context="",
    )
    records = initialize_task_records([task])
    running = dispatch_ready_tasks([task], records, now=10.0, max_concurrency=1)
    proposal = AgentProposal(
        task_id=task.task_id,
        agent_id="solver-a",
        role=AgentRole.SOLVER,
        claim="5",
        rationale="Direct arithmetic.",
    )
    completed = complete_task(task, running, proposal)
    return [task], completed


def test_snapshot_round_trip_restores_completed_proposal_without_dispatch():
    tasks, records = _completed_state()
    snapshot = SchedulerSnapshot.capture(tasks, records)
    restored = load_scheduler_snapshot(serialize_scheduler_snapshot(snapshot))
    assert restored == snapshot
    assert restored.records[0].status == TaskStatus.COMPLETED
    assert restored.records[0].proposal.claim == "5"


def test_snapshot_store_recovers_after_store_reconstruction(tmp_path):
    tasks, records = _completed_state()
    snapshot = SchedulerSnapshot.capture(tasks, records)
    first = SchedulerSnapshotStore(tmp_path / "scheduler")
    first.save(snapshot)
    restarted = SchedulerSnapshotStore(tmp_path / "scheduler")
    assert restarted.load(snapshot.snapshot_sha256) == snapshot


def test_snapshot_rejects_tampered_proposal_and_stale_digest():
    tasks, records = _completed_state()
    snapshot = SchedulerSnapshot.capture(tasks, records)
    altered_proposal = records[0].proposal.model_copy(update={"claim": "6"})
    altered_record = records[0].model_copy(update={"proposal": altered_proposal})
    altered = snapshot.model_copy(update={"records": (altered_record,)})
    with pytest.raises(ValueError, match="integrity"):
        from mosaic.core.scheduler_persistence import validate_scheduler_snapshot
        validate_scheduler_snapshot(altered)


def test_snapshot_rejects_completed_record_without_proposal():
    tasks, records = _completed_state()
    altered_record = records[0].model_copy(update={"proposal": None})
    with pytest.raises(ValueError, match="requires its proposal"):
        SchedulerSnapshot(
            tasks=tuple(tasks),
            records=(altered_record,),
            snapshot_sha256="0" * 64,
        )


def test_snapshot_rejects_missing_records_and_path_injection(tmp_path):
    tasks, records = _completed_state()
    with pytest.raises(ValueError, match="match task IDs"):
        SchedulerSnapshot.capture(tasks, ())
    store = SchedulerSnapshotStore(tmp_path / "scheduler")
    with pytest.raises(ValueError, match="identifier"):
        store.load("../outside")


def test_snapshot_loader_enforces_size_limit():
    with pytest.raises(ValueError, match="maximum serialized size"):
        load_scheduler_snapshot(b"x" * 262_145)


def test_recovery_quarantines_running_tasks_instead_of_redispatching():
    task = AgentTask(
        task_id="remote-call-1",
        role=AgentRole.SOLVER,
        goal="Call an external solver",
    )
    records = initialize_task_records([task])
    running = dispatch_ready_tasks([task], records, now=10.0, max_concurrency=1)
    snapshot = SchedulerSnapshot.capture([task], running)

    recovered = quarantine_interrupted_tasks(snapshot)
    assert recovered.records[0].status == TaskStatus.FAILED
    assert "outcome is unknown" in recovered.records[0].error
    assert recovered.records[0].proposal is None

    # Failed is not a dispatchable state: recovery cannot duplicate an unknown
    # remote call merely because the local process restarted.
    from mosaic.core.orchestration import dispatch_ready_tasks
    after_restart = dispatch_ready_tasks(
        [task], recovered.records, now=11.0, max_concurrency=1
    )
    assert after_restart[0].status == TaskStatus.FAILED


def test_recovery_refuses_tampered_snapshot():
    tasks, records = _completed_state()
    snapshot = SchedulerSnapshot.capture(tasks, records)
    tampered = snapshot.model_copy(update={"snapshot_sha256": "0" * 64})
    from mosaic.core.scheduler_persistence import quarantine_interrupted_tasks
    with pytest.raises(ValueError, match="integrity"):
        quarantine_interrupted_tasks(tampered)


def test_snapshot_rejects_noncompleted_proposal_in_completed_record():
    tasks, records = _completed_state()
    invalid_proposal = records[0].proposal.model_copy(
        update={"status": TaskStatus.FAILED}
    )
    invalid_record = records[0].model_copy(update={"proposal": invalid_proposal})
    with pytest.raises(ValueError, match="does not match its task"):
        SchedulerSnapshot(
            tasks=tuple(tasks),
            records=(invalid_record,),
            snapshot_sha256="0" * 64,
        )
