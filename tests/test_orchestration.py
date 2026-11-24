import pytest
from pydantic import ValidationError

from mosaic.core.orchestration import (
    AgentProposal, AgentRole, AgentTask, ReviewFinding, ReviewFindingKind, TaskRunRecord, TaskStatus, assess_completed_reviews, assess_proposals, collision_review_tasks, complete_task, dispatch_ready_tasks, fail_task, initialize_task_records, obligation_verification_tasks, validate_task_graph,
)


def test_dependency_graph_is_sorted_and_validated():
    a = AgentTask(task_id="a", role=AgentRole.DECOMPOSER, goal="Split the theorem")
    b = AgentTask(task_id="b", role=AgentRole.SOLVER, goal="Solve subgoal", depends_on=("a",))
    assert validate_task_graph([b, a]) == ["a", "b"]


def test_dependency_cycle_is_rejected():
    a = AgentTask(task_id="a", role=AgentRole.SOLVER, goal="A", depends_on=("b",))
    b = AgentTask(task_id="b", role=AgentRole.SOLVER, goal="B", depends_on=("a",))
    with pytest.raises(ValueError, match="cycle"):
        validate_task_graph([a, b])


def test_unknown_dependency_is_rejected():
    a = AgentTask(task_id="a", role=AgentRole.SOLVER, goal="A", depends_on=("missing",))
    with pytest.raises(ValueError, match="unknown dependencies"):
        validate_task_graph([a])


def test_agent_agreement_is_not_a_proof():
    task = AgentTask(task_id="t1", role=AgentRole.SOLVER, goal="Find a factorization")
    proposals = [
        AgentProposal(task_id="t1", agent_id="model-a", role=AgentRole.SOLVER, claim="x*(x+1)"),
        AgentProposal(task_id="t1", agent_id="model-b", role=AgentRole.CRITIC, claim="x*(x+1)"),
    ]
    result = assess_proposals(task, proposals)
    assert result.proposal_count == 2
    assert result.conflict_detected is False
    assert result.mathematical_status == "EXPERIMENTAL"
    assert result.disposition == "candidate-for-independent-check"
    assert result.preserved_proposals == tuple(proposals)
    assert result.claim_groups == ((0, 1),)


def test_disagreement_triggers_review_and_preserves_both_claims():
    task = AgentTask(task_id="t1", role=AgentRole.SOLVER, goal="Find result")
    proposals = [
        AgentProposal(task_id="t1", agent_id="a", role=AgentRole.SOLVER, claim="x+1"),
        AgentProposal(task_id="t1", agent_id="b", role=AgentRole.SOLVER, claim="x-1"),
    ]
    result = assess_proposals(task, proposals)
    assert result.disposition == "needs-adversarial-review"
    assert result.conflict_detected is True
    assert result.claim_groups == ((0,), (1,))
    assert result.conflicting_proposal_indices == (0, 1)
    assert result.preserved_proposals == tuple(proposals)
    assert result.mathematical_status == "EXPERIMENTAL"


def test_whitespace_only_claim_difference_is_not_a_collision():
    task = AgentTask(task_id="t1", role=AgentRole.SOLVER, goal="Normalize claims")
    proposals = [
        AgentProposal(task_id="t1", agent_id="a", role=AgentRole.SOLVER, claim="x + 1"),
        AgentProposal(task_id="t1", agent_id="b", role=AgentRole.SOLVER, claim=" x   + 1 "),
    ]
    result = assess_proposals(task, proposals)
    assert result.conflict_detected is False
    assert result.claim_groups == ((0, 1),)
    assert result.preserved_proposals == tuple(proposals)


def test_conflict_detection_does_not_case_fold_or_rewrite_math():
    task = AgentTask(task_id="t1", role=AgentRole.SOLVER, goal="Preserve syntax")
    proposals = [
        AgentProposal(task_id="t1", agent_id="a", role=AgentRole.SOLVER, claim="X"),
        AgentProposal(task_id="t1", agent_id="b", role=AgentRole.SOLVER, claim="x"),
    ]
    assert assess_proposals(task, proposals).conflict_detected is True


def test_proposal_for_another_task_is_rejected():
    task = AgentTask(task_id="t1", role=AgentRole.SOLVER, goal="Find result")
    proposal = AgentProposal(task_id="other", agent_id="a", role=AgentRole.SOLVER, claim="x")
    with pytest.raises(ValueError, match="does not match"):
        assess_proposals(task, [proposal])


def test_task_contract_rejects_extra_fields():
    with pytest.raises(ValidationError):
        AgentTask(task_id="t", role=AgentRole.SOLVER, goal="g", admin=True)



def test_collision_creates_bounded_dependency_ordered_review_plan():
    task = AgentTask(task_id="t1", role=AgentRole.SOLVER, goal="Find result")
    proposals = [
        AgentProposal(task_id="t1", agent_id="a", role=AgentRole.SOLVER, claim="x+1"),
        AgentProposal(task_id="t1", agent_id="b", role=AgentRole.SOLVER, claim="x-1"),
        AgentProposal(task_id="t1", agent_id="c", role=AgentRole.CRITIC, claim="x+2"),
    ]
    assessment = assess_proposals(task, proposals)
    reviews = collision_review_tasks(task, assessment)
    assert len(reviews) == 4
    critics, synthesis = reviews[:-1], reviews[-1]
    assert all(review.role == AgentRole.CRITIC for review in critics)
    assert all(review.depends_on == ("t1",) for review in critics)
    assert synthesis.depends_on == ("t1", *(review.task_id for review in critics))
    assert all(str(index) in review.context for index, review in enumerate(critics))
    ordered = validate_task_graph([synthesis, *critics, task])
    assert ordered.index("t1") < min(ordered.index(item.task_id) for item in critics)
    assert max(ordered.index(item.task_id) for item in critics) < ordered.index(synthesis.task_id)


def test_collision_review_plan_is_deterministic():
    task = AgentTask(task_id="stable-task", role=AgentRole.SOLVER, goal="Compare claims")
    proposals = [
        AgentProposal(task_id="stable-task", agent_id="a", role=AgentRole.SOLVER, claim="left"),
        AgentProposal(task_id="stable-task", agent_id="b", role=AgentRole.SOLVER, claim="right"),
    ]
    assessment = assess_proposals(task, proposals)
    first = collision_review_tasks(task, assessment)
    second = collision_review_tasks(task, assessment)
    assert [item.model_dump() for item in first] == [item.model_dump() for item in second]


def test_collision_review_rejects_non_conflict_and_budget_overflow():
    task = AgentTask(task_id="t1", role=AgentRole.SOLVER, goal="Find result")
    same = [
        AgentProposal(task_id="t1", agent_id="a", role=AgentRole.SOLVER, claim="x"),
        AgentProposal(task_id="t1", agent_id="b", role=AgentRole.SOLVER, claim="x"),
    ]
    with pytest.raises(ValueError, match="conflicting"):
        collision_review_tasks(task, assess_proposals(task, same))
    different = [
        AgentProposal(task_id="t1", agent_id=str(i), role=AgentRole.SOLVER, claim=f"x+{i}")
        for i in range(3)
    ]
    with pytest.raises(ValueError, match="budget"):
        collision_review_tasks(task, assess_proposals(task, different), max_proposals=2)


def test_collision_review_rejects_mismatched_assessment():
    task = AgentTask(task_id="t1", role=AgentRole.SOLVER, goal="Find result")
    other = AgentTask(task_id="t2", role=AgentRole.SOLVER, goal="Other result")
    proposals = [
        AgentProposal(task_id="t2", agent_id="a", role=AgentRole.SOLVER, claim="x"),
        AgentProposal(task_id="t2", agent_id="b", role=AgentRole.SOLVER, claim="y"),
    ]
    assessment = assess_proposals(other, proposals)
    with pytest.raises(ValueError, match="does not match"):
        collision_review_tasks(task, assessment)



def test_scheduler_dispatches_only_dependency_ready_tasks():
    root = AgentTask(task_id="root", role=AgentRole.SOLVER, goal="Solve")
    child = AgentTask(task_id="child", role=AgentRole.CRITIC, goal="Review", depends_on=("root",))
    records = initialize_task_records([child, root])
    running = dispatch_ready_tasks([child, root], records, now=10, max_concurrency=2)
    state = {record.task_id: record for record in running}
    assert state["root"].status == TaskStatus.RUNNING
    assert state["child"].status == TaskStatus.PENDING
    proposal = AgentProposal(task_id="root", agent_id="solver", role=AgentRole.SOLVER, claim="candidate")
    completed = complete_task(root, running, proposal)
    ready = dispatch_ready_tasks([child, root], completed, now=11, max_concurrency=2)
    state = {record.task_id: record for record in ready}
    assert state["root"].status == TaskStatus.COMPLETED
    assert state["child"].status == TaskStatus.RUNNING


def test_scheduler_enforces_concurrency_and_deterministic_order():
    tasks = [
        AgentTask(task_id="a", role=AgentRole.SOLVER, goal="A"),
        AgentTask(task_id="b", role=AgentRole.SOLVER, goal="B"),
        AgentTask(task_id="c", role=AgentRole.SOLVER, goal="C"),
    ]
    records = initialize_task_records(tasks)
    dispatched = dispatch_ready_tasks(tasks, records, now=1, max_concurrency=2)
    state = {record.task_id: record for record in dispatched}
    assert state["a"].status == TaskStatus.RUNNING
    assert state["b"].status == TaskStatus.RUNNING
    assert state["c"].status == TaskStatus.PENDING


def test_scheduler_retries_timeouts_only_within_attempt_budget():
    task = AgentTask(task_id="slow", role=AgentRole.SOLVER, goal="Slow task", timeout_seconds=5)
    records = initialize_task_records([task])
    first = dispatch_ready_tasks([task], records, now=10, max_attempts=2)
    assert first[0].status == TaskStatus.RUNNING
    second = dispatch_ready_tasks([task], first, now=15, max_attempts=2)
    assert second[0].status == TaskStatus.RUNNING
    assert second[0].attempt == 2
    exhausted = dispatch_ready_tasks([task], second, now=20, max_attempts=2)
    assert exhausted[0].status == TaskStatus.TIMED_OUT
    assert exhausted[0].attempt == 2


def test_scheduler_failure_blocks_dependent_tasks():
    root = AgentTask(task_id="root", role=AgentRole.SOLVER, goal="Solve")
    child = AgentTask(task_id="child", role=AgentRole.CRITIC, goal="Review", depends_on=("root",))
    records = initialize_task_records([root, child])
    running = dispatch_ready_tasks([root, child], records, now=1)
    failed = fail_task(root, running, error="provider unavailable")
    next_state = dispatch_ready_tasks([root, child], failed, now=2)
    state = {record.task_id: record for record in next_state}
    assert state["root"].status == TaskStatus.FAILED
    assert state["child"].status == TaskStatus.PENDING


def test_scheduler_rejects_mismatched_proposal_and_nonrunning_completion():
    task = AgentTask(task_id="task", role=AgentRole.SOLVER, goal="Solve")
    records = initialize_task_records([task])
    wrong = AgentProposal(task_id="other", agent_id="agent", role=AgentRole.SOLVER, claim="x")
    with pytest.raises(ValueError, match="only a running"):
        complete_task(task, records, wrong)
    running = dispatch_ready_tasks([task], records, now=1)
    with pytest.raises(ValueError, match="does not match"):
        complete_task(task, running, wrong)


def test_scheduler_rejects_duplicate_or_missing_records():
    task = AgentTask(task_id="task", role=AgentRole.SOLVER, goal="Solve")
    with pytest.raises(ValueError, match="match task IDs"):
        dispatch_ready_tasks([task], (), now=1)
    duplicate = (TaskRunRecord(task_id="task"), TaskRunRecord(task_id="task"))
    with pytest.raises(ValueError, match="match task IDs"):
        dispatch_ready_tasks([task], duplicate, now=1)



def _completed_review_fixture():
    original = AgentTask(task_id="root-review", role=AgentRole.SOLVER, goal="Solve theorem")
    reviews = [
        AgentTask(task_id="critic-a", role=AgentRole.CRITIC, goal="Audit A", depends_on=(original.task_id,)),
        AgentTask(task_id="critic-b", role=AgentRole.CRITIC, goal="Audit B", depends_on=(original.task_id,)),
    ]
    tasks = [original, *reviews]
    records = initialize_task_records(tasks)
    records = dispatch_ready_tasks(tasks, records, now=1, max_concurrency=3)
    root_proposal = AgentProposal(
        task_id=original.task_id, agent_id="solver", role=AgentRole.SOLVER, claim="candidate"
    )
    records = complete_task(original, records, root_proposal)
    records = dispatch_ready_tasks(tasks, records, now=2, max_concurrency=3)
    for index, review in enumerate(reviews):
        proposal = AgentProposal(
            task_id=review.task_id,
            agent_id=f"critic-{index}",
            role=AgentRole.CRITIC,
            claim="reviewed",
            findings=(
                ReviewFinding(
                    finding_id=f"finding-{index}",
                    kind=ReviewFindingKind.DERIVATION_GAP,
                    statement=f"Check derivation step {index}",
                    evidence_refs=(f"source:{index}",),
                ),
            ),
        )
        records = complete_task(review, records, proposal)
    return original, reviews, records


def test_completed_reviews_route_only_explicit_typed_findings():
    original, reviews, records = _completed_review_fixture()
    review_records = tuple(r for r in records if r.task_id != original.task_id)
    assessment = assess_completed_reviews(original, reviews, review_records)
    assert assessment.completed_review_count == 2
    assert len(assessment.obligations) == 2
    assert assessment.disposition == "independent-checks-required"
    assert assessment.mathematical_status == "EXPERIMENTAL"
    tasks = obligation_verification_tasks(original, assessment)
    assert len(tasks) == 2
    assert all(task.role == AgentRole.VERIFIER for task in tasks)
    assert tasks[0].depends_on == (original.task_id, reviews[0].task_id)
    assert validate_task_graph([original, *reviews, *tasks])


def test_review_assessment_requires_every_expected_critic_result():
    original, reviews, records = _completed_review_fixture()
    partial = tuple(r for r in records if r.task_id == reviews[0].task_id)
    with pytest.raises(ValueError, match="exactly"):
        assess_completed_reviews(original, reviews, partial)


def test_review_assessment_rejects_wrong_role_or_task_proposal():
    original, reviews, records = _completed_review_fixture()
    bad = list(records)
    index = next(i for i, record in enumerate(bad) if record.task_id == reviews[0].task_id)
    bad[index] = bad[index].model_copy(update={
        "proposal": AgentProposal(
            task_id=reviews[0].task_id,
            agent_id="wrong",
            role=AgentRole.SOLVER,
            claim="not a critic",
        )
    })
    review_records = tuple(r for r in bad if r.task_id != original.task_id)
    with pytest.raises(ValueError, match="does not match"):
        assess_completed_reviews(original, reviews, review_records)


def test_untyped_narrative_does_not_become_an_obligation():
    original = AgentTask(task_id="root", role=AgentRole.SOLVER, goal="Solve")
    critic = AgentTask(task_id="critic", role=AgentRole.CRITIC, goal="Review", depends_on=("root",))
    records = initialize_task_records([original, critic])
    records = dispatch_ready_tasks([original, critic], records, now=1)
    records = complete_task(original, records, AgentProposal(
        task_id="root", agent_id="solver", role=AgentRole.SOLVER, claim="candidate"
    ))
    records = dispatch_ready_tasks([original, critic], records, now=2)
    records = complete_task(critic, records, AgentProposal(
        task_id="critic", agent_id="critic-agent", role=AgentRole.CRITIC,
        claim="There may be a gap, please investigate.",
    ))
    assessment = assess_completed_reviews(
        original, [critic], tuple(r for r in records if r.task_id == "critic")
    )
    assert assessment.obligations == ()
    assert assessment.disposition == "no-typed-checks-requested"


def test_obligation_verification_task_budget_is_enforced():
    original, reviews, records = _completed_review_fixture()
    assessment = assess_completed_reviews(
        original, reviews, tuple(r for r in records if r.task_id != original.task_id)
    )
    with pytest.raises(ValueError, match="budget"):
        obligation_verification_tasks(original, assessment, max_obligations=1)



def test_verifier_routing_rejects_forged_obligation_provenance():
    from mosaic.core.orchestration import ReviewAssessment

    original, reviews, records = _completed_review_fixture()
    assessment = assess_completed_reviews(
        original, reviews, tuple(r for r in records if r.task_id != original.task_id)
    )
    forged = assessment.model_copy(update={
        "obligations": (
            assessment.obligations[0].model_copy(update={"source_task_id": "unknown-review"}),
        )
    })
    with pytest.raises(ValueError, match="source"):
        obligation_verification_tasks(original, forged)



def test_review_assessment_rejects_empty_and_noncritic_review_sets():
    original = AgentTask(task_id="root-x", role=AgentRole.SOLVER, goal="Solve")
    with pytest.raises(ValueError, match="at least one"):
        assess_completed_reviews(original, [], ())
    solver_task = AgentTask(task_id="solver-review", role=AgentRole.SOLVER, goal="Not a critic", depends_on=("root-x",))
    with pytest.raises(ValueError, match="critic role"):
        assess_completed_reviews(original, [solver_task], ())


def test_review_assessment_rejects_critic_without_original_dependency():
    original = AgentTask(task_id="root-y", role=AgentRole.SOLVER, goal="Solve")
    critic = AgentTask(task_id="orphan-critic", role=AgentRole.CRITIC, goal="Review")
    with pytest.raises(ValueError, match="depend on the original"):
        assess_completed_reviews(original, [critic], ())


def test_review_assessment_rejects_running_or_failed_critic():
    original, reviews, records = _completed_review_fixture()
    incomplete = tuple(
        record.model_copy(update={"status": TaskStatus.RUNNING, "proposal": None,
                                  "started_at": 1.0, "deadline_at": 20.0})
        if record.task_id == reviews[0].task_id else record
        for record in records if record.task_id != original.task_id
    )
    with pytest.raises(ValueError, match="not completed"):
        assess_completed_reviews(original, reviews, incomplete)


def test_review_assessment_enforces_finding_budget():
    original = AgentTask(task_id="root-budget", role=AgentRole.SOLVER, goal="Solve")
    critic = AgentTask(task_id="critic-budget", role=AgentRole.CRITIC, goal="Review", depends_on=("root-budget",))
    records = initialize_task_records([original, critic])
    records = dispatch_ready_tasks([original, critic], records, now=1)
    records = complete_task(original, records, AgentProposal(
        task_id="root-budget", agent_id="solver", role=AgentRole.SOLVER, claim="candidate"
    ))
    records = dispatch_ready_tasks([original, critic], records, now=2)
    records = complete_task(critic, records, AgentProposal(
        task_id="critic-budget", agent_id="critic", role=AgentRole.CRITIC, claim="review",
        findings=tuple(
            ReviewFinding(finding_id=f"f-{i}", kind=ReviewFindingKind.UNRESOLVED, statement=f"Check {i}")
            for i in range(2)
        ),
    ))
    with pytest.raises(ValueError, match="budget"):
        assess_completed_reviews(original, [critic], (next(r for r in records if r.task_id == critic.task_id),), max_findings=1)


def test_review_assessment_rejects_duplicate_review_task_ids():
    original, reviews, records = _completed_review_fixture()
    with pytest.raises(ValueError, match="unique"):
        assess_completed_reviews(original, [reviews[0], reviews[0]], ())


def test_obligation_routing_rejects_oversized_finding_context():
    from mosaic.core.orchestration import ReviewAssessment, ReviewObligation

    original = AgentTask(task_id="root-large", role=AgentRole.SOLVER, goal="Solve")
    finding = ReviewFinding(
        finding_id="huge",
        kind=ReviewFindingKind.EVIDENCE_REQUIRED,
        statement="x" * 4000,
        evidence_refs=("e" * 2500,),
    )
    digest = __import__("hashlib").sha256(b"critic-large:huge").hexdigest()[:12]
    assessment = ReviewAssessment(
        original_task_id=original.task_id,
        review_task_ids=("critic-large",),
        completed_review_count=1,
        obligations=(ReviewObligation(
            obligation_id=f"obligation-{digest}",
            source_task_id="critic-large",
            source_agent_id="critic",
            finding=finding,
        ),),
        disposition="independent-checks-required",
    )
    with pytest.raises(ValueError, match="size limit"):
        obligation_verification_tasks(original, assessment)


def test_review_assessment_rejects_malformed_proposal_status_and_missing_proposal():
    original, reviews, records = _completed_review_fixture()
    no_proposal = tuple(
        record.model_copy(update={"proposal": None})
        if record.task_id == reviews[0].task_id else record
        for record in records if record.task_id != original.task_id
    )
    with pytest.raises(ValueError, match="not completed"):
        assess_completed_reviews(original, reviews, no_proposal)
