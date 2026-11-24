import pytest
from pydantic import ValidationError

from mosaic.core.orchestration import (
    AgentProposal, AgentRole, AgentTask, assess_proposals, validate_task_graph,
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
