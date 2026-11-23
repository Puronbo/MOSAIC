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


def test_disagreement_triggers_review():
    task = AgentTask(task_id="t1", role=AgentRole.SOLVER, goal="Find result")
    proposals = [
        AgentProposal(task_id="t1", agent_id="a", role=AgentRole.SOLVER, claim="x+1"),
        AgentProposal(task_id="t1", agent_id="b", role=AgentRole.SOLVER, claim="x-1"),
    ]
    assert assess_proposals(task, proposals).disposition == "needs-adversarial-review"


def test_task_contract_rejects_extra_fields():
    with pytest.raises(ValidationError):
        AgentTask(task_id="t", role=AgentRole.SOLVER, goal="g", admin=True)
