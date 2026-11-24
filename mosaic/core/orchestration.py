"""Trust-aware contracts for delegating mathematical work to agents.

This module plans and records proposals; it does not execute agents or prove theorems.
"""
import hashlib
import json
from enum import StrEnum
from pydantic import BaseModel, ConfigDict, Field, model_validator


class AgentRole(StrEnum):
    DECOMPOSER = "decomposer"
    SOLVER = "solver"
    CRITIC = "critic"
    VERIFIER = "verifier"


class TaskStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"


class AgentTask(BaseModel):
    """A bounded, auditable unit of mathematical work."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    task_id: str = Field(min_length=1, max_length=80)
    role: AgentRole
    goal: str = Field(min_length=1, max_length=4000)
    context: str = Field(default="", max_length=12000)
    assumptions: tuple[str, ...] = ()
    depends_on: tuple[str, ...] = ()
    max_tokens: int = Field(default=2000, ge=1, le=20000)
    timeout_seconds: int = Field(default=30, ge=1, le=300)

    @model_validator(mode="after")
    def no_self_dependency(self):
        if self.task_id in self.depends_on:
            raise ValueError("a task cannot depend on itself")
        if len(set(self.depends_on)) != len(self.depends_on):
            raise ValueError("depends_on must not contain duplicates")
        return self


class AgentProposal(BaseModel):
    """Untrusted output from one agent; never a proof certificate."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    task_id: str
    agent_id: str = Field(min_length=1, max_length=120)
    role: AgentRole
    claim: str = Field(min_length=1, max_length=8000)
    rationale: str = Field(default="", max_length=12000)
    assumptions: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()
    status: TaskStatus = TaskStatus.COMPLETED


class ProposalAssessment(BaseModel):
    """A conservative aggregation record, not a mathematical verdict."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    task_id: str
    proposal_count: int = Field(ge=0)
    distinct_claim_count: int = Field(ge=0)
    conflict_detected: bool
    disposition: str
    mathematical_status: str = "EXPERIMENTAL"
    preserved_proposals: tuple[AgentProposal, ...] = ()
    claim_groups: tuple[tuple[int, ...], ...] = ()
    conflicting_proposal_indices: tuple[int, ...] = ()


def _claim_key(claim: str) -> str:
    """Normalize presentation whitespace only; never rewrite mathematical syntax."""
    return " ".join(claim.split())


def assess_proposals(task: AgentTask, proposals: list[AgentProposal]) -> ProposalAssessment:
    """Detect incompatible claims while preserving every proposal and its provenance."""
    for proposal in proposals:
        if proposal.task_id != task.task_id:
            raise ValueError("proposal task_id does not match task")

    grouped: dict[str, list[int]] = {}
    for index, proposal in enumerate(proposals):
        grouped.setdefault(_claim_key(proposal.claim), []).append(index)
    groups = tuple(tuple(indices) for indices in grouped.values())
    conflict = len(groups) > 1
    conflicting_indices = tuple(
        index for group in groups for index in group
    ) if conflict else ()

    if not proposals:
        disposition = "no-proposals"
    elif conflict:
        disposition = "needs-adversarial-review"
    else:
        disposition = "candidate-for-independent-check"
    return ProposalAssessment(
        task_id=task.task_id,
        proposal_count=len(proposals),
        distinct_claim_count=len(groups),
        conflict_detected=conflict,
        disposition=disposition,
        mathematical_status="EXPERIMENTAL",
        preserved_proposals=tuple(proposals),
        claim_groups=groups,
        conflicting_proposal_indices=conflicting_indices,
    )


def collision_review_tasks(
    task: AgentTask,
    assessment: ProposalAssessment,
    *,
    max_proposals: int = 16,
) -> list[AgentTask]:
    """Create bounded critic tasks plus a dependent review-synthesis task.

    Each critic receives exactly one original proposal as untrusted data. The synthesis
    task depends on all critic tasks and the original task. IDs are deterministic and
    content-derived so plans can be replayed; no model/provider is invoked here.
    """
    if assessment.task_id != task.task_id:
        raise ValueError("assessment task_id does not match task")
    if not assessment.conflict_detected or assessment.disposition != "needs-adversarial-review":
        raise ValueError("collision review requires a conflicting assessment")
    if assessment.proposal_count != len(assessment.preserved_proposals):
        raise ValueError("assessment proposal records are incomplete")
    if assessment.proposal_count > max_proposals:
        raise ValueError("collision exceeds the configured proposal review budget")
    if max_proposals < 1:
        raise ValueError("max_proposals must be positive")
    if any(p.task_id != task.task_id for p in assessment.preserved_proposals):
        raise ValueError("assessment contains a proposal for another task")

    seed = hashlib.sha256(task.task_id.encode("utf-8")).hexdigest()[:16]
    critic_tasks: list[AgentTask] = []
    for index in assessment.conflicting_proposal_indices:
        if index < 0 or index >= len(assessment.preserved_proposals):
            raise ValueError("assessment contains an invalid conflicting proposal index")
        proposal = assessment.preserved_proposals[index]
        payload = json.dumps(
            {
                "proposal_index": index,
                "agent_id": proposal.agent_id,
                "role": proposal.role.value,
                "claim": proposal.claim,
                "assumptions": list(proposal.assumptions),
                "evidence_refs": list(proposal.evidence_refs),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
        if len(payload) > 12000:
            raise ValueError("proposal context exceeds the review task size limit")
        critic_tasks.append(
            AgentTask(
                task_id=f"collision-{seed}-p{index}-critic",
                role=AgentRole.CRITIC,
                goal=(
                    "Independently audit this proposal: test its derivation, expose hidden "
                    "assumptions, seek counterexamples, and identify evidence a separate "
                    "checker would need. Do not treat the claim as established."
                ),
                context=payload,
                depends_on=(task.task_id,),
                max_tokens=2000,
                timeout_seconds=30,
            )
        )

    synthesis_id = f"collision-{seed}-synthesis"
    synthesis = AgentTask(
        task_id=synthesis_id,
        role=AgentRole.CRITIC,
        goal=(
            "Compare all independent collision reviews. Map disagreements, unresolved "
            "assumptions, counterexamples, and required independent checks. Do not select "
            "a winner by vote and do not claim formal verification."
        ),
        context=json.dumps(
            {
                "original_task_id": task.task_id,
                "proposal_count": assessment.proposal_count,
                "distinct_claim_count": assessment.distinct_claim_count,
            },
            sort_keys=True,
        ),
        depends_on=(task.task_id, *(review.task_id for review in critic_tasks)),
        max_tokens=3000,
        timeout_seconds=45,
    )
    return [*critic_tasks, synthesis]


def validate_task_graph(tasks: list[AgentTask]) -> list[str]:
    """Validate unique IDs, known dependencies, and acyclicity; return stable order."""
    by_id = {task.task_id: task for task in tasks}
    if len(by_id) != len(tasks):
        raise ValueError("task_id values must be unique")
    for task in tasks:
        missing = set(task.depends_on) - by_id.keys()
        if missing:
            raise ValueError(f"unknown dependencies for {task.task_id}: {sorted(missing)}")

    ordered: list[str] = []
    temporary: set[str] = set()
    permanent: set[str] = set()

    def visit(task_id: str) -> None:
        if task_id in permanent:
            return
        if task_id in temporary:
            raise ValueError("task dependency graph contains a cycle")
        temporary.add(task_id)
        for dependency in sorted(by_id[task_id].depends_on):
            visit(dependency)
        temporary.remove(task_id)
        permanent.add(task_id)
        ordered.append(task_id)

    for task_id in sorted(by_id):
        visit(task_id)
    return ordered
