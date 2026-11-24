"""Trust-aware contracts for delegating mathematical work to agents.

This module plans and records proposals; it does not execute agents or prove theorems.
"""
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
    # Preserve the complete immutable inputs and their original ordering.
    preserved_proposals: tuple[AgentProposal, ...] = ()
    # Each group contains indexes into preserved_proposals for one normalized claim.
    claim_groups: tuple[tuple[int, ...], ...] = ()
    conflicting_proposal_indices: tuple[int, ...] = ()


def _claim_key(claim: str) -> str:
    """Normalize presentation whitespace only; never rewrite mathematical syntax."""
    return " ".join(claim.split())


def assess_proposals(task: AgentTask, proposals: list[AgentProposal]) -> ProposalAssessment:
    """Detect incompatible claims while preserving every proposal and its provenance.

    Whitespace-only differences are grouped together. Case, symbols, and mathematical
    structure are preserved because changing them could change the meaning of a claim.
    """
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
