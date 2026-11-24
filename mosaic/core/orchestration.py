"""Trust-aware contracts and deterministic scheduling for mathematical agents.

This module plans and records proposals; provider execution and proof checking are external.
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


class ReviewFindingKind(StrEnum):
    DERIVATION_GAP = "derivation-gap"
    UNSUPPORTED_ASSUMPTION = "unsupported-assumption"
    COUNTEREXAMPLE = "counterexample"
    EVIDENCE_REQUIRED = "evidence-required"
    UNRESOLVED = "unresolved"


class ReviewFinding(BaseModel):
    """A reviewer-authored, explicitly typed issue; still untrusted evidence."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: str = Field(min_length=1, max_length=80)
    kind: ReviewFindingKind
    statement: str = Field(min_length=1, max_length=4000)
    requires_independent_check: bool = True
    evidence_refs: tuple[str, ...] = ()


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
    findings: tuple[ReviewFinding, ...] = ()
    status: TaskStatus = TaskStatus.COMPLETED


class ReviewObligation(BaseModel):
    """A review finding routed for independent checking, with its provenance."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    obligation_id: str
    source_task_id: str
    source_agent_id: str
    finding: ReviewFinding


class ReviewAssessment(BaseModel):
    """Structured aggregation of completed reviews; never a proof verdict."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    original_task_id: str
    review_task_ids: tuple[str, ...]
    completed_review_count: int = Field(ge=0)
    obligations: tuple[ReviewObligation, ...] = ()
    disposition: str
    mathematical_status: str = "EXPERIMENTAL"


class TaskRunRecord(BaseModel):
    """Immutable scheduler state for one task attempt."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    task_id: str
    status: TaskStatus = TaskStatus.PENDING
    attempt: int = Field(default=0, ge=0)
    started_at: float | None = None
    deadline_at: float | None = None
    proposal: AgentProposal | None = None
    error: str | None = Field(default=None, max_length=2000)

    @model_validator(mode="after")
    def validate_timing(self):
        if self.status == TaskStatus.RUNNING:
            if self.started_at is None or self.deadline_at is None:
                raise ValueError("running tasks require start and deadline timestamps")
            if self.deadline_at <= self.started_at:
                raise ValueError("task deadline must follow its start")
        return self


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
    """Create bounded critic tasks plus a dependent review-synthesis task."""
    if assessment.task_id != task.task_id:
        raise ValueError("assessment task_id does not match task")
    if not assessment.conflict_detected or assessment.disposition != "needs-adversarial-review":
        raise ValueError("collision review requires a conflicting assessment")
    if assessment.proposal_count != len(assessment.preserved_proposals):
        raise ValueError("assessment proposal records are incomplete")
    if max_proposals < 1 or assessment.proposal_count > max_proposals:
        raise ValueError("collision exceeds the configured proposal review budget")
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

    synthesis = AgentTask(
        task_id=f"collision-{seed}-synthesis",
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


def initialize_task_records(tasks: list[AgentTask]) -> tuple[TaskRunRecord, ...]:
    """Create pending records in deterministic topological order."""
    return tuple(TaskRunRecord(task_id=task_id) for task_id in validate_task_graph(tasks))


def dispatch_ready_tasks(
    tasks: list[AgentTask],
    records: tuple[TaskRunRecord, ...],
    *,
    now: float,
    max_concurrency: int = 4,
    max_attempts: int = 2,
) -> tuple[TaskRunRecord, ...]:
    """Expire deadlines, retry within budget, and dispatch ready tasks deterministically.

    The caller supplies a monotonic clock value and performs provider calls separately.
    A task is ready only after every dependency is COMPLETED. Failed or exhausted
    dependencies block descendants rather than being treated as successful.
    """
    if now < 0 or max_concurrency < 1 or max_attempts < 1:
        raise ValueError("invalid scheduler clock or budget")
    order = validate_task_graph(tasks)
    by_task = {task.task_id: task for task in tasks}
    by_record = {record.task_id: record for record in records}
    if len(by_record) != len(records) or set(by_record) != set(by_task):
        raise ValueError("scheduler records must match task IDs exactly")

    updated = dict(by_record)
    for task_id, record in updated.items():
        if record.status == TaskStatus.RUNNING and record.deadline_at <= now:
            updated[task_id] = record.model_copy(
                update={"status": TaskStatus.TIMED_OUT, "error": "deadline exceeded"}
            )
        record = updated[task_id]
        if record.status == TaskStatus.TIMED_OUT and record.attempt < max_attempts:
            updated[task_id] = record.model_copy(
                update={
                    "status": TaskStatus.PENDING,
                    "started_at": None,
                    "deadline_at": None,
                    "error": None,
                }
            )

    running = sum(record.status == TaskStatus.RUNNING for record in updated.values())
    capacity = max(0, max_concurrency - running)
    for task_id in order:
        if capacity == 0:
            break
        record = updated[task_id]
        task = by_task[task_id]
        if record.status != TaskStatus.PENDING:
            continue
        if not all(updated[dep].status == TaskStatus.COMPLETED for dep in task.depends_on):
            continue
        updated[task_id] = record.model_copy(
            update={
                "status": TaskStatus.RUNNING,
                "attempt": record.attempt + 1,
                "started_at": now,
                "deadline_at": now + task.timeout_seconds,
                "proposal": None,
                "error": None,
            }
        )
        capacity -= 1
    return tuple(updated[task_id] for task_id in order)


def complete_task(
    task: AgentTask,
    records: tuple[TaskRunRecord, ...],
    proposal: AgentProposal,
) -> tuple[TaskRunRecord, ...]:
    """Record one untrusted proposal for a currently running matching task."""
    by_record = {record.task_id: record for record in records}
    if len(by_record) != len(records) or task.task_id not in by_record:
        raise ValueError("scheduler record for task is missing or duplicated")
    record = by_record[task.task_id]
    if record.status != TaskStatus.RUNNING:
        raise ValueError("only a running task can be completed")
    if proposal.task_id != task.task_id:
        raise ValueError("proposal task_id does not match task")
    if proposal.role != task.role:
        raise ValueError("proposal role does not match task role")
    by_record[task.task_id] = record.model_copy(
        update={"status": TaskStatus.COMPLETED, "proposal": proposal}
    )
    return tuple(by_record[item.task_id] for item in records)


def fail_task(
    task: AgentTask,
    records: tuple[TaskRunRecord, ...],
    *,
    error: str,
) -> tuple[TaskRunRecord, ...]:
    """Record a bounded failure; failures are not silently retried or treated as success."""
    by_record = {record.task_id: record for record in records}
    if len(by_record) != len(records) or task.task_id not in by_record:
        raise ValueError("scheduler record for task is missing or duplicated")
    record = by_record[task.task_id]
    if record.status != TaskStatus.RUNNING:
        raise ValueError("only a running task can fail")
    by_record[task.task_id] = record.model_copy(
        update={"status": TaskStatus.FAILED, "error": error[:2000]}
    )
    return tuple(by_record[item.task_id] for item in records)


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


def assess_completed_reviews(
    original_task: AgentTask,
    review_tasks: list[AgentTask],
    records: tuple[TaskRunRecord, ...],
    *,
    max_findings: int = 64,
) -> ReviewAssessment:
    """Require every expected critic result and extract only typed check requests.

    Natural-language claims, reviewer consensus, and synthesis prose are not parsed
    into proof obligations. Only explicit ReviewFinding records are routed onward.
    """
    if max_findings < 1:
        raise ValueError("max_findings must be positive")
    if not review_tasks:
        raise ValueError("at least one review task is required")
    task_ids = [task.task_id for task in review_tasks]
    if len(set(task_ids)) != len(task_ids):
        raise ValueError("review task IDs must be unique")
    if any(task.role != AgentRole.CRITIC for task in review_tasks):
        raise ValueError("all review tasks must have the critic role")
    if any(original_task.task_id not in task.depends_on for task in review_tasks):
        raise ValueError("each review task must depend on the original task")

    by_record = {record.task_id: record for record in records}
    if len(by_record) != len(records) or set(by_record) != set(task_ids):
        raise ValueError("review records must match expected task IDs exactly")

    obligations: list[ReviewObligation] = []
    seen_finding_ids: set[tuple[str, str]] = set()
    for task in review_tasks:
        record = by_record[task.task_id]
        if record.status != TaskStatus.COMPLETED or record.proposal is None:
            raise ValueError(f"review task {task.task_id} is not completed")
        proposal = record.proposal
        if proposal.task_id != task.task_id or proposal.role != AgentRole.CRITIC:
            raise ValueError("review proposal does not match its critic task")
        for finding in proposal.findings:
            key = (task.task_id, finding.finding_id)
            if key in seen_finding_ids:
                raise ValueError("duplicate finding ID within a review task")
            seen_finding_ids.add(key)
            if finding.requires_independent_check:
                if len(obligations) >= max_findings:
                    raise ValueError("review findings exceed the configured budget")
                digest = hashlib.sha256(
                    f"{task.task_id}:{finding.finding_id}".encode("utf-8")
                ).hexdigest()[:12]
                obligations.append(
                    ReviewObligation(
                        obligation_id=f"obligation-{digest}",
                        source_task_id=task.task_id,
                        source_agent_id=proposal.agent_id,
                        finding=finding,
                    )
                )

    return ReviewAssessment(
        original_task_id=original_task.task_id,
        review_task_ids=tuple(task_ids),
        completed_review_count=len(review_tasks),
        obligations=tuple(obligations),
        disposition=(
            "independent-checks-required" if obligations else "no-typed-checks-requested"
        ),
        mathematical_status="EXPERIMENTAL",
    )


def obligation_verification_tasks(
    original_task: AgentTask,
    assessment: ReviewAssessment,
    *,
    max_obligations: int = 32,
) -> list[AgentTask]:
    """Route explicit review findings to bounded verifier tasks, preserving provenance."""
    if assessment.original_task_id != original_task.task_id:
        raise ValueError("review assessment belongs to another original task")
    if assessment.completed_review_count != len(assessment.review_task_ids):
        raise ValueError("review assessment is incomplete")
    if len(set(assessment.review_task_ids)) != len(assessment.review_task_ids):
        raise ValueError("review assessment contains duplicate task IDs")
    if max_obligations < 1 or len(assessment.obligations) > max_obligations:
        raise ValueError("verification obligation budget exceeded")

    tasks: list[AgentTask] = []
    seen_ids: set[str] = set()
    for obligation in assessment.obligations:
        if obligation.obligation_id in seen_ids:
            raise ValueError("duplicate obligation ID")
        seen_ids.add(obligation.obligation_id)
        if obligation.source_task_id not in assessment.review_task_ids:
            raise ValueError("obligation source is not in the completed review set")
        if not obligation.finding.requires_independent_check:
            raise ValueError("non-actionable finding cannot become a verifier task")
        expected_digest = hashlib.sha256(
            f"{obligation.source_task_id}:{obligation.finding.finding_id}".encode("utf-8")
        ).hexdigest()[:12]
        if obligation.obligation_id != f"obligation-{expected_digest}":
            raise ValueError("obligation ID does not match its source finding")
        payload = json.dumps(
            {
                "obligation_id": obligation.obligation_id,
                "source_task_id": obligation.source_task_id,
                "source_agent_id": obligation.source_agent_id,
                "finding_id": obligation.finding.finding_id,
                "kind": obligation.finding.kind.value,
                "statement": obligation.finding.statement,
                "evidence_refs": list(obligation.finding.evidence_refs),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
        if len(payload) > 6000:
            raise ValueError("verification context exceeds the task size limit")
        tasks.append(
            AgentTask(
                task_id=obligation.obligation_id,
                role=AgentRole.VERIFIER,
                goal=(
                    "Independently check this explicitly reported review obligation. "
                    "Return the method, assumptions, and checkable evidence; do not "
                    "treat the originating reviewer statement as established."
                ),
                context=payload,
                depends_on=(original_task.task_id, obligation.source_task_id),
                max_tokens=2500,
                timeout_seconds=45,
            )
        )
    validate_task_graph([original_task, *[
        AgentTask(
            task_id=task_id,
            role=AgentRole.CRITIC,
            goal="Completed source review task.",
            depends_on=(original_task.task_id,),
        )
        for task_id in assessment.review_task_ids
    ], *tasks])
    return tasks
