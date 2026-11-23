"""Dependency-aware composition of request-bound verification obligations."""
from __future__ import annotations

from collections import defaultdict, deque
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from mosaic.core.requests import MathRequest
from mosaic.verification.obligations import (
    VerificationObligation,
    verify_obligation_candidate,
)
from mosaic.verification.side_conditions import (
    RuleSideCondition,
    verify_side_condition_contract,
)
from mosaic.verification.task_bound import TaskBoundCheck


class ObligationNode(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    request: MathRequest
    obligation: VerificationObligation
    depends_on: tuple[str, ...] = ()


class RuleSideConditionNode(BaseModel):
    """A rule precondition attached to the exact request that generated it."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    request: MathRequest
    condition: RuleSideCondition


class ObligationGraph(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    nodes: tuple[ObligationNode, ...] = Field(min_length=1)
    side_conditions: tuple[RuleSideConditionNode, ...] = ()


class ObligationNodeResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    obligation_id: str
    status: Literal[
        "EXPERIMENTAL", "INCOMPLETE", "INVALID_CERTIFICATE", "UNSUPPORTED"
    ]
    equal: bool | None = None
    explanation: str


class SideConditionResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    condition_id: str
    status: Literal["UNSUPPORTED"]
    explanation: str


class ObligationGraphResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    status: Literal[
        "EXPERIMENTAL", "INCOMPLETE", "INVALID_CERTIFICATE", "UNSUPPORTED"
    ]
    results: tuple[ObligationNodeResult, ...]
    execution_order: tuple[str, ...]
    side_condition_results: tuple[SideConditionResult, ...] = ()


def validate_obligation_graph(graph: ObligationGraph) -> tuple[ObligationNode, ...]:
    """Validate references, registered precondition contracts, and cycles."""
    by_id: dict[str, ObligationNode] = {}
    for node in graph.nodes:
        key = node.obligation.obligation_id
        if key in by_id:
            raise ValueError(f"duplicate obligation id: {key}")
        by_id[key] = node

    from mosaic.verification.decomposition import get_decomposition_rule

    condition_ids: set[str] = set()
    for item in graph.side_conditions:
        condition = item.condition
        if condition.condition_id in condition_ids:
            raise ValueError(f"duplicate side-condition id: {condition.condition_id}")
        condition_ids.add(condition.condition_id)
        try:
            rule = get_decomposition_rule(condition.rule_id)
            expected = rule.side_conditions(item.request)
        except (ValueError, TypeError) as exc:
            raise ValueError("side condition references an invalid registered rule") from exc
        if not verify_side_condition_contract(
            item.request, condition.rule_id, condition, expected
        ):
            raise ValueError(f"invalid side-condition contract: {condition.condition_id}")

    indegree = {key: 0 for key in by_id}
    dependents: dict[str, list[str]] = defaultdict(list)
    for key, node in by_id.items():
        if len(set(node.depends_on)) != len(node.depends_on):
            raise ValueError(f"duplicate dependency on node: {key}")
        for dependency in node.depends_on:
            if dependency not in by_id:
                raise ValueError(f"unknown dependency: {dependency}")
            if dependency == key:
                raise ValueError(f"self-dependency: {key}")
            indegree[key] += 1
            dependents[dependency].append(key)

    ready = deque(key for key in by_id if indegree[key] == 0)
    ordered: list[ObligationNode] = []
    while ready:
        key = ready.popleft()
        ordered.append(by_id[key])
        for child in dependents[key]:
            indegree[child] -= 1
            if indegree[child] == 0:
                ready.append(child)

    if len(ordered) != len(by_id):
        raise ValueError("obligation graph contains a cycle")
    return tuple(ordered)


def evaluate_obligation_graph(
    graph: ObligationGraph,
    candidates: dict[str, str],
) -> ObligationGraphResult:
    """Evaluate algebraic obligations while retaining unresolved rule preconditions.

    An unresolved side condition never blocks diagnostic checking of algebraic
    leaves, but it prevents the aggregate graph from being reported satisfied.
    """
    ordered = validate_obligation_graph(graph)
    results: dict[str, ObligationNodeResult] = {}
    for node in ordered:
        obligation_id = node.obligation.obligation_id
        blocked = [
            dep for dep in node.depends_on
            if results[dep].status != "EXPERIMENTAL" or results[dep].equal is not True
        ]
        if blocked:
            result = ObligationNodeResult(
                obligation_id=obligation_id,
                status="INCOMPLETE",
                explanation="Blocked by unsatisfied dependencies: " + ", ".join(blocked),
            )
        elif obligation_id not in candidates:
            result = ObligationNodeResult(
                obligation_id=obligation_id,
                status="INCOMPLETE",
                explanation="No candidate was supplied for this obligation.",
            )
        else:
            checked: TaskBoundCheck = verify_obligation_candidate(
                node.request, node.obligation, candidates[obligation_id]
            )
            result = ObligationNodeResult(
                obligation_id=obligation_id,
                status=checked.status,
                equal=checked.equal,
                explanation=checked.explanation,
            )
        results[obligation_id] = result

    ordered_results = tuple(results[node.obligation.obligation_id] for node in ordered)
    statuses = {result.status for result in ordered_results}
    if "INVALID_CERTIFICATE" in statuses:
        overall = "INVALID_CERTIFICATE"
    elif "UNSUPPORTED" in statuses or graph.side_conditions:
        overall = "UNSUPPORTED"
    elif all(result.status == "EXPERIMENTAL" and result.equal is True for result in ordered_results):
        overall = "EXPERIMENTAL"
    else:
        overall = "INCOMPLETE"

    side_results = tuple(
        SideConditionResult(
            condition_id=item.condition.condition_id,
            status="UNSUPPORTED",
            explanation=item.condition.statement,
        )
        for item in graph.side_conditions
    )
    return ObligationGraphResult(
        status=overall,
        results=ordered_results,
        execution_order=tuple(node.obligation.obligation_id for node in ordered),
        side_condition_results=side_results,
    )
