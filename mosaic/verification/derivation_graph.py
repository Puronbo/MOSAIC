"""Compile recursive derivations into dependency-aware obligation graphs."""
from __future__ import annotations

from mosaic.core.requests import MathRequest
from mosaic.engines.algebra import ExpressionError
from mosaic.verification.decomposition import get_decomposition_rule
from mosaic.verification.derivation import (
    DerivationNode,
    DerivationTree,
    validate_derivation_tree,
)
from mosaic.verification.graph import (
    ObligationGraph,
    ObligationNode,
    RuleSideConditionNode,
    ObligationGraphResult,
    evaluate_obligation_graph,
)
from mosaic.verification.obligations import obligations_for_request
from mosaic.verification.side_conditions import RuleSideCondition


def _leaf_requests(node: DerivationNode) -> tuple[MathRequest, ...]:
    if not node.children:
        return (node.request,)
    return tuple(request for child in node.children for request in _leaf_requests(child))


def _collect_side_condition_nodes(node: DerivationNode) -> tuple[RuleSideConditionNode, ...]:
    collected: list[RuleSideConditionNode] = []
    if node.rule_id is not None:
        rule = get_decomposition_rule(node.rule_id)
        collected.extend(
            RuleSideConditionNode(request=node.request, condition=condition)
            for condition in rule.side_conditions(node.request)
        )
    for child in node.children:
        collected.extend(_collect_side_condition_nodes(child))
    return tuple(collected)


def compile_derivation_obligation_graph(
    request: MathRequest,
    tree: DerivationTree,
) -> ObligationGraph:
    """Compile leaves, rule dependencies, and unresolved rule preconditions."""
    if not validate_derivation_tree(request, tree):
        raise ExpressionError("Cannot compile an invalid or incomplete derivation tree.")

    requests_by_id: dict[str, MathRequest] = {}
    dependencies: dict[str, set[str]] = {}

    def add_leaf(leaf_request: MathRequest) -> str:
        obligation = obligations_for_request(leaf_request)[0]
        key = obligation.obligation_id
        existing = requests_by_id.get(key)
        if existing is not None and existing != leaf_request:
            raise ExpressionError("Obligation identifier collision between distinct requests.")
        requests_by_id[key] = leaf_request
        dependencies.setdefault(key, set())
        return key

    def compile_node(node: DerivationNode) -> tuple[str, ...]:
        if not node.children:
            return (add_leaf(node.request),)
        rule = get_decomposition_rule(node.rule_id or "")
        branch_ids = tuple(compile_node(child) for child in node.children)
        for target_index, prerequisite_indices in rule.dependency_policy(len(branch_ids)):
            if target_index < 0 or target_index >= len(branch_ids):
                raise ExpressionError("Registered dependency policy references an invalid child.")
            prerequisites: set[str] = set()
            for prerequisite_index in prerequisite_indices:
                if prerequisite_index < 0 or prerequisite_index >= len(branch_ids):
                    raise ExpressionError("Registered dependency policy references an invalid prerequisite.")
                prerequisites.update(branch_ids[prerequisite_index])
            for target_id in branch_ids[target_index]:
                dependencies[target_id].update(prerequisites - {target_id})
        return tuple(dict.fromkeys(key for branch in branch_ids for key in branch))

    compile_node(tree.root)
    nodes = tuple(
        ObligationNode(
            request=requests_by_id[key],
            obligation=obligations_for_request(requests_by_id[key])[0],
            depends_on=tuple(sorted(dependencies[key])),
        )
        for key in sorted(requests_by_id)
    )
    side_conditions = _collect_side_condition_nodes(tree.root)
    ids = [item.condition.condition_id for item in side_conditions]
    if len(ids) != len(set(ids)):
        raise ExpressionError("Duplicate side-condition identifier in derivation tree.")
    return ObligationGraph(nodes=nodes, side_conditions=side_conditions)


def side_conditions_for_derivation_tree(
    request: MathRequest,
    tree: DerivationTree,
) -> tuple[RuleSideCondition, ...]:
    """Return all registered rule preconditions in a validated derivation."""
    if not validate_derivation_tree(request, tree):
        raise ExpressionError("Cannot inspect side conditions for an invalid derivation tree.")
    return tuple(item.condition for item in _collect_side_condition_nodes(tree.root))


def evaluate_derivation_tree(
    request: MathRequest,
    tree: DerivationTree,
    candidates: dict[str, str],
) -> ObligationGraphResult:
    """Evaluate leaf checks; unresolved preconditions cap aggregate status."""
    graph = compile_derivation_obligation_graph(request, tree)
    return evaluate_obligation_graph(graph, candidates)
