"""Compile a complete derivation tree into a dependency-aware obligation DAG.

Only terminal derivation requests become checker obligations. Composition
obligations are gated on the terminal obligations of their prerequisite
branches. This is a structural compilation contract, not a proof system.
"""
from __future__ import annotations

from mosaic.core.requests import MathRequest
from mosaic.engines.algebra import ExpressionError
from mosaic.verification.derivation import (
    DerivationNode,
    DerivationTree,
    validate_derivation_tree,
)
from mosaic.verification.graph import (\n    ObligationGraph,\n    ObligationNode,\n    ObligationGraphResult,\n    evaluate_obligation_graph,\n)
from mosaic.verification.obligations import obligations_for_request


def _leaf_requests(node: DerivationNode) -> tuple[MathRequest, ...]:
    if not node.children:
        return (node.request,)
    return tuple(
        request
        for child in node.children
        for request in _leaf_requests(child)
    )


def compile_derivation_obligation_graph(
    request: MathRequest,
    tree: DerivationTree,
) -> ObligationGraph:
    """Compile a validated tree into leaf obligations with composition edges.

    For the registered three-branch chain-rule shape, the third branch
    (composition identity) depends on all terminal obligations in the first
    two branches. Nested applications therefore contribute their own
    prerequisite checks and final composition checks to the outer dependency
    closure.
    """
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

        # The registered chain-rule contract is ordered:
        # outer derivative, inner derivative, composition identity.
        if node.rule_id != "calculus.chain_rule.integer_power.v1" or len(node.children) != 3:
            raise ExpressionError("No obligation compiler is registered for this derivation rule.")

        outer_ids = compile_node(node.children[0])
        inner_ids = compile_node(node.children[1])
        final_ids = compile_node(node.children[2])
        prerequisites = set(outer_ids) | set(inner_ids)
        for final_id in final_ids:
            dependencies[final_id].update(prerequisites - {final_id})
        return tuple(dict.fromkeys((*outer_ids, *inner_ids, *final_ids)))

    compile_node(tree.root)
    nodes = tuple(
        ObligationNode(
            request=requests_by_id[key],
            obligation=obligations_for_request(requests_by_id[key])[0],
            depends_on=tuple(sorted(dependencies[key])),
        )
        for key in sorted(requests_by_id)
    )
    return ObligationGraph(nodes=nodes)



def evaluate_derivation_tree(
    request: MathRequest,
    tree: DerivationTree,
    candidates: dict[str, str],
) -> ObligationGraphResult:
    """Compile a validated derivation and evaluate its complete leaf graph.

    Missing candidates remain INCOMPLETE and prevent dependent composition
    checks from running. The aggregate status is governed by the existing
    obligation graph evaluator and cannot exceed its checker guarantees.
    """
    graph = compile_derivation_obligation_graph(request, tree)
    return evaluate_obligation_graph(graph, candidates)
