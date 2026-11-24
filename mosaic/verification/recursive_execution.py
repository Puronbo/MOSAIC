"""Bounded recursive execution of registered derivation trees.

Registered rule executors produce deterministic local plans. Their terminal
requests are then checked against the complete dependency graph; model-supplied
candidates are not required or trusted by this convenience execution path.
"""
from __future__ import annotations

import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from mosaic.core.requests import MathRequest
from mosaic.engines.algebra import ExpressionError, run_algebra
from mosaic.verification.decomposition import execute_decomposition
from mosaic.verification.derivation import (
    DerivationTree,
    build_derivation_tree,
    validate_derivation_tree,
)
from mosaic.verification.derivation_graph import (
    compile_derivation_obligation_graph,
    evaluate_derivation_tree,
)
from mosaic.verification.graph import ObligationGraphResult
from mosaic.verification.obligations import obligations_for_request


class ExecutedRule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    path: tuple[int, ...]
    rule_id: str


class RecursiveDerivationExecution(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    tree: DerivationTree
    executed_rules: tuple[ExecutedRule, ...]
    graph_result: ObligationGraphResult


def _collect_rule_nodes(node, output: list[tuple[tuple[int, ...], str]]) -> None:
    if node.rule_id is not None:
        output.append((node.path, node.rule_id))
    for child in node.children:
        _collect_rule_nodes(child, output)


def _candidate_for_leaf(request: MathRequest) -> str:
    """Create a deterministic candidate in the strict task-bound claim schema."""
    operation = request.operation.value
    if operation == "verify_identity":
        if request.rhs is None:
            raise ExpressionError("Identity leaf is missing its right-hand side.")
        claim = {
            "operation": "verify_identity",
            "expression": request.expression,
            "rhs": request.rhs,
        }
    elif operation in {"differentiate", "simplify", "expand", "factor"}:
        if request.variable is None:
            raise ExpressionError("Transformation leaf is missing its variable.")
        result = run_algebra(operation, request.expression, request.variable)
        claim = {
            "operation": operation,
            "expression": request.expression,
            "variable": request.variable,
            "result": str(result),
        }
    else:
        raise ExpressionError(f"No recursive executor is registered for leaf operation: {operation}.")
    return json.dumps(claim, sort_keys=True, separators=(",", ":"))


def execute_recursive_derivation(
    request: MathRequest,
    *,
    max_depth: int = 8,
    max_nodes: int = 128,
) -> RecursiveDerivationExecution:
    """Expand, execute, and evaluate a complete registered derivation recursively.

    The result is bounded by the same depth/node budgets as tree construction.
    Successful experimental checks are never promoted to formal proof.
    """
    tree = build_derivation_tree(
        request, max_depth=max_depth, max_nodes=max_nodes
    )
    if not validate_derivation_tree(
        request, tree, max_depth=max_depth, max_nodes=max_nodes
    ):
        raise ExpressionError("Generated derivation tree failed structural validation.")

    rule_nodes: list[tuple[tuple[int, ...], str]] = []
    _collect_rule_nodes(tree.root, rule_nodes)
    for path, rule_id in rule_nodes:
        # This replays the registered verifier and deterministic executor at
        # every internal node, including nested rule applications.
        node = tree.root
        for index in path:
            node = node.children[index]
        execute_decomposition(node.request, rule_id)

    graph = compile_derivation_obligation_graph(request, tree)
    candidates = {
        node.obligation.obligation_id: _candidate_for_leaf(node.request)
        for node in graph.nodes
    }
    result = evaluate_derivation_tree(request, tree, candidates)
    return RecursiveDerivationExecution(
        tree=tree,
        executed_rules=tuple(
            ExecutedRule(path=path, rule_id=rule_id)
            for path, rule_id in rule_nodes
        ),
        graph_result=result,
    )
