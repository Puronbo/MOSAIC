"""Deterministic chain-rule decomposition for a restricted power composition."""
from __future__ import annotations

import ast
import hashlib
import json

import sympy as sp
from pydantic import BaseModel, ConfigDict, Field

from mosaic.core.requests import MathRequest
from mosaic.core.types import Operation
from mosaic.engines.algebra import ExpressionError, parse_expression, run_algebra
from mosaic.verification.graph import (
    ObligationGraph,
    ObligationNode,
    evaluate_obligation_graph,
)
from mosaic.verification.obligations import obligations_for_request, request_fingerprint


class ChainRulePlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    inner_expression: str
    exponent: int
    outer_derivative: str
    inner_derivative: str
    composed_derivative: str
    expected_derivative: str
    subgoal_ids: tuple[str, str, str]


class ChainRuleExecution(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    plan: ChainRulePlan
    graph_result: object


def _extract_power_composition(expression: str) -> tuple[str, int]:
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError as exc:
        raise ExpressionError("Invalid expression syntax.") from exc
    node = tree.body
    if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Pow):
        raise ExpressionError("Only a top-level power composition is currently supported.")
    if not isinstance(node.right, ast.Constant) or isinstance(node.right.value, bool) or not isinstance(node.right.value, int):
        raise ExpressionError("The outer exponent must be an integer literal.")
    if isinstance(node.left, ast.Name):
        raise ExpressionError("The inner expression must be a nontrivial composition.")
    inner = ast.get_source_segment(expression, node.left)
    if not inner:
        raise ExpressionError("Could not isolate the inner expression.")
    parse_expression(inner)
    return inner, node.right.value


def _make_plan(request: MathRequest) -> tuple[ChainRulePlan, MathRequest, MathRequest, MathRequest]:
    if request.operation != Operation.DIFFERENTIATE:
        raise ExpressionError("Chain-rule decomposition requires a differentiate request.")
    if request.variable not in {"x", "y", "z"}:
        raise ExpressionError("Differentiation variable is outside the supported symbol set.")

    inner, exponent = _extract_power_composition(request.expression)
    placeholder = sp.Symbol(request.variable)
    inner_value = parse_expression(inner)
    outer_expression = f"{request.variable}**({exponent})"
    outer_derivative = run_algebra("differentiate", outer_expression, request.variable)
    inner_derivative = run_algebra("differentiate", inner, request.variable)
    composed = sp.expand(
        outer_derivative.subs(placeholder, inner_value) * inner_derivative
    )
    expected = run_algebra("differentiate", request.expression, request.variable)
    composed_text = str(composed)
    expected_text = str(expected)

    outer_request = MathRequest(
        operation=Operation.DIFFERENTIATE,
        expression=outer_expression,
        variable=request.variable,
    )
    inner_request = MathRequest(
        operation=Operation.DIFFERENTIATE,
        expression=inner,
        variable=request.variable,
    )
    final_request = MathRequest(
        operation=Operation.VERIFY_IDENTITY,
        expression=composed_text,
        rhs=expected_text,
        variable=request.variable,
    )
    ids = tuple(obligations_for_request(item)[0].obligation_id for item in (
        outer_request, inner_request, final_request
    ))
    plan = ChainRulePlan(
        request_sha256=request_fingerprint(request),
        inner_expression=inner,
        exponent=exponent,
        outer_derivative=str(outer_derivative),
        inner_derivative=str(inner_derivative),
        composed_derivative=composed_text,
        expected_derivative=expected_text,
        subgoal_ids=ids,
    )
    return plan, outer_request, inner_request, final_request


def decompose_power_chain_rule(request: MathRequest) -> ChainRulePlan:
    """Create a deterministic, request-bound chain-rule decomposition plan."""
    return _make_plan(request)[0]


def verify_chain_rule_plan(request: MathRequest, plan: ChainRulePlan) -> bool:
    """Recompute every decomposition field; never trust a supplied plan."""
    try:
        expected, _, _, _ = _make_plan(request)
    except (ExpressionError, ValueError, TypeError):
        return False
    return plan == expected


def execute_power_chain_rule(request: MathRequest) -> ChainRuleExecution:
    """Build and evaluate the three linked subgoals for a supported composition."""
    plan, outer_request, inner_request, final_request = _make_plan(request)
    outer_obligation = obligations_for_request(outer_request)[0]
    inner_obligation = obligations_for_request(inner_request)[0]
    final_obligation = obligations_for_request(final_request)[0]

    outer_node = ObligationNode(request=outer_request, obligation=outer_obligation)
    inner_node = ObligationNode(request=inner_request, obligation=inner_obligation)
    final_node = ObligationNode(
        request=final_request,
        obligation=final_obligation,
        depends_on=(outer_obligation.obligation_id, inner_obligation.obligation_id),
    )
    graph = ObligationGraph(nodes=(outer_node, inner_node, final_node))
    candidates = {
        outer_obligation.obligation_id: json.dumps({
            "operation": "differentiate",
            "expression": outer_request.expression,
            "variable": outer_request.variable,
            "result": plan.outer_derivative,
        }),
        inner_obligation.obligation_id: json.dumps({
            "operation": "differentiate",
            "expression": inner_request.expression,
            "variable": inner_request.variable,
            "result": plan.inner_derivative,
        }),
        final_obligation.obligation_id: json.dumps({
            "operation": "verify_identity",
            "expression": final_request.expression,
            "rhs": final_request.rhs,
        }),
    }
    result = evaluate_obligation_graph(graph, candidates)
    return ChainRuleExecution(plan=plan, graph_result=result)
