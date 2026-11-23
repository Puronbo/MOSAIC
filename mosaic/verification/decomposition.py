"""Explicit allow-listed registry for deterministic decomposition rules."""
from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Callable

from mosaic.core.requests import MathRequest
from mosaic.engines.algebra import ExpressionError
from mosaic.verification.side_conditions import (
    RuleSideCondition,
    make_unsupported_side_conditions,
)
from mosaic.verification.chain_rule import (
    ChainRulePlan,
    decompose_power_chain_rule,
    verify_chain_rule_plan,
    execute_power_chain_rule,
    _make_plan as _make_chain_plan,
)


@dataclass(frozen=True)
class DecompositionRule:
    """A registered rule and its independently callable plan verifier."""

    rule_id: str
    operation: str
    description: str
    matcher: Callable[[MathRequest], bool]
    decompose: Callable[[MathRequest], object]
    verify: Callable[[MathRequest, object], bool]
    execute: Callable[[MathRequest], object]
    dependency_policy: Callable[[int], tuple[tuple[int, tuple[int, ...]], ...]]
    children: Callable[[MathRequest], tuple[MathRequest, ...]]
    side_conditions: Callable[[MathRequest], tuple[RuleSideCondition, ...]]


def _matches_power_chain(request: MathRequest) -> bool:
    if request.operation.value != "differentiate":
        return False
    try:
        tree = ast.parse(request.expression, mode="eval")
    except SyntaxError:
        return False
    node = tree.body
    return (
        isinstance(node, ast.BinOp)
        and isinstance(node.op, ast.Pow)
        and not isinstance(node.left, ast.Name)
        and isinstance(node.right, ast.Constant)
        and not isinstance(node.right.value, bool)
        and isinstance(node.right.value, int)
    )


def _chain_rule_dependencies(child_count: int) -> tuple[tuple[int, tuple[int, ...]], ...]:
    if child_count != 3:
        raise ExpressionError("The chain-rule obligation contract requires three child branches.")
    return ((2, (0, 1)),)


def _chain_rule_children(request: MathRequest) -> tuple[MathRequest, ...]:
    """Return the ordered subrequests produced by the registered chain rule."""
    _, outer, inner, final = _make_chain_plan(request)
    return outer, inner, final


def _chain_rule_side_conditions(request: MathRequest) -> tuple[RuleSideCondition, ...]:
    """Expose chain-rule preconditions not yet discharged by a trusted checker."""
    return make_unsupported_side_conditions(
        request,
        "calculus.chain_rule.integer_power.v1",
        (
            (
                "inner_differentiability",
                "The inner expression must be differentiable on the domain under consideration; no domain-aware checker is registered.",
            ),
            (
                "domain_definedness",
                "The expression and its derivative must be defined on the declared domain; this request format carries no explicit domain contract.",
            ),
            (
                "domain_preservation",
                "The transformation must preserve the intended domain and branch conventions; no domain-preservation checker is registered.",
            ),
        ),
    )


def _verify_chain_plan(request: MathRequest, plan: object) -> bool:
    if not isinstance(plan, ChainRulePlan):
        return False
    return verify_chain_rule_plan(request, plan)


_RULES: tuple[DecompositionRule, ...] = (
    DecompositionRule(
        rule_id="calculus.chain_rule.integer_power.v1",
        operation="differentiate",
        description="Chain rule for a top-level integer power of a nontrivial expression.",
        matcher=_matches_power_chain,
        decompose=decompose_power_chain_rule,
        verify=_verify_chain_plan,
        execute=execute_power_chain_rule,
        dependency_policy=_chain_rule_dependencies,
        children=_chain_rule_children,
        side_conditions=_chain_rule_side_conditions,
    ),
)
_RULES_BY_ID = {rule.rule_id: rule for rule in _RULES}


def registered_decomposition_rules() -> tuple[DecompositionRule, ...]:
    """Return the immutable, statically registered rule definitions."""
    return _RULES


def applicable_decomposition_rules(
    request: MathRequest,
) -> tuple[DecompositionRule, ...]:
    """List rules whose structural matchers accept this request."""
    return tuple(rule for rule in _RULES if rule.matcher(request))


def get_decomposition_rule(rule_id: str) -> DecompositionRule:
    """Resolve a rule only from the built-in allow-list."""
    try:
        return _RULES_BY_ID[rule_id]
    except KeyError as exc:
        raise ExpressionError(f"Unknown decomposition rule: {rule_id}.") from exc


def decompose_request(request: MathRequest, rule_id: str | None = None) -> object:
    """Apply one applicable registered rule, optionally selected by stable ID."""
    if rule_id is not None:
        rule = get_decomposition_rule(rule_id)
        if not rule.matcher(request):
            raise ExpressionError(f"Request does not match rule: {rule_id}.")
        return rule.decompose(request)

    matches = applicable_decomposition_rules(request)
    if not matches:
        raise ExpressionError("No registered decomposition rule matches this request.")
    if len(matches) > 1:
        raise ExpressionError("Multiple decomposition rules match; select a rule ID.")
    return matches[0].decompose(request)


def verify_decomposition_plan(
    request: MathRequest,
    rule_id: str,
    plan: object,
) -> bool:
    """Verify a plan with the verifier paired to its registered rule."""
    rule = get_decomposition_rule(rule_id)
    if not rule.matcher(request):
        return False
    return rule.verify(request, plan)



def execute_decomposition(
    request: MathRequest,
    rule_id: str | None = None,
) -> object:
    """Execute a registered rule only after its generated plan passes its verifier."""
    if rule_id is None:
        matches = applicable_decomposition_rules(request)
        if not matches:
            raise ExpressionError("No registered decomposition rule matches this request.")
        if len(matches) > 1:
            raise ExpressionError("Multiple decomposition rules match; select a rule ID.")
        rule = matches[0]
    else:
        rule = get_decomposition_rule(rule_id)
        if not rule.matcher(request):
            raise ExpressionError(f"Request does not match rule: {rule_id}.")

    plan = rule.decompose(request)
    if not rule.verify(request, plan):
        raise ExpressionError(f"Generated plan failed its registered verifier: {rule.rule_id}.")
    execution = rule.execute(request)
    execution_plan = getattr(execution, "plan", None)
    if execution_plan != plan:
        raise ExpressionError(f"Execution plan differs from verified plan: {rule.rule_id}.")
    return execution


def verify_decomposition_execution(
    request: MathRequest,
    rule_id: str,
    execution: object,
) -> bool:
    """Audit an execution by replaying the registered deterministic executor.

    This verifies structural/result reproducibility, not a formal proof. The
    result remains limited by the trust and status of the underlying checkers.
    """
    rule = get_decomposition_rule(rule_id)
    if not rule.matcher(request):
        return False
    supplied_plan = getattr(execution, "plan", None)
    if not rule.verify(request, supplied_plan):
        return False
    try:
        expected = rule.execute(request)
    except (ExpressionError, ValueError, TypeError):
        return False
    supplied_dump = (
        execution.model_dump(mode="json")
        if hasattr(execution, "model_dump")
        else None
    )
    expected_dump = (
        expected.model_dump(mode="json")
        if hasattr(expected, "model_dump")
        else None
    )
    return supplied_dump is not None and supplied_dump == expected_dump
