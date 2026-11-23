"""Explicit allow-listed registry for deterministic decomposition rules."""
from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Callable

from mosaic.core.requests import MathRequest
from mosaic.engines.algebra import ExpressionError
from mosaic.verification.chain_rule import (
    ChainRulePlan,
    decompose_power_chain_rule,
    verify_chain_rule_plan,
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
