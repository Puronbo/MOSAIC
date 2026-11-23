"""Explicit, request-bound rule preconditions and conservative checkers."""
from __future__ import annotations

import ast
import hashlib
import json
import re
from typing import Literal

import sympy as sp
from pydantic import BaseModel, ConfigDict, Field

from mosaic.core.requests import MathRequest
from mosaic.engines.algebra import ExpressionError, parse_expression
from mosaic.verification.obligations import request_fingerprint


class RuleSideCondition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    condition_id: str = Field(min_length=1, max_length=160)
    rule_id: str = Field(min_length=1, max_length=120)
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    predicate: str = Field(min_length=1, max_length=120)
    statement: str = Field(min_length=1, max_length=2000)
    checker_id: str = "none"
    status: Literal["UNSUPPORTED"] = "UNSUPPORTED"


def make_unsupported_side_conditions(
    request: MathRequest,
    rule_id: str,
    conditions: tuple[tuple[str, str], ...],
) -> tuple[RuleSideCondition, ...]:
    """Create deterministic, request-bound unresolved precondition contracts."""
    fingerprint = request_fingerprint(request)
    output = []
    for predicate, statement in conditions:
        slug = re.sub(r"[^a-z0-9]+", "-", predicate.lower()).strip("-")
        digest_input = json.dumps(
            [fingerprint, rule_id, predicate, statement],
            ensure_ascii=False,
            separators=(",", ":"),
        )
        digest = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()[:16]
        output.append(RuleSideCondition(
            condition_id=f"side:{rule_id}:{slug}:{digest}",
            rule_id=rule_id,
            request_sha256=fingerprint,
            predicate=predicate,
            statement=statement,
        ))
    return tuple(output)


def verify_side_condition_contract(
    request: MathRequest,
    rule_id: str,
    supplied: RuleSideCondition,
    expected: tuple[RuleSideCondition, ...],
) -> bool:
    """Check contract integrity; this deliberately does not discharge it."""
    return (
        supplied.request_sha256 == request_fingerprint(request)
        and supplied.rule_id == rule_id
        and supplied in expected
        and supplied.status == "UNSUPPORTED"
        and supplied.checker_id == "none"
    )


def _is_nonnegative_integer_power_of_polynomial(request: MathRequest) -> bool:
    """Recognize a polynomial power whose real-domain preconditions are decidable."""
    try:
        tree = ast.parse(request.expression, mode="eval")
        root = tree.body
        if not (
            isinstance(root, ast.BinOp)
            and isinstance(root.op, ast.Pow)
            and isinstance(root.right, ast.Constant)
            and isinstance(root.right.value, int)
            and not isinstance(root.right.value, bool)
            and root.right.value >= 0
        ):
            return False
        inner = parse_expression(ast.unparse(root.left))
        whole = parse_expression(request.expression)
        sp.Poly(inner)
        sp.Poly(whole)
        variable = sp.Symbol(request.variable or "x")
        sp.diff(inner, variable)
        sp.diff(whole, variable)
        return True
    except (SyntaxError, ExpressionError, sp.PolynomialError, TypeError, ValueError):
        return False


def evaluate_side_condition(
    request: MathRequest,
    condition: RuleSideCondition,
) -> tuple[str, str, str]:
    """Evaluate a narrow checker without upgrading its result to formal proof."""
    if (
        condition.rule_id == "calculus.chain_rule.integer_power.v1"
        and condition.predicate in {
            "inner_differentiability", "domain_definedness", "domain_preservation"
        }
        and _is_nonnegative_integer_power_of_polynomial(request)
    ):
        return (
            "EXPERIMENTAL",
            "calculus.real_polynomial_domain.v1",
            "Recognized a nonnegative integer power of a polynomial; the expression and its derivatives are defined and differentiable over the real domain.",
        )
    return (
        "UNSUPPORTED",
        "none",
        "No registered checker can establish this precondition for the supplied expression and domain.",
    )
