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


class DomainRestriction(BaseModel):
    """A typed nonzero condition preserving its origin in the submitted syntax."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    restriction_id: str = Field(min_length=1, max_length=180)
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    predicate: Literal["nonzero"] = "nonzero"
    expression: str = Field(min_length=1, max_length=2000)
    source_kind: Literal["division_denominator", "negative_power_base"]
    line: int = Field(ge=1)
    column: int = Field(ge=0)




class DomainPreservationResult(BaseModel):
    """Conservative comparison of original and candidate rational domains."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["PRESERVED", "EXPANDED", "RESTRICTED", "CHANGED", "UNSUPPORTED"]
    original_nonzero_factors: tuple[str, ...] = ()
    candidate_nonzero_factors: tuple[str, ...] = ()
    missing_factors: tuple[str, ...] = ()
    additional_factors: tuple[str, ...] = ()
    explanation: str = Field(min_length=1, max_length=2000)



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


def _integer_literal(node: ast.AST) -> int | None:
    """Read a signed integer literal without accepting booleans or expressions."""
    if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
        return node.value
    if (
        isinstance(node, ast.UnaryOp)
        and isinstance(node.op, (ast.UAdd, ast.USub))
        and isinstance(node.operand, ast.Constant)
        and isinstance(node.operand.value, int)
        and not isinstance(node.operand.value, bool)
    ):
        value = node.operand.value
        return -value if isinstance(node.op, ast.USub) else value
    return None


def _rational_domain_analysis(request: MathRequest) -> tuple[bool, tuple[tuple[str, str, int, int], ...]]:
    """Recognize rational expressions while retaining every syntactic exclusion."""
    try:
        tree = ast.parse(request.expression, mode="eval")
        root = tree.body
        if not (
            isinstance(root, ast.BinOp)
            and isinstance(root.op, ast.Pow)
            and _integer_literal(root.right) is not None
            and _integer_literal(root.right) >= 0
        ):
            return False, ()

        constraints: list[tuple[str, str, int, int]] = []

        def supported(node: ast.AST) -> bool:
            if isinstance(node, ast.Name):
                return True
            if isinstance(node, ast.Constant):
                return isinstance(node.value, (int, float)) and not isinstance(node.value, bool)
            if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
                return supported(node.operand)
            if isinstance(node, ast.BinOp):
                if not (supported(node.left) and supported(node.right)):
                    return False
                if isinstance(node.op, (ast.Add, ast.Sub, ast.Mult)):
                    return True
                if isinstance(node.op, ast.Div):
                    denominator = parse_expression(ast.unparse(node.right))
                    symbols = tuple(sorted(denominator.free_symbols, key=str))
                    if symbols and not denominator.is_polynomial(*symbols):
                        return False
                    if not symbols and not denominator.is_number:
                        return False
                    if denominator == 0:
                        return False
                    constraints.append((sp.sstr(denominator), "division_denominator", node.lineno, node.col_offset))
                    return True
                if isinstance(node.op, ast.Pow):
                    exponent = _integer_literal(node.right)
                    if exponent is None:
                        return False
                    if exponent < 0:
                        base = parse_expression(ast.unparse(node.left))
                        constraints.append((sp.sstr(base), "negative_power_base", node.lineno, node.col_offset))
                    return True
            return False

        if not supported(root.left):
            return False, ()
        inner = parse_expression(ast.unparse(root.left))
        whole = parse_expression(request.expression)
        symbols = tuple(sorted(inner.free_symbols | whole.free_symbols, key=str))
        if symbols:
            if not inner.is_rational_function(*symbols) or not whole.is_rational_function(*symbols):
                return False, ()
        elif not inner.is_number or not whole.is_number:
            return False, ()
        variable = sp.Symbol(request.variable or "x")
        sp.diff(inner, variable)
        sp.diff(whole, variable)
        return True, tuple(dict.fromkeys(constraints))
    except (SyntaxError, ExpressionError, sp.PolynomialError, TypeError, ValueError):
        return False, ()


def domain_restrictions_for_request(request: MathRequest) -> tuple[DomainRestriction, ...]:
    """Return deterministic, request-bound restrictions for supported rational chains."""
    supported, constraints = _rational_domain_analysis(request)
    if not supported:
        return ()
    fingerprint = request_fingerprint(request)
    restrictions = []
    for expression, source_kind, line, column in constraints:
        payload = json.dumps(
            [fingerprint, expression, source_kind, line, column],
            separators=(",", ":"),
        )
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]
        restrictions.append(DomainRestriction(
            restriction_id=f"domain:{digest}",
            request_sha256=fingerprint,
            expression=expression,
            source_kind=source_kind,
            line=line,
            column=column,
        ))
    return tuple(restrictions)


def verify_domain_restriction(request: MathRequest, supplied: DomainRestriction) -> bool:
    """Validate restriction provenance; this does not establish the nonzero predicate."""
    return supplied in domain_restrictions_for_request(request)


def domain_constraints_for_request(request: MathRequest) -> tuple[str, ...]:
    """Compatibility view of the typed nonzero restrictions."""
    return tuple(item.expression for item in domain_restrictions_for_request(request))




def _nonzero_factor_signature(expressions: tuple[str, ...]) -> tuple[str, ...]:
    """Canonicalize polynomial nonzero predicates, ignoring nonzero multiplicity."""
    factors: set[str] = set()
    for expression in expressions:
        parsed = parse_expression(expression)
        symbols = tuple(sorted(parsed.free_symbols, key=str))
        if not symbols:
            if parsed == 0:
                raise ValueError("zero cannot be a domain restriction")
            continue
        polynomial = sp.Poly(parsed, *symbols)
        _, irreducible = sp.factor_list(polynomial.as_expr(), *symbols)
        for factor, _multiplicity in irreducible:
            normalized = sp.Poly(factor, *symbols).monic().as_expr()
            factors.add(sp.sstr(normalized))
    return tuple(sorted(factors))


def _candidate_rational_restrictions(expression: str) -> tuple[str, ...] | None:
    """Extract denominator and negative-power exclusions from a restricted AST."""
    try:
        tree = ast.parse(expression, mode="eval")
        restrictions: list[str] = []

        def visit(node: ast.AST) -> bool:
            if isinstance(node, ast.Name):
                return True
            if isinstance(node, ast.Constant):
                return isinstance(node.value, (int, float)) and not isinstance(node.value, bool)
            if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
                return visit(node.operand)
            if not isinstance(node, ast.BinOp) or not (visit(node.left) and visit(node.right)):
                return False
            if isinstance(node.op, (ast.Add, ast.Sub, ast.Mult)):
                return True
            if isinstance(node.op, ast.Div):
                denominator = parse_expression(ast.unparse(node.right))
                symbols = tuple(sorted(denominator.free_symbols, key=str))
                if symbols and not denominator.is_polynomial(*symbols):
                    return False
                if denominator == 0:
                    return False
                restrictions.append(sp.sstr(denominator))
                return True
            if isinstance(node.op, ast.Pow):
                exponent = _integer_literal(node.right)
                if exponent is None:
                    return False
                if exponent < 0:
                    base = parse_expression(ast.unparse(node.left))
                    symbols = tuple(sorted(base.free_symbols, key=str))
                    if symbols and not base.is_polynomial(*symbols):
                        return False
                    if base == 0:
                        return False
                    restrictions.append(sp.sstr(base))
                return True
            return False

        if not visit(tree.body):
            return None
        parsed = parse_expression(expression)
        symbols = tuple(sorted(parsed.free_symbols, key=str))
        if symbols and not parsed.is_rational_function(*symbols):
            return None
        return tuple(restrictions)
    except (SyntaxError, ExpressionError, sp.PolynomialError, TypeError, ValueError):
        return None


def check_domain_preservation(
    request: MathRequest,
    candidate_expression: str,
) -> DomainPreservationResult:
    """Compare exact polynomial exclusion factors; never infer a proof from matching syntax."""
    original_constraints = _candidate_rational_restrictions(request.expression)
    if original_constraints is None:
        return DomainPreservationResult(
            status="UNSUPPORTED",
            explanation="The original request is outside the supported rational-expression domain checker.",
        )
    candidate_constraints = _candidate_rational_restrictions(candidate_expression)
    if candidate_constraints is None:
        return DomainPreservationResult(
            status="UNSUPPORTED",
            explanation="The candidate is outside the restricted rational-expression grammar.",
        )
    try:
        original = _nonzero_factor_signature(original_constraints)
        candidate = _nonzero_factor_signature(candidate_constraints)
    except (ExpressionError, sp.PolynomialError, TypeError, ValueError):
        return DomainPreservationResult(
            status="UNSUPPORTED",
            explanation="A domain predicate could not be normalized as a polynomial nonzero condition.",
        )
    missing = tuple(sorted(set(original) - set(candidate)))
    additional = tuple(sorted(set(candidate) - set(original)))
    if missing and additional:
        status = "CHANGED"
    elif missing:
        status = "EXPANDED"
    elif additional:
        status = "RESTRICTED"
    else:
        status = "PRESERVED"
    explanations = {
        "PRESERVED": "The candidate retains the same polynomial nonzero exclusions as the original request.",
        "EXPANDED": "The candidate omits original exclusions and may be defined at points excluded by the original expression.",
        "RESTRICTED": "The candidate introduces additional exclusions and may have a narrower domain than the original expression.",
        "CHANGED": "The candidate both omits original exclusions and introduces additional exclusions.",
    }
    return DomainPreservationResult(
        status=status,
        original_nonzero_factors=original,
        candidate_nonzero_factors=candidate,
        missing_factors=missing,
        additional_factors=additional,
        explanation=explanations[status],
    )


def _is_supported_rational_power(request: MathRequest) -> bool:
    supported, _ = _rational_domain_analysis(request)
    return supported

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
        and _is_supported_rational_power(request)
    ):
        return (
            "EXPERIMENTAL",
            "calculus.rational_domain_constraints.v1",
            "Recognized a nonnegative integer power of a rational expression. Differentiability is conditional on the reported original-syntax nonzero constraints.",
        )
    return (
        "UNSUPPORTED",
        "none",
        "No registered checker can establish this precondition for the supplied expression and domain.",
    )
