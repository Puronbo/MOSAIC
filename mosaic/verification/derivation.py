"""Recursive, bounded derivation trees for registered decomposition rules.

A tree is a structural completeness contract: every applicable registered rule
must expose exactly its declared subrequests. It is not a proof object.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from mosaic.core.requests import MathRequest
from mosaic.engines.algebra import ExpressionError
from mosaic.verification.chain_rule import _make_plan
from mosaic.verification.decomposition import applicable_decomposition_rules
from mosaic.verification.obligations import request_fingerprint


class DerivationNode(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    path: tuple[int, ...]
    request: MathRequest
    rule_id: str | None = None
    children: tuple["DerivationNode", ...] = ()


class DerivationTree(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    root: DerivationNode
    node_count: int = Field(ge=1)


def _expected_children(request: MathRequest, rule_id: str) -> tuple[MathRequest, ...]:
    if rule_id == "calculus.chain_rule.integer_power.v1":
        _, outer, inner, final = _make_plan(request)
        return outer, inner, final
    raise ExpressionError(f"No derivation expander is registered for rule: {rule_id}.")


def build_derivation_tree(
    request: MathRequest,
    *,
    max_depth: int = 8,
    max_nodes: int = 128,
) -> DerivationTree:
    """Expand every applicable registered rule within explicit resource bounds."""
    if max_depth < 0 or max_nodes < 1:
        raise ValueError("max_depth must be nonnegative and max_nodes must be positive.")
    count = 0

    def visit(current: MathRequest, path: tuple[int, ...], depth: int) -> DerivationNode:
        nonlocal count
        count += 1
        if count > max_nodes:
            raise ExpressionError("Derivation tree exceeds max_nodes.")
        matches = applicable_decomposition_rules(current)
        if not matches:
            return DerivationNode(path=path, request=current)
        if len(matches) != 1:
            raise ExpressionError("Ambiguous decomposition: select a unique registered rule.")
        if depth >= max_depth:
            raise ExpressionError("Derivation tree exceeds max_depth.")
        rule = matches[0]
        expected = _expected_children(current, rule.rule_id)
        children = tuple(
            visit(child, path + (index,), depth + 1)
            for index, child in enumerate(expected)
        )
        return DerivationNode(
            path=path,
            request=current,
            rule_id=rule.rule_id,
            children=children,
        )

    root = visit(request, (), 0)
    return DerivationTree(root=root, node_count=count)


def validate_derivation_tree(
    request: MathRequest,
    tree: DerivationTree,
    *,
    max_depth: int = 8,
    max_nodes: int = 128,
) -> bool:
    """Check root binding, complete rule expansion, paths, and resource bounds."""
    try:
        if tree.root.request != request or tree.root.path != ():
            return False
        count = 0

        def check(node: DerivationNode, expected_request: MathRequest,
                  expected_path: tuple[int, ...], depth: int) -> bool:
            nonlocal count
            count += 1
            if count > max_nodes or depth > max_depth:
                return False
            if node.request != expected_request or node.path != expected_path:
                return False
            matches = applicable_decomposition_rules(node.request)
            if not matches:
                return node.rule_id is None and not node.children
            if len(matches) != 1 or node.rule_id != matches[0].rule_id:
                return False
            if depth >= max_depth:
                return False
            expected = _expected_children(node.request, node.rule_id)
            if len(node.children) != len(expected):
                return False
            return all(
                check(child, child_request, expected_path + (index,), depth + 1)
                for index, (child, child_request) in enumerate(zip(node.children, expected))
            )

        return check(tree.root, request, (), 0) and count == tree.node_count
    except (ExpressionError, ValueError, TypeError):
        return False
