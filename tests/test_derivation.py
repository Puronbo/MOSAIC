import pytest

from mosaic.core.requests import MathRequest
from mosaic.core.types import Operation
from mosaic.engines.algebra import ExpressionError
from mosaic.verification.derivation import (
    DerivationTree,
    build_derivation_tree,
    validate_derivation_tree,
)


def request(expression="((x**2+1)**3)**2"):
    return MathRequest(
        operation=Operation.DIFFERENTIATE,
        expression=expression,
        variable="x",
    )


def test_nested_chain_rules_expand_recursively_and_validate():
    tree = build_derivation_tree(request())
    assert tree.node_count == 7
    assert tree.root.rule_id == "calculus.chain_rule.integer_power.v1"
    nested_inner = tree.root.children[1]
    assert nested_inner.rule_id == "calculus.chain_rule.integer_power.v1"
    assert validate_derivation_tree(request(), tree)


def test_tree_rejects_missing_child_and_tampered_request():
    tree = build_derivation_tree(request())
    shortened_root = tree.root.model_copy(
        update={"children": tree.root.children[:2]}
    )
    shortened = tree.model_copy(update={"root": shortened_root, "node_count": 3})
    assert not validate_derivation_tree(request(), shortened)

    wrong_root = tree.root.model_copy(update={
        "request": request("(x+1)**2")
    })
    wrong = tree.model_copy(update={"root": wrong_root})
    assert not validate_derivation_tree(request(), wrong)


def test_tree_rejects_altered_rule_id_and_path():
    tree = build_derivation_tree(request())
    wrong_rule = tree.root.model_copy(update={"rule_id": "model.rule"})
    assert not validate_derivation_tree(
        request(), tree.model_copy(update={"root": wrong_rule})
    )

    wrong_child = tree.root.children[0].model_copy(update={"path": (9,)})
    wrong_root = tree.root.model_copy(update={
        "children": (wrong_child,) + tree.root.children[1:]
    })
    assert not validate_derivation_tree(
        request(), tree.model_copy(update={"root": wrong_root})
    )


def test_builder_enforces_depth_and_node_budgets():
    with pytest.raises(ExpressionError, match="max_depth"):
        build_derivation_tree(request(), max_depth=1)
    with pytest.raises(ExpressionError, match="max_nodes"):
        build_derivation_tree(request(), max_nodes=3)


def test_leaf_request_is_a_valid_complete_tree():
    simple = request("x**2+1")
    tree = build_derivation_tree(simple)
    assert tree.node_count == 1
    assert tree.root.rule_id is None
    assert validate_derivation_tree(simple, tree)


def test_registered_rule_exposes_its_own_child_expander():
    from mosaic.verification.decomposition import (
        get_decomposition_rule,
        registered_decomposition_rules,
    )

    rule = get_decomposition_rule("calculus.chain_rule.integer_power.v1")
    assert rule in registered_decomposition_rules()
    assert rule.children(request()).__len__() == 3


def test_builder_rejects_non_integer_or_ambiguous_resource_budgets():
    for value in (True, False, 1.5, "2", -1):
        with pytest.raises(ValueError, match="integer"):
            build_derivation_tree(request(), max_depth=value)
    for value in (True, False, 1.5, "4", 0, -1):
        with pytest.raises(ValueError, match="integer"):
            build_derivation_tree(request(), max_nodes=value)


def test_validator_rejects_non_integer_resource_budgets():
    tree = build_derivation_tree(request())
    for kwargs in (
        {"max_depth": True},
        {"max_depth": 1.5},
        {"max_nodes": False},
        {"max_nodes": "128"},
    ):
        assert not validate_derivation_tree(request(), tree, **kwargs)
