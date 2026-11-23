from mosaic.core.requests import MathRequest
from mosaic.core.types import Operation
from mosaic.verification.decomposition import get_decomposition_rule
from mosaic.verification.side_conditions import verify_side_condition_contract


def request(expression="(x**2 + 1)**3"):
    return MathRequest(
        operation=Operation.DIFFERENTIATE,
        expression=expression,
        variable="x",
    )


def test_chain_rule_declares_unresolved_side_conditions_explicitly():
    req = request()
    rule = get_decomposition_rule("calculus.chain_rule.integer_power.v1")
    conditions = rule.side_conditions(req)

    assert {item.predicate for item in conditions} == {
        "inner_differentiability",
        "domain_definedness",
        "domain_preservation",
    }
    assert all(item.status == "UNSUPPORTED" for item in conditions)
    assert all(item.checker_id == "none" for item in conditions)
    assert all(
        verify_side_condition_contract(req, rule.rule_id, item, conditions)
        for item in conditions
    )


def test_side_condition_contract_is_request_bound_and_tamper_evident():
    req = request()
    other = request("(x - 4)**2")
    rule = get_decomposition_rule("calculus.chain_rule.integer_power.v1")
    conditions = rule.side_conditions(req)

    assert not verify_side_condition_contract(other, rule.rule_id, conditions[0], conditions)
    altered = conditions[0].model_copy(update={"statement": "Assume this is true."})
    assert not verify_side_condition_contract(req, rule.rule_id, altered, conditions)


def test_side_conditions_are_deterministic():
    rule = get_decomposition_rule("calculus.chain_rule.integer_power.v1")
    assert rule.side_conditions(request()) == rule.side_conditions(request())



def test_nested_derivation_exposes_side_conditions_for_each_rule_node():
    from mosaic.verification.derivation import build_derivation_tree
    from mosaic.verification.derivation_graph import side_conditions_for_derivation_tree

    req = request("((x**2 + 1)**3)**2")
    tree = build_derivation_tree(req)
    conditions = side_conditions_for_derivation_tree(req, tree)

    assert len(conditions) == 6
    assert all(item.status == "UNSUPPORTED" for item in conditions)
    assert len({item.condition_id for item in conditions}) == 6
