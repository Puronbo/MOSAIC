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



def test_real_polynomial_chain_rule_preconditions_are_checked_experimentally():
    from mosaic.verification.side_conditions import evaluate_side_condition

    req = request("(x**2 + 1)**3")
    rule = get_decomposition_rule("calculus.chain_rule.integer_power.v1")
    results = [evaluate_side_condition(req, item) for item in rule.side_conditions(req)]

    assert all(status == "EXPERIMENTAL" for status, _, _ in results)
    assert all(checker == "calculus.rational_domain_constraints.v1" for _, checker, _ in results)


def test_negative_power_domain_preconditions_remain_unsupported():
    from mosaic.verification.side_conditions import evaluate_side_condition

    req = request("(x**2 + 1)**-2")
    rule = get_decomposition_rule("calculus.chain_rule.integer_power.v1")
    results = [evaluate_side_condition(req, item) for item in rule.side_conditions(req)]

    assert all(status == "UNSUPPORTED" for status, _, _ in results)


def test_non_polynomial_inner_expression_remains_unsupported():
    from mosaic.verification.side_conditions import evaluate_side_condition

    req = request("(log(x))**2")
    rule = get_decomposition_rule("calculus.chain_rule.integer_power.v1")
    results = [evaluate_side_condition(req, item) for item in rule.side_conditions(req)]

    assert all(status == "UNSUPPORTED" for status, _, _ in results)



def test_rational_inner_expression_preserves_original_denominator_exclusion():
    from mosaic.verification.side_conditions import (
        domain_constraints_for_request, evaluate_side_condition,
    )

    req = request("((x**2 - 1)/(x - 1))**2")
    rule = get_decomposition_rule("calculus.chain_rule.integer_power.v1")
    results = [evaluate_side_condition(req, item) for item in rule.side_conditions(req)]

    assert all(status == "EXPERIMENTAL" for status, _, _ in results)
    assert all(checker == "calculus.rational_domain_constraints.v1" for _, checker, _ in results)
    assert domain_constraints_for_request(req) == ("x - 1",)


def test_rational_domain_analysis_collects_nested_denominators():
    from mosaic.verification.side_conditions import domain_constraints_for_request

    req = request("((1/(x - 2) + 1/(x + 3)))**2")
    assert domain_constraints_for_request(req) == ("x - 2", "x + 3")


def test_identically_zero_denominator_is_not_supported():
    from mosaic.verification.side_conditions import evaluate_side_condition

    req = request("((x + 1)/(x - x))**2")
    rule = get_decomposition_rule("calculus.chain_rule.integer_power.v1")
    results = [evaluate_side_condition(req, item) for item in rule.side_conditions(req)]
    assert all(status == "UNSUPPORTED" for status, _, _ in results)
