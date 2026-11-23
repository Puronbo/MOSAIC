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


def test_domain_restrictions_are_typed_request_bound_and_deterministic():
    from mosaic.verification.side_conditions import domain_restrictions_for_request

    req = request("((x + 1)/(x - 1))**2")
    restrictions = domain_restrictions_for_request(req)
    assert restrictions == domain_restrictions_for_request(req)
    assert len(restrictions) == 1
    restriction = restrictions[0]
    assert restriction.predicate == "nonzero"
    assert restriction.expression == "x - 1"
    assert restriction.source_kind == "division_denominator"
    assert restriction.request_sha256 != domain_restrictions_for_request(
        request("((x + 1)/(x - 2))**2")
    )[0].request_sha256


def test_distinct_original_denominator_occurrences_remain_distinct():
    from mosaic.verification.side_conditions import domain_restrictions_for_request

    restrictions = domain_restrictions_for_request(
        request("((1/(x - 1) + 1/(x - 1)))**2")
    )
    assert len(restrictions) == 2
    assert restrictions[0].expression == restrictions[1].expression
    assert restrictions[0].restriction_id != restrictions[1].restriction_id



def test_negative_inner_power_records_its_base_as_a_domain_restriction():
    from mosaic.verification.side_conditions import (
        domain_restrictions_for_request, evaluate_side_condition,
    )

    req = request("(x**-1 + 1)**2")
    restrictions = domain_restrictions_for_request(req)
    assert len(restrictions) == 1
    assert restrictions[0].expression == "x"
    assert restrictions[0].source_kind == "negative_power_base"
    assert all(
        status == "EXPERIMENTAL"
        for status, _, _ in (
            evaluate_side_condition(
                req, condition
            )
            for condition in get_decomposition_rule(
                "calculus.chain_rule.integer_power.v1"
            ).side_conditions(req)
        )
    )


def test_negative_power_of_composite_base_preserves_that_base():
    from mosaic.verification.side_conditions import domain_restrictions_for_request

    restrictions = domain_restrictions_for_request(request("((x - 1)**-2 + 3)**2"))
    assert len(restrictions) == 1
    assert restrictions[0].expression == "x - 1"
    assert restrictions[0].source_kind == "negative_power_base"


def test_domain_restriction_verifier_checks_exact_request_bound_provenance():
    from mosaic.verification.side_conditions import (
        domain_restrictions_for_request, verify_domain_restriction,
    )

    req = request("((x + 1)/(x - 1))**2")
    restriction = domain_restrictions_for_request(req)[0]
    assert verify_domain_restriction(req, restriction)
    assert not verify_domain_restriction(
        request("((x + 1)/(x - 2))**2"), restriction
    )
    altered = restriction.model_copy(update={"expression": "x - 9"})
    assert not verify_domain_restriction(req, altered)
    altered_source = restriction.model_copy(update={"source_kind": "negative_power_base"})
    assert not verify_domain_restriction(req, altered_source)


def test_negative_outer_power_remains_unsupported():
    from mosaic.verification.side_conditions import domain_restrictions_for_request

    req = request("((x + 1)/(x - 1))**-2")
    assert domain_restrictions_for_request(req) == ()



def test_domain_preservation_detects_cancellation_that_expands_domain():
    from mosaic.verification.side_conditions import check_domain_preservation

    req = request("((x**2 - 1)/(x - 1))**2")
    result = check_domain_preservation(req, "(x + 1)**2")
    assert result.status == "EXPANDED"
    assert result.missing_factors == ("x - 1",)
    assert result.additional_factors == ()


def test_domain_preservation_accepts_equivalent_denominator_multiplicity():
    from mosaic.verification.side_conditions import check_domain_preservation

    req = request("((x + 1)/(x - 1))**2")
    result = check_domain_preservation(req, "(x + 1)**2/(x - 1)**2")
    assert result.status == "PRESERVED"
    assert result.original_nonzero_factors == ("x - 1",)


def test_domain_preservation_detects_additional_candidate_exclusions():
    from mosaic.verification.side_conditions import check_domain_preservation

    req = request("(x**2 + 1)**2")
    result = check_domain_preservation(req, "1/(x - 3)")
    assert result.status == "RESTRICTED"
    assert result.additional_factors == ("x - 3",)


def test_domain_preservation_handles_factorized_equivalent_denominators():
    from mosaic.verification.side_conditions import check_domain_preservation

    req = request("((x + 1)/(x**2 - 1))**2")
    result = check_domain_preservation(req, "(x + 1)**2/((x - 1)*(x + 1))**2")
    assert result.status == "PRESERVED"
    assert set(result.original_nonzero_factors) == {"x - 1", "x + 1"}


def test_domain_preservation_rejects_unsupported_candidate_grammar():
    from mosaic.verification.side_conditions import check_domain_preservation

    req = request("((x + 1)/(x - 1))**2")
    result = check_domain_preservation(req, "sin(x)")
    assert result.status == "UNSUPPORTED"
