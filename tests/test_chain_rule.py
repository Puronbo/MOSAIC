import pytest

from mosaic.core.requests import MathRequest
from mosaic.core.types import Operation
from mosaic.engines.algebra import ExpressionError
from mosaic.verification.chain_rule import (
    decompose_power_chain_rule,
    execute_power_chain_rule,
    verify_chain_rule_plan,
)


def request(expression="(x**2+1)**3"):
    return MathRequest(
        operation=Operation.DIFFERENTIATE,
        expression=expression,
        variable="x",
    )


def test_power_chain_rule_decomposition_has_three_explicit_subgoals():
    plan = decompose_power_chain_rule(request())
    assert plan.inner_expression == "x**2+1"
    assert plan.exponent == 3
    assert plan.outer_derivative == "3*x**2"
    assert plan.inner_derivative == "2*x"
    assert len(plan.subgoal_ids) == 3
    assert verify_chain_rule_plan(request(), plan)


def test_plan_is_bound_to_original_request():
    plan = decompose_power_chain_rule(request())
    assert not verify_chain_rule_plan(request("(x**2+2)**3"), plan)


def test_execution_verifies_both_derivatives_before_composition():
    execution = execute_power_chain_rule(request())
    assert execution.graph_result.status == "EXPERIMENTAL"
    assert len(execution.graph_result.results) == 3
    assert all(item.equal is True for item in execution.graph_result.results)
    final = execution.graph_result.results[-1]
    assert "3*(x**2 + 1)**2" in final.explanation or final.equal is True


@pytest.mark.parametrize("expression", [
    "x**3",
    "sin(x)**2",
    "(x**2+1)**(1/2)",
    "x**2+1",
])
def test_unsupported_decomposition_shapes_are_rejected(expression):
    with pytest.raises(ExpressionError):
        decompose_power_chain_rule(request(expression))


def test_non_differentiation_request_is_rejected():
    bad = MathRequest(operation=Operation.EXPAND, expression="(x+1)**2")
    with pytest.raises(ExpressionError):
        decompose_power_chain_rule(bad)


def test_direct_execution_includes_and_checks_rule_preconditions():
    execution = execute_power_chain_rule(request())
    assert len(execution.graph_result.side_condition_results) == 3
    assert all(item.status == "EXPERIMENTAL" for item in execution.graph_result.side_condition_results)
    assert execution.graph_result.status == "EXPERIMENTAL"


def test_direct_execution_reports_rational_domain_constraints():
    execution = execute_power_chain_rule(request("((x+1)/(x-1))**2"))
    assert all(item.status == "EXPERIMENTAL" for item in execution.graph_result.side_condition_results)
    assert all(item.domain_constraints == ("x - 1",) for item in execution.graph_result.side_condition_results)
    restrictions = execution.graph_result.domain_restrictions
    assert len(restrictions) == 1
    assert restrictions[0].predicate == "nonzero"
    assert restrictions[0].expression == "x - 1"
    assert restrictions[0].source_kind == "division_denominator"
    assert len(restrictions[0].request_sha256) == 64
    assert restrictions[0].line == 1
    assert restrictions[0].column > 0
    assert execution.graph_result.status == "EXPERIMENTAL"

