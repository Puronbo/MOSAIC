import pytest

from mosaic.core.requests import MathRequest
from mosaic.core.types import Operation
from mosaic.engines.algebra import ExpressionError
from mosaic.verification.decomposition import (
    applicable_decomposition_rules,
    decompose_request,
    execute_decomposition,
    get_decomposition_rule,
    registered_decomposition_rules,
    verify_decomposition_execution,
    verify_decomposition_plan,
)


def request(expression="(x**2+1)**3"):
    return MathRequest(
        operation=Operation.DIFFERENTIATE,
        expression=expression,
        variable="x",
    )


def test_registry_exposes_only_static_allow_list():
    rules = registered_decomposition_rules()
    assert [rule.rule_id for rule in rules] == [
        "calculus.chain_rule.integer_power.v1"
    ]
    assert get_decomposition_rule(rules[0].rule_id) is rules[0]


def test_matcher_finds_chain_rule_without_executing_a_model_plan():
    matches = applicable_decomposition_rules(request())
    assert [rule.rule_id for rule in matches] == [
        "calculus.chain_rule.integer_power.v1"
    ]
    assert applicable_decomposition_rules(request("x**2+1")) == ()


def test_generic_dispatch_and_registered_verifier():
    rule_id = "calculus.chain_rule.integer_power.v1"
    plan = decompose_request(request())
    assert verify_decomposition_plan(request(), rule_id, plan)
    assert not verify_decomposition_plan(request("(x+2)**3"), rule_id, plan)


def test_unknown_or_nonmatching_rules_are_rejected():
    with pytest.raises(ExpressionError, match="Unknown decomposition rule"):
        decompose_request(request(), "model.supplied.rule")
    with pytest.raises(ExpressionError, match="does not match"):
        decompose_request(request("x+1"), "calculus.chain_rule.integer_power.v1")


def test_verifier_rejects_wrong_plan_type():
    assert not verify_decomposition_plan(
        request(), "calculus.chain_rule.integer_power.v1", {"claim": "trust me"}
    )


def test_generic_executor_verifies_plan_and_returns_graph_execution():
    rule_id = "calculus.chain_rule.integer_power.v1"
    execution = execute_decomposition(request(), rule_id)
    assert execution.graph_result.status == "EXPERIMENTAL"
    assert verify_decomposition_execution(request(), rule_id, execution)


def test_execution_audit_rejects_tampered_graph_result():
    rule_id = "calculus.chain_rule.integer_power.v1"
    execution = execute_decomposition(request(), rule_id)
    tampered_result = execution.graph_result.model_copy(update={"status": "PROVED"})
    tampered_execution = execution.model_copy(update={"graph_result": tampered_result})
    assert not verify_decomposition_execution(request(), rule_id, tampered_execution)


def test_generic_executor_rejects_unknown_and_nonmatching_rule():
    with pytest.raises(ExpressionError, match="Unknown decomposition rule"):
        execute_decomposition(request(), "unregistered.rule")
    with pytest.raises(ExpressionError, match="does not match"):
        execute_decomposition(request("x+1"), "calculus.chain_rule.integer_power.v1")
