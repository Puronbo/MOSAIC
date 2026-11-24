import pytest

from mosaic.core.requests import MathRequest
from mosaic.core.types import Operation
from mosaic.engines.algebra import ExpressionError
from mosaic.verification.recursive_execution import execute_recursive_derivation


def request(expression="((x**2+1)**3)**2"):
    return MathRequest(
        operation=Operation.DIFFERENTIATE,
        expression=expression,
        variable="x",
    )


def test_recursive_execution_replays_nested_rules_and_checks_all_leaves():
    execution = execute_recursive_derivation(request())
    assert execution.tree.node_count == 7
    assert len(execution.executed_rules) == 2
    assert execution.executed_rules[0].path == ()
    assert execution.executed_rules[1].path == (1,)
    assert len(execution.graph_result.results) == 5
    assert all(item.equal is True for item in execution.graph_result.results)
    assert execution.graph_result.status == "EXPERIMENTAL"


def test_recursive_execution_handles_a_leaf_without_decomposition():
    execution = execute_recursive_derivation(request("x**2+1"))
    assert execution.tree.node_count == 1
    assert execution.executed_rules == ()
    assert len(execution.graph_result.results) == 1
    assert execution.graph_result.results[0].equal is True
    assert execution.graph_result.status == "EXPERIMENTAL"


def test_recursive_execution_preserves_depth_and_node_budgets():
    with pytest.raises(ExpressionError, match="max_depth"):
        execute_recursive_derivation(request(), max_depth=1)
    with pytest.raises(ExpressionError, match="max_nodes"):
        execute_recursive_derivation(request(), max_nodes=3)


def test_recursive_execution_does_not_claim_formal_proof():
    execution = execute_recursive_derivation(request())
    assert execution.graph_result.status != "FORMALLY_VERIFIED"
