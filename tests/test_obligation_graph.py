import pytest

from mosaic.core.requests import MathRequest
from mosaic.core.types import Operation
from mosaic.verification.graph import (
    ObligationGraph,
    ObligationNode,
    evaluate_obligation_graph,
    validate_obligation_graph,
)
from mosaic.verification.obligations import obligations_for_request


def node(operation, expression, rhs=None, depends_on=()):
    request = MathRequest(
        operation=Operation(operation),
        expression=expression,
        rhs=rhs,
    )
    (obligation,) = obligations_for_request(request)
    return ObligationNode(
        request=request,
        obligation=obligation,
        depends_on=depends_on,
    )


def identity_candidate(lhs, rhs):
    return (
        '{"operation":"verify_identity","expression":' + repr(lhs)
        + ',"rhs":' + repr(rhs) + '}'
    )


def expand_candidate(expression, result):
    import json
    return json.dumps({
        "operation": "expand",
        "expression": expression,
        "variable": "x",
        "result": result,
    })


def test_graph_orders_dependencies_before_dependents():
    first = node("verify_identity", "x+1", "x+1")
    second = node("verify_identity", "x+2", "x+2", (first.obligation.obligation_id,))
    graph = ObligationGraph(nodes=(second, first))
    ordered = validate_obligation_graph(graph)
    assert [item.obligation.obligation_id for item in ordered] == [
        first.obligation.obligation_id,
        second.obligation.obligation_id,
    ]


def test_graph_rejects_unknown_dependency_and_cycles():
    first = node("verify_identity", "x", "x", ("missing",))
    with pytest.raises(ValueError, match="unknown dependency"):
        validate_obligation_graph(ObligationGraph(nodes=(first,)))

    a = node("verify_identity", "x", "x")
    b = node("verify_identity", "y", "y", (a.obligation.obligation_id,))
    a_cycle = a.model_copy(update={"depends_on": (b.obligation.obligation_id,)})
    with pytest.raises(ValueError, match="cycle"):
        validate_obligation_graph(ObligationGraph(nodes=(a_cycle, b)))


def test_all_satisfied_nodes_remain_experimental():
    first = node("expand", "(x+1)**2")
    second = node("verify_identity", "x+1", "x+1", (first.obligation.obligation_id,))
    graph = ObligationGraph(nodes=(first, second))
    candidates = {
        first.obligation.obligation_id: expand_candidate("(x+1)**2", "x**2+2*x+1"),
        second.obligation.obligation_id: identity_candidate("x+1", "x+1"),
    }
    result = evaluate_obligation_graph(graph, candidates)
    assert result.status == "EXPERIMENTAL"
    assert all(item.status == "EXPERIMENTAL" for item in result.results)


def test_failed_dependency_blocks_only_downstream_node():
    first = node("expand", "(x+1)**2")
    second = node("verify_identity", "x+1", "x+1", (first.obligation.obligation_id,))
    independent = node("verify_identity", "y+1", "y+1")
    graph = ObligationGraph(nodes=(first, second, independent))
    candidates = {
        first.obligation.obligation_id: expand_candidate("(x+1)**2", "x**2"),
        second.obligation.obligation_id: identity_candidate("x+1", "x+1"),
        independent.obligation.obligation_id: identity_candidate("y+1", "y+1"),
    }
    result = evaluate_obligation_graph(graph, candidates)
    by_id = {item.obligation_id: item for item in result.results}
    assert by_id[first.obligation.obligation_id].equal is False
    assert by_id[second.obligation.obligation_id].status == "INCOMPLETE"
    assert by_id[independent.obligation.obligation_id].equal is True
    assert result.status == "INCOMPLETE"


def test_missing_candidate_is_incomplete_not_success():
    item = node("verify_identity", "x", "x")
    result = evaluate_obligation_graph(ObligationGraph(nodes=(item,)), {})
    assert result.status == "INCOMPLETE"
