from mosaic.core.requests import MathRequest
from mosaic.core.types import Operation
from mosaic.engines.algebra import ExpressionError
from mosaic.verification.derivation import build_derivation_tree
from mosaic.verification.derivation_graph import (
    compile_derivation_obligation_graph,
    evaluate_derivation_tree,
)
from mosaic.verification.graph import validate_obligation_graph


def request(expression="((x**2+1)**3)**2"):
    return MathRequest(
        operation=Operation.DIFFERENTIATE,
        expression=expression,
        variable="x",
    )


def test_nested_tree_compiles_to_leaf_obligations_with_dependencies():
    source = request()
    tree = build_derivation_tree(source)
    graph = compile_derivation_obligation_graph(source, tree)
    ordered = validate_obligation_graph(graph)

    assert len(graph.nodes) == 5
    assert len(ordered) == 5
    by_id = {node.obligation.obligation_id: node for node in graph.nodes}
    final_nodes = [
        node for node in graph.nodes
        if node.request.operation == Operation.VERIFY_IDENTITY
    ]
    assert len(final_nodes) == 2
    assert all(node.depends_on for node in final_nodes)
    assert all(dep in by_id for node in graph.nodes for dep in node.depends_on)


def test_leaf_only_tree_compiles_to_single_obligation():
    source = request("x**2+1")
    tree = build_derivation_tree(source)
    graph = compile_derivation_obligation_graph(source, tree)
    assert len(graph.nodes) == 1
    assert graph.nodes[0].depends_on == ()


def test_compiler_rejects_incomplete_or_tampered_tree():
    source = request()
    tree = build_derivation_tree(source)
    altered_root = tree.root.model_copy(update={"children": tree.root.children[:2]})
    altered = tree.model_copy(update={"root": altered_root, "node_count": 3})
    try:
        compile_derivation_obligation_graph(source, altered)
    except ExpressionError as exc:
        assert "invalid or incomplete" in str(exc)
    else:
        raise AssertionError("tampered derivation tree should be rejected")



def test_evaluator_keeps_missing_leaf_obligations_incomplete():
    source = request()
    tree = build_derivation_tree(source)
    result = evaluate_derivation_tree(source, tree, {})
    assert result.status == "INCOMPLETE"
    assert len(result.results) == 5
    assert all(item.status == "INCOMPLETE" for item in result.results)



def test_compiled_graph_includes_unresolved_rule_preconditions():
    source = request()
    tree = build_derivation_tree(source)
    graph = compile_derivation_obligation_graph(source, tree)
    assert len(graph.side_conditions) == 6
    assert {item.condition.status for item in graph.side_conditions} == {"UNSUPPORTED"}


def test_unresolved_preconditions_cap_aggregate_status_after_leaf_checks():
    import json

    source = request()
    tree = build_derivation_tree(source)
    graph = compile_derivation_obligation_graph(source, tree)
    candidates = {}
    for node in graph.nodes:
        if node.request.operation == Operation.VERIFY_IDENTITY:
            candidates[node.obligation.obligation_id] = json.dumps({
                "operation": "verify_identity",
                "expression": node.request.expression,
                "rhs": node.request.rhs,
            })
        else:
            from mosaic.engines.algebra import run_algebra
            operation = node.request.operation.value
            variable = node.request.variable or "x"
            expected = run_algebra(operation, node.request.expression, variable)
            candidates[node.obligation.obligation_id] = json.dumps({
                "operation": operation,
                "expression": node.request.expression,
                "variable": variable,
                "result": str(expected),
            })

    result = evaluate_derivation_tree(source, tree, candidates)
    assert result.status == "EXPERIMENTAL"
    assert len(result.side_condition_results) == 6
    assert all(item.status == "EXPERIMENTAL" for item in result.side_condition_results)
    assert all(item.checker_id == "calculus.rational_domain_constraints.v1" for item in result.side_condition_results)
    assert all(item.status == "EXPERIMENTAL" for item in result.results)


def test_compiled_graph_rejects_tampered_side_condition_contract():
    from mosaic.verification.graph import validate_obligation_graph

    source = request()
    tree = build_derivation_tree(source)
    graph = compile_derivation_obligation_graph(source, tree)
    first = graph.side_conditions[0]
    altered_condition = first.condition.model_copy(update={"statement": "pretend this is satisfied"})
    altered_node = first.model_copy(update={"condition": altered_condition})
    altered_graph = graph.model_copy(update={
        "side_conditions": (altered_node,) + graph.side_conditions[1:]
    })
    try:
        validate_obligation_graph(altered_graph)
    except ValueError as exc:
        assert "invalid side-condition contract" in str(exc)
    else:
        raise AssertionError("tampered side condition should be rejected")
