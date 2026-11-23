import json

from mosaic.core.requests import MathRequest
from mosaic.core.types import Operation
from mosaic.verification.evidence import (\n    EvidenceItem, aggregate_evidence, evidence_from_check,\n    REGISTERED_EVIDENCE_SOURCES,\n)
from mosaic.verification.task_bound import verify_task_bound_candidate


def _check(result: str):
    request = MathRequest(
        operation=Operation.SIMPLIFY,
        expression="(x + 1)**2",
        variable="x",
    )
    raw = json.dumps({
        "operation": "simplify",
        "expression": "(x + 1)**2",
        "variable": "x",
        "result": result,
    })
    return verify_task_bound_candidate(request, raw)


def test_related_algebra_and_domain_findings_count_as_one_source():
    request = MathRequest(
        operation=Operation.SIMPLIFY,
        expression="(x**2 - 1)/(x - 1)",
        variable="x",
    )
    raw = json.dumps({
        "operation": "simplify",
        "expression": "(x**2 - 1)/(x - 1)",
        "variable": "x",
        "result": "(x + 1)*(x - 1)/(x - 1)",
    })
    bundle = evidence_from_check(verify_task_bound_candidate(request, raw))
    assert len(bundle.items) == 2
    assert {item.claim_id for item in bundle.items} == {
        "algebraic_equivalence", "rational_domain_preservation"
    }
    assert bundle.assessment.status == "SINGLE_SOURCE_SUPPORT"
    assert bundle.assessment.independent_support_count == 1
    assert bundle.assessment.independent_support_groups == ("sympy_symbolic_runtime",)


def test_algebraic_failure_is_not_hidden_by_domain_support():
    request = MathRequest(
        operation=Operation.SIMPLIFY,
        expression="(x + 1)**2",
        variable="x",
    )
    raw = json.dumps({
        "operation": "simplify",
        "expression": "(x + 1)**2",
        "variable": "x",
        "result": "x + 1",
    })
    bundle = evidence_from_check(verify_task_bound_candidate(request, raw))
    assert bundle.assessment.status == "REFUTED_BY_CHECKER"
    assert bundle.assessment.independent_support_count == 0
    assert any(item.finding == "refutes" for item in bundle.items)


def test_evidence_items_are_bound_to_exact_candidate_and_source_type():
    bundle = evidence_from_check(_check("x**2 + 2*x + 1"))
    item = bundle.items[0]
    assert item.source_kind == "deterministic_checker"
    assert item.checker_id == "mosaic.task_bound_candidate.v1"
    assert len(item.request_sha256) == 64
    assert len(item.candidate_sha256) == 64


def test_two_findings_from_same_runtime_are_not_independent_votes():
    bundle = evidence_from_check(_check("x**2 + 2*x + 1"))
    assert bundle.assessment.independent_support_count == 1
    assert bundle.assessment.model_opinion_count == 0



def test_distinct_registered_checker_groups_can_accumulate_support(monkeypatch):
    bundle = evidence_from_check(_check("x**2 + 2*x + 1"))
    first = bundle.items[0]
    monkeypatch.setitem(REGISTERED_EVIDENCE_SOURCES, "independent.polynomial_checker.v1", "exact_polynomial_arithmetic")
    independent = first.model_copy(update={
        "evidence_id": "a" * 64,
        "checker_id": "independent.polynomial_checker.v1",
        "independence_group": "exact_polynomial_arithmetic",
    })
    combined = aggregate_evidence((first, independent))
    assert combined.assessment.status == "MULTI_SOURCE_SUPPORT"
    assert combined.assessment.independent_support_count == 2


def test_independent_disagreement_on_same_claim_is_conflict(monkeypatch):
    bundle = evidence_from_check(_check("x**2 + 2*x + 1"))
    first = bundle.items[0]
    monkeypatch.setitem(REGISTERED_EVIDENCE_SOURCES, "independent.polynomial_checker.v1", "exact_polynomial_arithmetic")
    independent = first.model_copy(update={
        "evidence_id": "b" * 64,
        "checker_id": "independent.polynomial_checker.v1",
        "independence_group": "exact_polynomial_arithmetic",
        "finding": "refutes",
    })
    combined = aggregate_evidence((first, independent))
    assert combined.assessment.status == "CONFLICT"
    assert combined.assessment.claim_conflicts == ("algebraic_equivalence",)


def test_unregistered_checker_cannot_inflate_independence():
    bundle = evidence_from_check(_check("x**2 + 2*x + 1"))
    forged = bundle.items[0].model_copy(update={
        "evidence_id": "c" * 64,
        "checker_id": "model.says.yes",
        "independence_group": "new_vote",
    })
    import pytest
    with pytest.raises(ValueError, match="not registered"):
        aggregate_evidence((bundle.items[0], forged))
