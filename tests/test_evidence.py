import json

import pytest

from mosaic.core.requests import MathRequest
from mosaic.core.types import Operation
from mosaic.verification.evidence import (
    EvidenceItem, aggregate_evidence, evidence_from_check,
    REGISTERED_EVIDENCE_SOURCES,
)
from mosaic.verification.task_bound import verify_task_bound_candidate


def _bundle(result: str, expression: str = "(x + 1)**2"):
    request = MathRequest(
        operation=Operation.SIMPLIFY, expression=expression, variable="x"
    )
    raw = json.dumps({
        "operation": "simplify", "expression": expression,
        "variable": "x", "result": result,
    })
    check = verify_task_bound_candidate(request, raw)
    return evidence_from_check(check, request, raw)


def test_related_algebra_and_domain_findings_count_as_one_source():
    bundle = _bundle("(x + 1)*(x - 1)/(x - 1)", "(x**2 - 1)/(x - 1)")
    assert len(bundle.items) == 3
    assert {item.claim_id for item in bundle.items} == {
        "algebraic_equivalence", "rational_domain_preservation"
    }
    assert bundle.assessment.status == "MULTI_SOURCE_SUPPORT"
    assert bundle.assessment.independent_support_count == 2
    assert set(bundle.assessment.independent_support_groups) == {
        "sympy_symbolic_runtime", "exact_fraction_polynomial"
    }


def test_algebraic_failure_is_not_hidden_by_domain_support():
    bundle = _bundle("x + 1")
    assert bundle.assessment.status == "REFUTED_BY_CHECKER"
    assert bundle.assessment.independent_refutation_groups == (
        "exact_fraction_polynomial", "sympy_symbolic_runtime"
    )
    assert any(item.finding == "refutes" for item in bundle.items)


def test_evidence_items_are_bound_to_exact_candidate_and_source_type():
    bundle = _bundle("x**2 + 2*x + 1")
    item = next(item for item in bundle.items if item.checker_id == "mosaic.task_bound_candidate.v1")
    assert item.source_kind == "deterministic_checker"
    assert len(item.request_sha256) == 64
    assert len(item.candidate_sha256) == 64


def test_distinct_checker_implementations_accumulate_as_distinct_sources():
    bundle = _bundle("x**2 + 2*x + 1")
    assert bundle.assessment.independent_support_count == 2
    assert bundle.assessment.model_opinion_count == 0


def test_distinct_registered_checker_groups_can_accumulate_support(monkeypatch):
    bundle = _bundle("x**2 + 2*x + 1")
    first = bundle.items[0]
    monkeypatch.setitem(
        REGISTERED_EVIDENCE_SOURCES,
        "independent.polynomial_checker.v1",
        "another_exact_arithmetic_implementation",
    )
    independent = first.model_copy(update={
        "evidence_id": "a" * 64,
        "checker_id": "independent.polynomial_checker.v1",
        "independence_group": "another_exact_arithmetic_implementation",
    })
    combined = aggregate_evidence((first, independent))
    assert combined.assessment.status == "MULTI_SOURCE_SUPPORT"
    assert combined.assessment.independent_support_count == 2


def test_independent_disagreement_on_same_claim_is_conflict(monkeypatch):
    bundle = _bundle("x**2 + 2*x + 1")
    first = next(item for item in bundle.items if item.checker_id == "mosaic.task_bound_candidate.v1")
    monkeypatch.setitem(
        REGISTERED_EVIDENCE_SOURCES,
        "independent.polynomial_checker.v1",
        "another_exact_arithmetic_implementation",
    )
    independent = first.model_copy(update={
        "evidence_id": "b" * 64,
        "checker_id": "independent.polynomial_checker.v1",
        "independence_group": "another_exact_arithmetic_implementation",
        "finding": "refutes",
    })
    combined = aggregate_evidence((first, independent))
    assert combined.assessment.status == "CONFLICT"
    assert combined.assessment.claim_conflicts == ("algebraic_equivalence",)


def test_unregistered_checker_cannot_inflate_independence():
    bundle = _bundle("x**2 + 2*x + 1")
    first = bundle.items[0]
    forged = first.model_copy(update={
        "evidence_id": "c" * 64,
        "checker_id": "model.says.yes",
        "independence_group": "new_vote",
    })
    with pytest.raises(ValueError, match="not registered"):
        aggregate_evidence((first, forged))
