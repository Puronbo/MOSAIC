import json

from mosaic.core.requests import MathRequest
from mosaic.core.types import Operation
from mosaic.verification.task_bound import verify_task_bound_candidate


def req(operation, expression, variable="x", rhs=None):
    return MathRequest(operation=Operation(operation), expression=expression, variable=variable, rhs=rhs)


def test_identity_is_bound_to_both_requested_sides():
    request = req("verify_identity", "(x+1)**2", rhs="x**2+2*x+1")
    raw = json.dumps({"operation":"verify_identity", "expression":"(x+1)**2", "rhs":"x**2+2*x+1"})
    result = verify_task_bound_candidate(request, raw)
    assert result.status == "EXPERIMENTAL"
    assert result.equal is True


def test_irrelevant_true_identity_cannot_answer_request():
    request = req("verify_identity", "x+1", rhs="x+2")
    raw = json.dumps({"operation":"verify_identity", "expression":"x", "rhs":"x"})
    result = verify_task_bound_candidate(request, raw)
    assert result.status == "INVALID_CERTIFICATE"


def test_transform_result_is_checked_against_requested_operation():
    request = req("expand", "(x+1)**2")
    raw = json.dumps({"operation":"expand", "expression":"(x+1)**2", "variable":"x", "result":"x**2+2*x+1"})
    result = verify_task_bound_candidate(request, raw)
    assert result.status == "EXPERIMENTAL"
    assert result.equal is True


def test_wrong_operation_is_rejected():
    request = req("expand", "(x+1)**2")
    raw = json.dumps({"operation":"factor", "expression":"(x+1)**2", "variable":"x", "result":"(x+1)**2"})
    assert verify_task_bound_candidate(request, raw).status == "INVALID_CERTIFICATE"


def test_wrong_result_is_not_accepted():
    request = req("differentiate", "x**3")
    raw = json.dumps({"operation":"differentiate", "expression":"x**3", "variable":"x", "result":"3*x"})
    result = verify_task_bound_candidate(request, raw)
    assert result.status == "INCOMPLETE"
    assert result.equal is False


def test_integrate_is_not_silently_accepted():
    request = req("integrate", "x**2")
    raw = json.dumps({"operation":"integrate", "expression":"x**2", "variable":"x", "result":"x**3/3"})
    assert verify_task_bound_candidate(request, raw).status == "UNSUPPORTED"


def test_extra_fields_are_rejected():
    request = req("expand", "x+1")
    raw = json.dumps({"operation":"expand", "expression":"x+1", "variable":"x", "result":"x+1", "trusted":True})
    assert verify_task_bound_candidate(request, raw).status == "INVALID_CERTIFICATE"



def test_simplification_cannot_silently_expand_domain_after_cancellation():
    request = req("simplify", "((x**2 - 1)/(x - 1))**2")
    raw = json.dumps({"operation": "simplify", "expression": "((x**2 - 1)/(x - 1))**2", "variable": "x", "result": "(x + 1)**2"})
    result = verify_task_bound_candidate(request, raw)
    assert result.status == "INCOMPLETE"
    assert result.equal is False
    assert result.domain_status == "EXPANDED"
    assert "domain" in result.explanation.lower()


def test_simplification_passes_when_original_domain_is_preserved():
    request = req("simplify", "((x**2 - 1)/(x - 1))**2")
    raw = json.dumps({"operation": "simplify", "expression": "((x**2 - 1)/(x - 1))**2", "variable": "x", "result": "(x**2 - 1)**2/(x - 1)**2"})
    result = verify_task_bound_candidate(request, raw)
    assert result.status == "EXPERIMENTAL"
    assert result.equal is True
    assert result.domain_status == "PRESERVED"


def test_differentiation_does_not_apply_rewrite_domain_equality_policy():
    request = req("differentiate", "x**3")
    raw = json.dumps({"operation": "differentiate", "expression": "x**3", "variable": "x", "result": "3*x**2"})
    result = verify_task_bound_candidate(request, raw)
    assert result.status == "EXPERIMENTAL"
    assert result.domain_status == "NOT_CHECKED"



def test_domain_certificate_is_bound_to_request_candidate_and_exclusions():
    request = req("simplify", "((x**2 - 1)/(x - 1))**2")
    raw = json.dumps({
        "operation": "simplify",
        "expression": "((x**2 - 1)/(x - 1))**2",
        "variable": "x",
        "result": "(x**2 - 1)**2/(x - 1)**2",
    })
    result = verify_task_bound_candidate(request, raw)
    certificate = result.domain_certificate
    assert certificate is not None
    assert certificate.request_sha256 == result.request_sha256
    assert certificate.candidate_sha256 == result.candidate_sha256
    assert certificate.status == "PRESERVED"
    assert certificate.original_nonzero_factors == ("x - 1",)
    assert certificate.candidate_nonzero_factors == ("x - 1",)
    assert certificate.checker_id == "rational_domain_factor_comparison.v1"


def test_domain_expansion_certificate_identifies_missing_exclusion():
    request = req("simplify", "((x**2 - 1)/(x - 1))**2")
    raw = json.dumps({
        "operation": "simplify",
        "expression": "((x**2 - 1)/(x - 1))**2",
        "variable": "x",
        "result": "(x + 1)**2",
    })
    result = verify_task_bound_candidate(request, raw)
    assert result.domain_certificate is not None
    assert result.domain_certificate.status == "EXPANDED"
    assert result.domain_certificate.missing_factors == ("x - 1",)
    assert result.domain_certificate.candidate_nonzero_factors == ()
