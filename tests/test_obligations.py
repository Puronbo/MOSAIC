import pytest

from mosaic.core.requests import MathRequest
from mosaic.core.types import Operation
from mosaic.verification.obligations import (
    VerificationObligation,
    obligations_for_request,
    request_fingerprint,
)


def request(operation, expression="x", rhs=None):
    return MathRequest(operation=Operation(operation), expression=expression, rhs=rhs)


def test_identity_request_produces_named_checker_obligation():
    req = request("verify_identity", "(x+1)**2", "x**2+2*x+1")
    (obligation,) = obligations_for_request(req)
    assert obligation.kind == "identity"
    assert obligation.checker_id == "mosaic.symbolic_identity.v1"
    assert obligation.request_sha256 == request_fingerprint(req)
    assert obligation.obligation_id.endswith(":primary")


def test_supported_transformation_names_deterministic_checker():
    (obligation,) = obligations_for_request(request("differentiate", "x**2"))
    assert obligation.kind == "transformation"
    assert obligation.checker_id == "mosaic.recompute_differentiate.v1"


def test_unimplemented_operation_is_explicitly_unsupported():
    (obligation,) = obligations_for_request(request("integrate", "x**2"))
    assert obligation.kind == "unsupported"
    assert obligation.checker_id == "none"


def test_missing_identity_rhs_is_explicitly_unsupported():
    (obligation,) = obligations_for_request(request("verify_identity"))
    assert obligation.kind == "unsupported"


def test_obligation_rejects_extra_fields_and_bad_hash():
    with pytest.raises(Exception):
        VerificationObligation(
            obligation_id="o1", kind="identity", request_sha256="bad",
            operation="verify_identity", checker_id="mosaic.symbolic_identity.v1",
            statement="Check equality.", injected=True,
        )



def test_obligation_gate_delegates_to_the_named_registered_checker():
    from mosaic.verification.obligations import verify_obligation_candidate
    req = request("expand", "(x+1)**2")
    (obligation,) = obligations_for_request(req)
    raw = '{"operation":"expand","expression":"(x+1)**2","variable":"x","result":"x**2+2*x+1"}'
    result = verify_obligation_candidate(req, obligation, raw)
    assert result.status == "EXPERIMENTAL"
    assert result.equal is True


def test_stale_obligation_cannot_be_reused_for_another_request():
    from mosaic.verification.obligations import verify_obligation_candidate
    original = request("expand", "(x+1)**2")
    changed = request("expand", "(x+2)**2")
    (obligation,) = obligations_for_request(original)
    result = verify_obligation_candidate(changed, obligation, "{}")
    assert result.status == "INVALID_CERTIFICATE"


def test_unsupported_obligation_never_invokes_a_checker():
    from mosaic.verification.obligations import verify_obligation_candidate
    req = request("integrate", "x**2")
    (obligation,) = obligations_for_request(req)
    result = verify_obligation_candidate(req, obligation, "{}")
    assert result.status == "UNSUPPORTED"



def test_modified_obligation_statement_is_rejected():
    from mosaic.verification.obligations import verify_obligation_candidate
    req = request("expand", "(x+1)**2")
    (obligation,) = obligations_for_request(req)
    altered = obligation.model_copy(update={"statement": "Check an unrelated claim."})
    result = verify_obligation_candidate(req, altered, "{}")
    assert result.status == "INVALID_CERTIFICATE"
