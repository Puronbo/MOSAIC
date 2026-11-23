import json

from mosaic.verification.candidate import check_identity_candidate


def candidate(lhs, rhs):
    return json.dumps({"claim_type": "identity", "lhs": lhs, "rhs": rhs})


def test_valid_identity_is_checked_but_not_formally_proved():
    result = check_identity_candidate(candidate("(x+1)**2", "x**2+2*x+1"))
    assert result.status == "EXPERIMENTAL"
    assert result.equal is True
    assert result.certificate["kind"] == "symbolic-zero-candidate"
    assert len(result.input_sha256) == 64
    assert len(result.claim_sha256) == 64


def test_non_identity_is_incomplete_not_a_proof_of_inequality():
    result = check_identity_candidate(candidate("x+1", "x+2"))
    assert result.status == "INCOMPLETE"
    assert result.equal is False
    assert result.certificate is None


def test_invalid_json_is_rejected_without_symbolic_evaluation():
    result = check_identity_candidate("{not json")
    assert result.status == "INVALID_CERTIFICATE"
    assert result.equal is None
    assert result.claim_sha256 is None


def test_extra_fields_are_rejected():
    raw = json.dumps({
        "claim_type": "identity", "lhs": "x", "rhs": "x",
        "verified": True,
    })
    result = check_identity_candidate(raw)
    assert result.status == "INVALID_CERTIFICATE"


def test_unsupported_claim_type_is_rejected():
    raw = json.dumps({"claim_type": "theorem", "lhs": "x", "rhs": "x"})
    assert check_identity_candidate(raw).status == "INVALID_CERTIFICATE"


def test_expression_parser_rejects_injected_syntax():
    result = check_identity_candidate(candidate("x.__class__", "x"))
    assert result.status == "INVALID_CERTIFICATE"
    assert result.claim_sha256 is not None


def test_input_size_is_bounded():
    try:
        check_identity_candidate(" " * 10001)
    except ValueError as exc:
        assert "10000" in str(exc)
    else:
        raise AssertionError("expected size limit")
