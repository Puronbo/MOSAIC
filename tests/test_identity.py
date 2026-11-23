from mosaic.verification.exact_checker import verify_identity

def test_exact_identity_returns_candidate_not_formal_proof():
    result = verify_identity("(x+1)**2", "x**2+2*x+1")
    assert result["status"] == "EXPERIMENTAL"
    assert result["equal"] is True
    assert result["certificate"]["kind"] == "symbolic-zero-candidate"

def test_nonidentity_is_not_claimed_as_universal_inequality():
    result = verify_identity("x+1", "x+2")
    assert result["status"] == "INCOMPLETE"
    assert result["equal"] is False
