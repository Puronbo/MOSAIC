from mosaic.verification.exact_checker import verify_identity

def test_exact_identity_has_certificate():
    result = verify_identity("(x+1)**2", "x**2+2*x+1")
    assert result["status"] == "PROVED"
    assert result["equal"] is True
    assert result["certificate"]["kind"] == "exact-symbolic-zero"

def test_nonidentity_is_not_claimed_as_universal_inequality():
    result = verify_identity("x+1", "x+2")
    assert result["status"] == "INCOMPLETE"
    assert result["equal"] is False
