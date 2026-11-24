import base64
import pytest

from mosaic.verification.evidence_envelope import EvidenceEventOutcome
from mosaic.verification.lean_runner_signature import generate_ed25519_keypair
from mosaic.verification.historical_trust import (
    HistoricalLeanTrustedKey,
    HistoricalSignedLeanAttestation,
    verify_historical_with_keyring,
)


ISSUED = "2026-11-24T01:00:00.000000Z"
WITNESSED = "2026-11-24T01:01:00.000000Z"
PRIVATE, PUBLIC = generate_ed25519_keypair()


def signed(issued=ISSUED):
    source = "theorem receipt_test : True := by trivial"
    import hashlib

    return HistoricalSignedLeanAttestation.sign_v2(
        issued_at_utc=issued,
        receipt_id="historical-test",
        runner_id="runner",
        key_id="key-1",
        request_sha256="1" * 64,
        artifact_sha256="2" * 64,
        proof_artifact_sha256=hashlib.sha256(source.encode()).hexdigest(),
        proof_source=source,
        checker_id="lean",
        kernel_version="4.36.0",
        outcome=EvidenceEventOutcome.PASSED,
        private_key=PRIVATE,
    )


def key(status="active", **dates):
    dates.setdefault("activated_at_utc", "2026-11-01T00:00:00Z")
    return HistoricalLeanTrustedKey(
        key_id="key-1",
        public_key_b64=base64.b64encode(PUBLIC).decode(),
        status=status,
        **dates,
    )


def verify(receipt, record, witnessed=WITNESSED, trusted=True):
    return verify_historical_with_keyring(
        receipt, {"key-1": record},
        verified_timestamp_utc=witnessed,
        timestamp_evidence_verified=trusted,
    )


def test_v2_issuance_time_is_signed_and_uses_canonical_utc():
    receipt = signed()
    assert receipt.schema_version == "2.0"
    assert receipt.issued_at_utc == ISSUED
    assert receipt.verify(PUBLIC)
    changed = receipt.model_copy(update={"issued_at_utc": "2026-11-24T01:02:00.000000Z"})
    assert not changed.verify(PUBLIC)


def test_historical_acceptance_requires_verified_external_timestamp():
    receipt = signed()
    assert verify(receipt, key(), trusted=True)
    assert not verify(receipt, key(), trusted=False)
    assert not verify(receipt, key(), witnessed="2026-11-24T00:59:59Z")


def test_active_key_must_be_activated_and_have_no_lifecycle_end():
    receipt = signed()
    assert not verify(receipt, key(activated_at_utc="2026-11-24T01:00:01Z"))
    assert not verify(receipt, key(retired_at_utc="2026-11-25T00:00:00Z"))


def test_retired_key_accepts_only_receipts_and_timestamps_before_retirement():
    receipt = signed()
    retired = key("retired", retired_at_utc="2026-11-24T01:02:00Z")
    assert verify(receipt, retired)
    assert not verify(receipt, retired, witnessed="2026-11-24T01:03:00Z")
    late = signed("2026-11-24T01:02:00.000000Z")
    assert not verify(late, retired)


def test_revoked_key_requires_pre_revocation_timestamp_and_pre_revocation_issue():
    receipt = signed()
    revoked = key("revoked", revoked_at_utc="2026-11-24T01:02:00Z")
    assert verify(receipt, revoked)
    assert not verify(receipt, revoked, witnessed="2026-11-24T01:03:00Z")
    late = signed("2026-11-24T01:02:00.000000Z")
    assert not verify(late, revoked)


def test_compromise_effective_time_rejects_backdated_post_compromise_receipt():
    before = signed("2026-11-24T00:59:00.000000Z")
    after = signed("2026-11-24T01:00:00.000000Z")
    compromised = key(
        "revoked",
        revoked_at_utc="2026-11-24T01:03:00Z",
        compromise_effective_at_utc="2026-11-24T00:59:30Z",
    )
    assert verify(before, compromised)
    assert not verify(after, compromised)


def test_rejects_timezone_naive_times_and_malformed_lifecycle_records():
    with pytest.raises(ValueError, match="UTC offset"):
        signed("2026-11-24T01:00:00")
    receipt = signed()
    malformed = key("revoked", revoked_at_utc="not-a-time")
    assert not verify(receipt, malformed)
