import base64

from mosaic.verification.lean_runner_signature import generate_ed25519_keypair
from mosaic.verification.trust_policy import HistoricalTrustPolicy, HistoricalTrustPolicyRecord
from mosaic.verification.policy_registry import (
    SignedPolicyRegistryEntry,
    verify_policy_registry,
)


PRIVATE, PUBLIC = generate_ed25519_keypair()


def policy_record(version="1.0.0"):
    policy = HistoricalTrustPolicy(
        policy_id="mosaic-ci",
        policy_version=version,
        allowed_kernel_ids=("Lean",),
        allowed_checker_ids=("lean",),
    )
    return HistoricalTrustPolicyRecord(
        policy_sha256=policy.digest(),
        policy=policy,
        activated_at_utc="2026-11-01T00:00:00Z",
    )


def entry(sequence, previous=None, version="1.0.0", private=PRIVATE):
    return SignedPolicyRegistryEntry.sign(
        sequence=sequence,
        previous_entry_sha256=previous,
        policy_record=policy_record(version),
        published_at_utc=f"2026-11-24T01:0{sequence}:00Z",
        publisher_key_id="publisher-1",
        private_key=private,
    )


def chain():
    first = entry(0)
    second = entry(1, first.entry_sha256(), "1.0.1")
    return [first, second]


def test_signed_policy_registry_chain_and_checkpoint():
    entries = chain()
    assert verify_policy_registry(entries, publisher_public_keys={"publisher-1": PUBLIC})
    assert verify_policy_registry(
        entries,
        publisher_public_keys={"publisher-1": PUBLIC},
        expected_head_sequence=1,
        expected_head_sha256=entries[-1].entry_sha256(),
    )


def test_rejects_unknown_or_wrong_publisher_key():
    entries = chain()
    _, other_public = generate_ed25519_keypair()
    assert not verify_policy_registry(entries, publisher_public_keys={})
    assert not verify_policy_registry(entries, publisher_public_keys={"publisher-1": other_public})


def test_rejects_entry_mutation_and_forged_signature():
    entries = chain()
    altered = entries[0].model_copy(update={"published_at_utc": "2026-11-24T01:09:00.000000Z"})
    assert not altered.verify({"publisher-1": PUBLIC})
    forged = entries[0].model_copy(update={"signature_b64": base64.b64encode(b"x" * 64).decode()})
    assert not forged.verify({"publisher-1": PUBLIC})


def test_rejects_reordering_missing_entry_and_broken_link():
    entries = chain()
    assert not verify_policy_registry(list(reversed(entries)), publisher_public_keys={"publisher-1": PUBLIC})
    assert not verify_policy_registry(entries[1:], publisher_public_keys={"publisher-1": PUBLIC})
    broken = entries[1].model_copy(update={"previous_entry_sha256": "0" * 64})
    assert not verify_policy_registry([entries[0], broken], publisher_public_keys={"publisher-1": PUBLIC})


def test_checkpoint_detects_rollback_to_valid_prefix():
    entries = chain()
    assert verify_policy_registry([entries[0]], publisher_public_keys={"publisher-1": PUBLIC})
    assert not verify_policy_registry(
        [entries[0]],
        publisher_public_keys={"publisher-1": PUBLIC},
        expected_head_sequence=1,
        expected_head_sha256=entries[1].entry_sha256(),
    )


def test_checkpoint_requires_both_sequence_and_digest():
    entries = chain()
    assert not verify_policy_registry(
        entries,
        publisher_public_keys={"publisher-1": PUBLIC},
        expected_head_sequence=1,
    )
    assert not verify_policy_registry(
        entries,
        publisher_public_keys={"publisher-1": PUBLIC},
        expected_head_sha256=entries[-1].entry_sha256(),
    )


def test_rejects_noncanonical_or_timezone_naive_publication_time():
    try:
        entry(0, private=PRIVATE).model_copy(update={"published_at_utc": "2026-11-24T01:00:00"})
        bad = SignedPolicyRegistryEntry.sign(
            sequence=0, previous_entry_sha256=None, policy_record=policy_record(),
            published_at_utc="2026-11-24T01:00:00", publisher_key_id="publisher-1",
            private_key=PRIVATE,
        )
    except ValueError:
        return
    assert not bad.verify({"publisher-1": PUBLIC})


def test_rejects_invalid_policy_record_before_signing():
    record = policy_record().model_copy(update={"policy_sha256": "0" * 64})
    try:
        SignedPolicyRegistryEntry.sign(
            sequence=0, previous_entry_sha256=None, policy_record=record,
            published_at_utc="2026-11-24T01:00:00Z", publisher_key_id="publisher-1",
            private_key=PRIVATE,
        )
    except ValueError:
        return
    raise AssertionError("invalid policy record was signed")
