import base64

from mosaic.verification.lean_runner_signature import generate_ed25519_keypair
from mosaic.verification.policy_registry import SignedPolicyRegistryEntry
from mosaic.verification.policy_governance import (
    PolicyPublisherApproval, PolicyPublisherKey, verify_policy_registry_with_keyring,
)
from mosaic.verification.trust_policy import HistoricalTrustPolicy, HistoricalTrustPolicyRecord


P1_PRIVATE, P1_PUBLIC = generate_ed25519_keypair()
P2_PRIVATE, P2_PUBLIC = generate_ed25519_keypair()


def record():
    policy = HistoricalTrustPolicy(
        policy_id="mosaic-governance", policy_version="1.0.0",
        allowed_kernel_ids=("Lean",), allowed_checker_ids=("lean",),
    )
    return HistoricalTrustPolicyRecord(
        policy_sha256=policy.digest(), policy=policy,
        activated_at_utc="2026-11-01T00:00:00Z",
    )


def key(key_id, public, activated="2026-11-01T00:00:00Z", revoked=None):
    return PolicyPublisherKey(
        key_id=key_id, public_key_b64=base64.b64encode(public).decode("ascii"),
        activated_at_utc=activated, revoked_at_utc=revoked,
    )


def entry():
    return SignedPolicyRegistryEntry.sign(
        sequence=0, previous_entry_sha256=None, policy_record=record(),
        published_at_utc="2026-11-24T01:00:00.000000Z",
        publisher_key_id="publisher-1", private_key=P1_PRIVATE,
    )


def test_keyring_verifies_active_publisher():
    assert verify_policy_registry_with_keyring(
        [entry()], publisher_keyring={"publisher-1": key("publisher-1", P1_PUBLIC)}
    )


def test_rejects_publisher_before_activation_or_after_revocation():
    item = entry()
    before = key("publisher-1", P1_PUBLIC, activated="2026-11-25T00:00:00Z")
    after = key("publisher-1", P1_PUBLIC, revoked="2026-11-24T00:59:59Z")
    assert not verify_policy_registry_with_keyring([item], publisher_keyring={"publisher-1": before})
    assert not verify_policy_registry_with_keyring([item], publisher_keyring={"publisher-1": after})


def test_quorum_requires_distinct_independent_approval():
    item = entry()
    approval = PolicyPublisherApproval.sign(
        entry=item, publisher_key_id="publisher-2",
        approved_at_utc="2026-11-24T01:01:00Z", private_key=P2_PRIVATE,
    )
    ring = {
        "publisher-1": key("publisher-1", P1_PUBLIC),
        "publisher-2": key("publisher-2", P2_PUBLIC),
    }
    assert not verify_policy_registry_with_keyring(
        [item], publisher_keyring=ring, minimum_approvals=2
    )
    assert verify_policy_registry_with_keyring(
        [item], publisher_keyring=ring, minimum_approvals=2,
        approvals_by_entry={item.entry_sha256(): [approval]},
    )


def test_quorum_rejects_duplicate_or_untrusted_approval():
    item = entry()
    approval = PolicyPublisherApproval.sign(
        entry=item, publisher_key_id="publisher-2",
        approved_at_utc="2026-11-24T01:01:00Z", private_key=P2_PRIVATE,
    )
    ring = {
        "publisher-1": key("publisher-1", P1_PUBLIC),
        "publisher-2": key("publisher-2", P2_PUBLIC),
    }
    assert not verify_policy_registry_with_keyring(
        [item], publisher_keyring=ring, minimum_approvals=2,
        approvals_by_entry={item.entry_sha256(): [approval, approval]},
    )
    assert not verify_policy_registry_with_keyring(
        [item], publisher_keyring={"publisher-1": ring["publisher-1"]},
        minimum_approvals=2, approvals_by_entry={item.entry_sha256(): [approval]},
    )


def test_approval_is_bound_to_exact_entry_and_revocation_time():
    item = entry()
    approval = PolicyPublisherApproval.sign(
        entry=item, publisher_key_id="publisher-2",
        approved_at_utc="2026-11-24T01:01:00Z", private_key=P2_PRIVATE,
    )
    ring = {
        "publisher-1": key("publisher-1", P1_PUBLIC),
        "publisher-2": key("publisher-2", P2_PUBLIC, revoked="2026-11-24T01:00:30Z"),
    }
    assert not verify_policy_registry_with_keyring(
        [item], publisher_keyring=ring, minimum_approvals=2,
        approvals_by_entry={item.entry_sha256(): [approval]},
    )
    altered = approval.model_copy(update={"entry_sha256": "0" * 64})
    assert not altered.verify(ring, item)
