import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from mosaic.verification.policy_governance import PolicyPublisherKey
from mosaic.verification.policy_witness_recovery_governance import PolicyWitnessRecoveryPolicy
from mosaic.verification.policy_witness_recovery_policy_registry import (
    SignedPolicyWitnessRecoveryPolicyCheckpoint,
    SignedPolicyWitnessRecoveryPolicyEntry,
    verify_policy_witness_recovery_policy_registry,
)


def keypair(key_id):
    private = Ed25519PrivateKey.generate()
    raw_private = private.private_bytes_raw()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    record = PolicyPublisherKey(
        key_id=key_id, public_key_b64=base64.b64encode(public).decode(),
        activated_at_utc="2026-01-01T00:00:00.000000Z",
    )
    return raw_private, record


def entry(sequence, previous, policy, private, key_id="policy-admin"):
    return SignedPolicyWitnessRecoveryPolicyEntry.sign(
        registry_id="production-recovery", sequence=sequence,
        previous_entry_sha256=previous, policy=policy,
        published_at_utc=f"2026-11-{sequence + 1:02d}T00:00:00.000000Z",
        publisher_key_id=key_id, private_key=private,
    )


def test_signed_policy_chain_and_independent_head_checkpoint():
    private, record = keypair("policy-admin")
    first = entry(0, None, PolicyWitnessRecoveryPolicy(minimum_approvals=2), private)
    second = entry(1, first.digest(), PolicyWitnessRecoveryPolicy(
        minimum_approvals=3, required_operator_key_ids=("operator-a",)
    ), private)
    checkpoint = SignedPolicyWitnessRecoveryPolicyCheckpoint.sign(
        entry=second, issued_at_utc="2026-11-03T00:00:00Z",
        signer_key_id="policy-admin", private_key=private,
    )
    assert verify_policy_witness_recovery_policy_registry(
        [first, second], publisher_keyring={"policy-admin": record},
        trusted_checkpoint=checkpoint,
    )
    assert not verify_policy_witness_recovery_policy_registry(
        [first], publisher_keyring={"policy-admin": record},
        trusted_checkpoint=checkpoint,
    )


def test_policy_chain_rejects_mutation_and_wrong_checkpoint():
    private, record = keypair("policy-admin")
    original = entry(0, None, PolicyWitnessRecoveryPolicy(minimum_approvals=2), private)
    checkpoint = SignedPolicyWitnessRecoveryPolicyCheckpoint.sign(
        entry=original, issued_at_utc="2026-11-02T00:00:00Z",
        signer_key_id="policy-admin", private_key=private,
    )
    mutated = original.model_copy(update={
        "policy": PolicyWitnessRecoveryPolicy(minimum_approvals=1)
    })
    assert not verify_policy_witness_recovery_policy_registry(
        [mutated], publisher_keyring={"policy-admin": record},
        trusted_checkpoint=checkpoint,
    )
    other_private, _ = keypair("other")
    other = entry(0, None, PolicyWitnessRecoveryPolicy(minimum_approvals=2), other_private)
    assert not verify_policy_witness_recovery_policy_registry(
        [other], publisher_keyring={"policy-admin": record},
        trusted_checkpoint=checkpoint,
    )


def test_policy_signer_revocation_invalidates_registry():
    private, active = keypair("policy-admin")
    item = entry(0, None, PolicyWitnessRecoveryPolicy(minimum_approvals=2), private)
    checkpoint = SignedPolicyWitnessRecoveryPolicyCheckpoint.sign(
        entry=item, issued_at_utc="2026-11-02T00:00:00Z",
        signer_key_id="policy-admin", private_key=private,
    )
    revoked = active.model_copy(update={"revoked_at_utc": "2026-10-01T00:00:00.000000Z"})
    assert not verify_policy_witness_recovery_policy_registry(
        [item], publisher_keyring={"policy-admin": revoked},
        trusted_checkpoint=checkpoint,
    )
