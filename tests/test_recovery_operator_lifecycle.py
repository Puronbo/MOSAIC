import copy

from mosaic.verification.recovery_operator_lifecycle import (
    SignedOperatorLifecycleCheckpoint, verify_operator_lifecycle_checkpoint,
)
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
from mosaic.verification.policy_governance import PolicyPublisherKey


def identity(name):
    private = Ed25519PrivateKey.generate()
    raw = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return raw, PolicyPublisherKey(
        key_id=name, public_key_b64=base64.b64encode(public).decode(),
        activated_at_utc="2026-01-01T00:00:00.000000Z")


def test_signed_operator_lifecycle_checkpoint_detects_tampering_and_rollback():
    authority_sk, authority = identity("lifecycle-authority")
    operator_sk, operator = identity("operator-1")
    second_sk, second = identity("operator-2")
    first = SignedOperatorLifecycleCheckpoint.sign(
        registry_id="operators", sequence=0, previous_checkpoint_sha256=None,
        issued_at_utc="2026-11-24T08:00:00Z", authority_key_id="lifecycle-authority",
        operator_keys=[operator, second], private_key=authority_sk)
    ring = {"lifecycle-authority": authority}
    assert verify_operator_lifecycle_checkpoint(
        first, authority_keyring=ring, expected_registry_id="operators",
        expected_sequence=0, expected_previous_sha256=None,
        expected_checkpoint_sha256=first.digest(),
        authorization_time_utc="2026-11-24T08:01:00.000000Z")
    assert not verify_operator_lifecycle_checkpoint(
        first, authority_keyring=ring, expected_registry_id="operators",
        expected_checkpoint_sha256="0" * 64)
    assert not verify_operator_lifecycle_checkpoint(
        first, authority_keyring=ring, expected_registry_id="different")
    changed = first.model_copy(update={"operator_keys": (operator,)})
    assert not verify_operator_lifecycle_checkpoint(
        changed, authority_keyring=ring, expected_registry_id="operators")
    assert not verify_operator_lifecycle_checkpoint(
        first, authority_keyring=ring, expected_registry_id="operators",
        authorization_time_utc="2026-11-24T07:59:59.000000Z")

    revoked = operator.model_copy(update={"revoked_at_utc": "2026-11-24T08:30:00.000000Z"})
    second_checkpoint = SignedOperatorLifecycleCheckpoint.sign(
        registry_id="operators", sequence=1,
        previous_checkpoint_sha256=first.digest(),
        issued_at_utc="2026-11-24T09:00:00.000000Z",
        authority_key_id="lifecycle-authority",
        operator_keys=[revoked, second], private_key=authority_sk)
    assert verify_operator_lifecycle_checkpoint(
        second_checkpoint, authority_keyring=ring, expected_registry_id="operators",
        expected_sequence=1, expected_previous_sha256=first.digest(),
        expected_checkpoint_sha256=second_checkpoint.digest(),
        authorization_time_utc="2026-11-24T09:01:00.000000Z")
    assert not verify_operator_lifecycle_checkpoint(
        second_checkpoint, authority_keyring=ring, expected_registry_id="operators",
        expected_sequence=0, expected_previous_sha256=None)


def test_lifecycle_checkpoint_advance_requires_contiguous_pinned_chain():
    from mosaic.verification.recovery_operator_lifecycle import (
        verify_operator_lifecycle_checkpoint_advance,
    )
    authority_sk, authority = identity("advance-authority")
    op_sk, operator = identity("advance-operator")
    ring = {"advance-authority": authority}
    first = SignedOperatorLifecycleCheckpoint.sign(
        registry_id="operators", sequence=12, previous_checkpoint_sha256="a" * 64,
        issued_at_utc="2026-11-24T08:00:00.000000Z",
        authority_key_id="advance-authority", operator_keys=[operator],
        private_key=authority_sk)
    second = SignedOperatorLifecycleCheckpoint.sign(
        registry_id="operators", sequence=13, previous_checkpoint_sha256=first.digest(),
        issued_at_utc="2026-11-24T08:05:00.000000Z",
        authority_key_id="advance-authority", operator_keys=[operator],
        private_key=authority_sk)
    accepted = verify_operator_lifecycle_checkpoint_advance(
        first, second, authority_keyring=ring,
        expected_previous_sha256=first.digest(), expected_registry_id="operators",
        authorization_time_utc="2026-11-24T08:06:00.000000Z")
    assert accepted.accepted
    assert accepted.errors == ()

    skipped = SignedOperatorLifecycleCheckpoint.sign(
        registry_id="operators", sequence=14, previous_checkpoint_sha256=first.digest(),
        issued_at_utc="2026-11-24T08:07:00.000000Z",
        authority_key_id="advance-authority", operator_keys=[operator],
        private_key=authority_sk)
    rejected = verify_operator_lifecycle_checkpoint_advance(
        first, skipped, authority_keyring=ring,
        expected_previous_sha256=first.digest(), expected_registry_id="operators",
        authorization_time_utc="2026-11-24T08:08:00.000000Z")
    assert not rejected.accepted
    assert "sequence_not_contiguous" in rejected.errors

    fork = SignedOperatorLifecycleCheckpoint.sign(
        registry_id="operators", sequence=13, previous_checkpoint_sha256="b" * 64,
        issued_at_utc="2026-11-24T08:09:00.000000Z",
        authority_key_id="advance-authority", operator_keys=[operator],
        private_key=authority_sk)
    rejected_fork = verify_operator_lifecycle_checkpoint_advance(
        first, fork, authority_keyring=ring,
        expected_previous_sha256=first.digest(), expected_registry_id="operators",
        authorization_time_utc="2026-11-24T08:10:00.000000Z")
    assert not rejected_fork.accepted
    assert "predecessor_digest_mismatch" in rejected_fork.errors

    assert not verify_operator_lifecycle_checkpoint_advance(
        first, second, authority_keyring=ring,
        expected_previous_sha256="0" * 64, expected_registry_id="operators",
        authorization_time_utc="2026-11-24T08:06:00.000000Z").accepted


def test_durable_lifecycle_anchor_store_advances_atomically_and_rejects_replay(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from mosaic.verification.recovery_operator_lifecycle import RecoveryOperatorLifecycleTrustAnchorStore
    authority_sk, authority = identity("durable-authority")
    op_sk, operator = identity("durable-operator")
    ring = {"durable-authority": authority}
    first = SignedOperatorLifecycleCheckpoint.sign(
        registry_id="durable-operators", sequence=20, previous_checkpoint_sha256="c" * 64,
        issued_at_utc="2026-11-24T08:00:00.000000Z",
        authority_key_id="durable-authority", operator_keys=[operator], private_key=authority_sk)
    candidate_a = SignedOperatorLifecycleCheckpoint.sign(
        registry_id="durable-operators", sequence=21, previous_checkpoint_sha256=first.digest(),
        issued_at_utc="2026-11-24T08:05:00.000000Z",
        authority_key_id="durable-authority", operator_keys=[operator], private_key=authority_sk)
    candidate_b = SignedOperatorLifecycleCheckpoint.sign(
        registry_id="durable-operators", sequence=21, previous_checkpoint_sha256=first.digest(),
        issued_at_utc="2026-11-24T08:06:00.000000Z",
        authority_key_id="durable-authority", operator_keys=[operator], private_key=authority_sk)
    store = RecoveryOperatorLifecycleTrustAnchorStore(str(tmp_path / "lifecycle-anchor.sqlite3"))
    assert store.provision(registry_id=first.registry_id, sequence=first.sequence,
                           checkpoint_sha256=first.digest(),
                           updated_at_utc="2026-11-24T08:00:00.000000Z")
    assert not store.provision(registry_id=first.registry_id, sequence=first.sequence,
                               checkpoint_sha256=first.digest(),
                               updated_at_utc="2026-11-24T08:00:00.000000Z")
    assert not store.advance(first, candidate_a, authority_keyring=ring,
                             expected_current_sha256="0" * 64,
                             authorization_time_utc="2026-11-24T08:10:00.000000Z").accepted
    assert store.read(first.registry_id)["checkpoint_sha256"] == first.digest()

    barrier = Barrier(2)
    def attempt(candidate):
        local_store = RecoveryOperatorLifecycleTrustAnchorStore(str(tmp_path / "lifecycle-anchor.sqlite3"))
        barrier.wait()
        return local_store.advance(
            first, candidate, authority_keyring=ring,
            expected_current_sha256=first.digest(),
            authorization_time_utc="2026-11-24T08:10:00.000000Z").accepted
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(attempt, [candidate_a, candidate_b]))
    assert sum(outcomes) == 1
    retained = store.read(first.registry_id)
    assert retained["sequence"] == 21
    assert retained["checkpoint_sha256"] in {candidate_a.digest(), candidate_b.digest()}
    winner = candidate_a if retained["checkpoint_sha256"] == candidate_a.digest() else candidate_b
    loser = candidate_b if winner is candidate_a else candidate_a
    assert not store.advance(first, loser, authority_keyring=ring,
                             expected_current_sha256=first.digest(),
                             authorization_time_utc="2026-11-24T08:10:00.000000Z").accepted
    assert store.read(first.registry_id)["checkpoint_sha256"] == winner.digest()
