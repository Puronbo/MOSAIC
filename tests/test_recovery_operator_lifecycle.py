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


def test_signed_portable_lifecycle_anchor_receipt_binds_checkpoint_and_trust_anchor():
    from mosaic.verification.recovery_operator_lifecycle import (
        SignedOperatorLifecycleTrustAnchorReceipt,
        verify_operator_lifecycle_trust_anchor_receipt,
    )
    authority_sk, authority = identity("receipt-authority")
    op_sk, operator = identity("receipt-operator")
    ring = {"receipt-authority": authority}
    checkpoint = SignedOperatorLifecycleCheckpoint.sign(
        registry_id="receipt-registry", sequence=31, previous_checkpoint_sha256="d" * 64,
        issued_at_utc="2026-11-24T08:00:00.000000Z",
        authority_key_id="receipt-authority", operator_keys=[operator],
        private_key=authority_sk)
    receipt = SignedOperatorLifecycleTrustAnchorReceipt.sign(
        checkpoint=checkpoint, issued_at_utc="2026-11-24T08:02:00.000000Z",
        private_key=authority_sk)
    assert verify_operator_lifecycle_trust_anchor_receipt(
        receipt, checkpoint, authority_keyring=ring,
        expected_registry_id="receipt-registry",
        expected_checkpoint_sha256=checkpoint.digest(), expected_sequence=31,
        authorization_time_utc="2026-11-24T08:03:00.000000Z")
    assert not verify_operator_lifecycle_trust_anchor_receipt(
        receipt, checkpoint, authority_keyring=ring,
        expected_registry_id="receipt-registry",
        expected_checkpoint_sha256="0" * 64,
        authorization_time_utc="2026-11-24T08:03:00.000000Z")
    assert not verify_operator_lifecycle_trust_anchor_receipt(
        receipt, checkpoint, authority_keyring=ring,
        expected_registry_id="other-registry",
        expected_checkpoint_sha256=checkpoint.digest())
    tampered = receipt.model_copy(update={"sequence": 32})
    assert not verify_operator_lifecycle_trust_anchor_receipt(
        tampered, checkpoint, authority_keyring=ring,
        expected_registry_id="receipt-registry",
        expected_checkpoint_sha256=checkpoint.digest())
    later = SignedOperatorLifecycleCheckpoint.sign(
        registry_id="receipt-registry", sequence=32,
        previous_checkpoint_sha256=checkpoint.digest(),
        issued_at_utc="2026-11-24T08:04:00.000000Z",
        authority_key_id="receipt-authority", operator_keys=[operator],
        private_key=authority_sk)
    assert not verify_operator_lifecycle_trust_anchor_receipt(
        receipt, later, authority_keyring=ring,
        expected_registry_id="receipt-registry",
        expected_checkpoint_sha256=later.digest())


def test_lifecycle_store_exports_only_current_head_and_restores_guardedly(tmp_path):
    from mosaic.verification.recovery_operator_lifecycle import (
        RecoveryOperatorLifecycleTrustAnchorStore,
        SignedOperatorLifecycleTrustAnchorReceipt,
    )
    authority_sk, authority = identity("restore-authority")
    _, operator = identity("restore-operator")
    ring = {"restore-authority": authority}
    checkpoint = SignedOperatorLifecycleCheckpoint.sign(
        registry_id="restore-registry", sequence=7,
        previous_checkpoint_sha256="e" * 64,
        issued_at_utc="2026-11-24T08:00:00.000000Z",
        authority_key_id="restore-authority", operator_keys=[operator],
        private_key=authority_sk)
    store = RecoveryOperatorLifecycleTrustAnchorStore(str(tmp_path / "source.sqlite3"))
    assert store.provision(
        registry_id=checkpoint.registry_id, sequence=checkpoint.sequence,
        checkpoint_sha256=checkpoint.digest(),
        updated_at_utc="2026-11-24T08:00:00.000000Z")
    receipt = store.export_receipt(
        checkpoint=checkpoint, issued_at_utc="2026-11-24T08:02:00.000000Z",
        private_key=authority_sk)
    assert isinstance(receipt, SignedOperatorLifecycleTrustAnchorReceipt)
    stale = checkpoint.model_copy(update={"sequence": 8})
    assert store.export_receipt(
        checkpoint=stale, issued_at_utc="2026-11-24T08:02:00.000000Z",
        private_key=authority_sk) is None

    restored = RecoveryOperatorLifecycleTrustAnchorStore(str(tmp_path / "restored.sqlite3"))
    kwargs = dict(
        authority_keyring=ring, expected_registry_id=checkpoint.registry_id,
        expected_checkpoint_sha256=checkpoint.digest(),
        expected_sequence=checkpoint.sequence,
        authorization_time_utc="2026-11-24T08:03:00.000000Z")
    assert not restored.restore_receipt(receipt, checkpoint, **kwargs)
    assert restored.read(checkpoint.registry_id) is None
    assert restored.restore_receipt(receipt, checkpoint, allow_initial=True, **kwargs)
    assert restored.read(checkpoint.registry_id)["checkpoint_sha256"] == checkpoint.digest()
    assert restored.restore_receipt(receipt, checkpoint, **kwargs)  # exact idempotent replay

    forged = receipt.model_copy(update={"sequence": 8})
    assert not restored.restore_receipt(forged, checkpoint, **kwargs)
    assert restored.read(checkpoint.registry_id)["checkpoint_sha256"] == checkpoint.digest()

    newer = RecoveryOperatorLifecycleTrustAnchorStore(str(tmp_path / "newer.sqlite3"))
    assert newer.provision(
        registry_id=checkpoint.registry_id, sequence=checkpoint.sequence + 1,
        checkpoint_sha256="f" * 64,
        updated_at_utc="2026-11-24T08:04:00.000000Z")
    assert not newer.restore_receipt(receipt, checkpoint, allow_initial=True, **kwargs)
    assert newer.read(checkpoint.registry_id)["checkpoint_sha256"] == "f" * 64


def test_lifecycle_receipt_restore_rejects_same_sequence_equivocation(tmp_path):
    from mosaic.verification.recovery_operator_lifecycle import (
        RecoveryOperatorLifecycleTrustAnchorStore,
    )
    authority_sk, authority = identity("equivocation-authority")
    _, operator = identity("equivocation-operator")
    ring = {"equivocation-authority": authority}
    first = SignedOperatorLifecycleCheckpoint.sign(
        registry_id="equivocation-registry", sequence=4,
        previous_checkpoint_sha256="a" * 64,
        issued_at_utc="2026-11-24T08:00:00.000000Z",
        authority_key_id="equivocation-authority", operator_keys=[operator],
        private_key=authority_sk)
    fork = SignedOperatorLifecycleCheckpoint.sign(
        registry_id="equivocation-registry", sequence=4,
        previous_checkpoint_sha256="a" * 64,
        issued_at_utc="2026-11-24T08:01:00.000000Z",
        authority_key_id="equivocation-authority", operator_keys=[operator],
        private_key=authority_sk)
    receipt = __import__(
        "mosaic.verification.recovery_operator_lifecycle",
        fromlist=["SignedOperatorLifecycleTrustAnchorReceipt"]
    ).SignedOperatorLifecycleTrustAnchorReceipt.sign(
        checkpoint=fork, issued_at_utc="2026-11-24T08:02:00.000000Z",
        private_key=authority_sk)
    store = RecoveryOperatorLifecycleTrustAnchorStore(str(tmp_path / "equivocation.sqlite3"))
    assert store.provision(
        registry_id=first.registry_id, sequence=first.sequence,
        checkpoint_sha256=first.digest(),
        updated_at_utc="2026-11-24T08:00:00.000000Z")
    assert not store.restore_receipt(
        receipt, fork, authority_keyring=ring,
        expected_registry_id=fork.registry_id,
        expected_checkpoint_sha256=fork.digest(), expected_sequence=fork.sequence,
        authorization_time_utc="2026-11-24T08:03:00.000000Z",
        allow_initial=True)
    assert store.read(first.registry_id)["checkpoint_sha256"] == first.digest()


def test_portable_lifecycle_checkpoint_chain_bundle_verifies_full_contiguous_suffix():
    from mosaic.verification.recovery_operator_lifecycle import (
        OperatorLifecycleCheckpointChainBundle,
        verify_operator_lifecycle_checkpoint_chain_bundle,
    )
    authority_sk, authority = identity("bundle-authority")
    _, operator = identity("bundle-operator")
    ring = {"bundle-authority": authority}
    first = SignedOperatorLifecycleCheckpoint.sign(
        registry_id="bundle-registry", sequence=50,
        previous_checkpoint_sha256="b" * 64,
        issued_at_utc="2026-11-24T08:00:00.000000Z",
        authority_key_id="bundle-authority", operator_keys=[operator],
        private_key=authority_sk)
    second = SignedOperatorLifecycleCheckpoint.sign(
        registry_id="bundle-registry", sequence=51,
        previous_checkpoint_sha256=first.digest(),
        issued_at_utc="2026-11-24T08:01:00.000000Z",
        authority_key_id="bundle-authority", operator_keys=[operator],
        private_key=authority_sk)
    third = SignedOperatorLifecycleCheckpoint.sign(
        registry_id="bundle-registry", sequence=52,
        previous_checkpoint_sha256=second.digest(),
        issued_at_utc="2026-11-24T08:02:00.000000Z",
        authority_key_id="bundle-authority", operator_keys=[operator],
        private_key=authority_sk)
    bundle = OperatorLifecycleCheckpointChainBundle.from_checkpoints(
        starting_checkpoint=first, checkpoints=[second, third])
    report = verify_operator_lifecycle_checkpoint_chain_bundle(
        bundle, first, authority_keyring=ring,
        expected_registry_id="bundle-registry",
        expected_starting_checkpoint_sha256=first.digest(),
        expected_ending_checkpoint_sha256=third.digest(),
        expected_ending_sequence=52,
        authorization_time_utc="2026-11-24T08:03:00.000000Z")
    assert report.accepted
    assert report.verified_transitions == 2
    assert report.ending_sequence == 52

    wrong_end = verify_operator_lifecycle_checkpoint_chain_bundle(
        bundle, first, authority_keyring=ring,
        expected_registry_id="bundle-registry",
        expected_starting_checkpoint_sha256=first.digest(),
        expected_ending_checkpoint_sha256="0" * 64,
        authorization_time_utc="2026-11-24T08:03:00.000000Z")
    assert not wrong_end.accepted
    assert "external_end_anchor_mismatch" in wrong_end.errors

    wrong_start = verify_operator_lifecycle_checkpoint_chain_bundle(
        bundle, first, authority_keyring=ring,
        expected_registry_id="bundle-registry",
        expected_starting_checkpoint_sha256="0" * 64,
        authorization_time_utc="2026-11-24T08:03:00.000000Z")
    assert not wrong_start.accepted
    assert "external_start_anchor_mismatch" in wrong_start.errors


def test_portable_lifecycle_checkpoint_chain_bundle_rejects_gap_fork_and_tampering():
    from mosaic.verification.recovery_operator_lifecycle import (
        OperatorLifecycleCheckpointChainBundle,
        verify_operator_lifecycle_checkpoint_chain_bundle,
    )
    authority_sk, authority = identity("bundle-negative-authority")
    _, operator = identity("bundle-negative-operator")
    ring = {"bundle-negative-authority": authority}
    first = SignedOperatorLifecycleCheckpoint.sign(
        registry_id="bundle-negative-registry", sequence=10,
        previous_checkpoint_sha256="c" * 64,
        issued_at_utc="2026-11-24T08:00:00.000000Z",
        authority_key_id="bundle-negative-authority", operator_keys=[operator],
        private_key=authority_sk)
    next_checkpoint = SignedOperatorLifecycleCheckpoint.sign(
        registry_id=first.registry_id, sequence=11,
        previous_checkpoint_sha256=first.digest(),
        issued_at_utc="2026-11-24T08:01:00.000000Z",
        authority_key_id="bundle-negative-authority", operator_keys=[operator],
        private_key=authority_sk)
    skipped = SignedOperatorLifecycleCheckpoint.sign(
        registry_id=first.registry_id, sequence=12,
        previous_checkpoint_sha256=first.digest(),
        issued_at_utc="2026-11-24T08:02:00.000000Z",
        authority_key_id="bundle-negative-authority", operator_keys=[operator],
        private_key=authority_sk)
    gap_bundle = OperatorLifecycleCheckpointChainBundle.from_checkpoints(
        starting_checkpoint=first, checkpoints=[skipped])
    gap = verify_operator_lifecycle_checkpoint_chain_bundle(
        gap_bundle, first, authority_keyring=ring,
        expected_registry_id=first.registry_id,
        expected_starting_checkpoint_sha256=first.digest(),
        authorization_time_utc="2026-11-24T08:03:00.000000Z")
    assert not gap.accepted
    assert any("sequence_not_contiguous" in item for item in gap.errors)

    fork = SignedOperatorLifecycleCheckpoint.sign(
        registry_id=first.registry_id, sequence=11,
        previous_checkpoint_sha256="d" * 64,
        issued_at_utc="2026-11-24T08:02:30.000000Z",
        authority_key_id="bundle-negative-authority", operator_keys=[operator],
        private_key=authority_sk)
    fork_bundle = OperatorLifecycleCheckpointChainBundle.from_checkpoints(
        starting_checkpoint=first, checkpoints=[fork])
    fork_report = verify_operator_lifecycle_checkpoint_chain_bundle(
        fork_bundle, first, authority_keyring=ring,
        expected_registry_id=first.registry_id,
        expected_starting_checkpoint_sha256=first.digest(),
        authorization_time_utc="2026-11-24T08:03:00.000000Z")
    assert not fork_report.accepted
    assert any("predecessor_digest_mismatch" in item for item in fork_report.errors)

    altered = next_checkpoint.model_copy(update={"sequence": 12})
    altered_bundle = OperatorLifecycleCheckpointChainBundle.from_checkpoints(
        starting_checkpoint=first, checkpoints=[altered])
    altered_report = verify_operator_lifecycle_checkpoint_chain_bundle(
        altered_bundle, first, authority_keyring=ring,
        expected_registry_id=first.registry_id,
        expected_starting_checkpoint_sha256=first.digest(),
        authorization_time_utc="2026-11-24T08:03:00.000000Z")
    assert not altered_report.accepted



def test_checkpoint_chain_restore_is_transactional_guarded_and_idempotent(tmp_path):
    from mosaic.verification.recovery_operator_lifecycle import (
        OperatorLifecycleCheckpointChainBundle,
        RecoveryOperatorLifecycleTrustAnchorStore,
    )
    authority_sk, authority = identity("chain-restore-authority")
    _, operator = identity("chain-restore-operator")
    ring = {"chain-restore-authority": authority}
    first = SignedOperatorLifecycleCheckpoint.sign(
        registry_id="chain-restore-registry", sequence=70,
        previous_checkpoint_sha256="a" * 64,
        issued_at_utc="2026-11-24T08:00:00.000000Z",
        authority_key_id="chain-restore-authority", operator_keys=[operator],
        private_key=authority_sk)
    second = SignedOperatorLifecycleCheckpoint.sign(
        registry_id=first.registry_id, sequence=71,
        previous_checkpoint_sha256=first.digest(),
        issued_at_utc="2026-11-24T08:01:00.000000Z",
        authority_key_id="chain-restore-authority", operator_keys=[operator],
        private_key=authority_sk)
    third = SignedOperatorLifecycleCheckpoint.sign(
        registry_id=first.registry_id, sequence=72,
        previous_checkpoint_sha256=second.digest(),
        issued_at_utc="2026-11-24T08:02:00.000000Z",
        authority_key_id="chain-restore-authority", operator_keys=[operator],
        private_key=authority_sk)
    bundle = OperatorLifecycleCheckpointChainBundle.from_checkpoints(
        starting_checkpoint=first, checkpoints=[second, third])
    kwargs = dict(
        authority_keyring=ring, expected_registry_id=first.registry_id,
        expected_starting_checkpoint_sha256=first.digest(),
        expected_ending_checkpoint_sha256=third.digest(),
        expected_ending_sequence=third.sequence,
        authorization_time_utc="2026-11-24T08:03:00.000000Z")

    empty = RecoveryOperatorLifecycleTrustAnchorStore(str(tmp_path / "empty-chain.sqlite3"))
    assert not empty.restore_checkpoint_chain_bundle(bundle, first, **kwargs)
    assert empty.read(first.registry_id) is None
    assert empty.restore_checkpoint_chain_bundle(bundle, first, allow_initial=True, **kwargs)
    assert empty.read(first.registry_id)["checkpoint_sha256"] == third.digest()
    assert empty.read(first.registry_id)["sequence"] == 72
    assert empty.restore_checkpoint_chain_bundle(bundle, first, **kwargs)

    # Existing stores advance only from the exact retained predecessor.
    advancing = RecoveryOperatorLifecycleTrustAnchorStore(str(tmp_path / "advance-chain.sqlite3"))
    assert advancing.provision(
        registry_id=first.registry_id, sequence=first.sequence,
        checkpoint_sha256=first.digest(), updated_at_utc=first.issued_at_utc)
    assert advancing.restore_checkpoint_chain_bundle(bundle, first, **kwargs)
    assert advancing.read(first.registry_id)["checkpoint_sha256"] == third.digest()

    stale = RecoveryOperatorLifecycleTrustAnchorStore(str(tmp_path / "stale-chain.sqlite3"))
    assert stale.provision(
        registry_id=first.registry_id, sequence=70,
        checkpoint_sha256="f" * 64, updated_at_utc=first.issued_at_utc)
    assert not stale.restore_checkpoint_chain_bundle(bundle, first, allow_initial=True, **kwargs)
    assert stale.read(first.registry_id)["checkpoint_sha256"] == "f" * 64

    newer = RecoveryOperatorLifecycleTrustAnchorStore(str(tmp_path / "newer-chain.sqlite3"))
    assert newer.provision(
        registry_id=first.registry_id, sequence=73,
        checkpoint_sha256="e" * 64, updated_at_utc=third.issued_at_utc)
    assert not newer.restore_checkpoint_chain_bundle(bundle, first, allow_initial=True, **kwargs)
    assert newer.read(first.registry_id)["sequence"] == 73
    assert newer.read(first.registry_id)["checkpoint_sha256"] == "e" * 64

    # A mathematically invalid but structurally well-formed suffix never mutates state.
    forged = third.model_copy(update={"previous_checkpoint_sha256": "0" * 64})
    invalid_bundle = OperatorLifecycleCheckpointChainBundle.from_checkpoints(
        starting_checkpoint=first, checkpoints=[second, forged])
    before = advancing.read(first.registry_id)
    invalid_kwargs = {**kwargs, "expected_ending_checkpoint_sha256": forged.digest()}
    assert not advancing.restore_checkpoint_chain_bundle(invalid_bundle, first, **invalid_kwargs)
    assert advancing.read(first.registry_id) == before



def test_checkpoint_chain_restore_receipt_is_signed_and_independently_verifiable(tmp_path):
    from mosaic.verification.recovery_operator_lifecycle import (
        OperatorLifecycleCheckpointChainBundle,
        RecoveryOperatorLifecycleTrustAnchorStore,
        verify_operator_lifecycle_checkpoint_chain_restore_receipt,
    )
    authority_sk, authority = identity("chain-receipt-authority")
    _, operator = identity("chain-receipt-operator")
    ring = {"chain-receipt-authority": authority}
    first = SignedOperatorLifecycleCheckpoint.sign(
        registry_id="chain-receipt-registry", sequence=80,
        previous_checkpoint_sha256="b" * 64,
        issued_at_utc="2026-11-24T08:00:00.000000Z",
        authority_key_id="chain-receipt-authority", operator_keys=[operator],
        private_key=authority_sk)
    second = SignedOperatorLifecycleCheckpoint.sign(
        registry_id=first.registry_id, sequence=81,
        previous_checkpoint_sha256=first.digest(),
        issued_at_utc="2026-11-24T08:01:00.000000Z",
        authority_key_id="chain-receipt-authority", operator_keys=[operator],
        private_key=authority_sk)
    third = SignedOperatorLifecycleCheckpoint.sign(
        registry_id=first.registry_id, sequence=82,
        previous_checkpoint_sha256=second.digest(),
        issued_at_utc="2026-11-24T08:02:00.000000Z",
        authority_key_id="chain-receipt-authority", operator_keys=[operator],
        private_key=authority_sk)
    bundle = OperatorLifecycleCheckpointChainBundle.from_checkpoints(
        starting_checkpoint=first, checkpoints=[second, third])
    store = RecoveryOperatorLifecycleTrustAnchorStore(str(tmp_path / "receipt-chain.sqlite3"))
    kwargs = dict(
        authority_keyring=ring, expected_registry_id=first.registry_id,
        expected_starting_checkpoint_sha256=first.digest(),
        expected_ending_checkpoint_sha256=third.digest(),
        expected_ending_sequence=third.sequence,
        authorization_time_utc="2026-11-24T08:04:00.000000Z")
    assert store.provision(
        registry_id=first.registry_id, sequence=first.sequence,
        checkpoint_sha256=first.digest(), updated_at_utc=first.issued_at_utc)
    receipt = store.restore_checkpoint_chain_bundle_with_receipt(
        bundle, first, issued_at_utc="2026-11-24T08:03:00.000000Z",
        receipt_private_key=authority_sk, **kwargs)
    assert receipt is not None
    assert store.read(first.registry_id)["checkpoint_sha256"] == third.digest()
    assert verify_operator_lifecycle_checkpoint_chain_restore_receipt(
        receipt, bundle, first, **kwargs)

    tampered = receipt.model_copy(update={"verified_transitions": 1})
    assert not verify_operator_lifecycle_checkpoint_chain_restore_receipt(
        tampered, bundle, first, **kwargs)
    other_bundle = OperatorLifecycleCheckpointChainBundle.from_checkpoints(
        starting_checkpoint=first, checkpoints=[second])
    assert not verify_operator_lifecycle_checkpoint_chain_restore_receipt(
        receipt, other_bundle, first,
        **{**kwargs, "expected_ending_checkpoint_sha256": second.digest(),
           "expected_ending_sequence": second.sequence})

    # A rejected import cannot produce a receipt or move the retained head.
    rejected_store = RecoveryOperatorLifecycleTrustAnchorStore(
        str(tmp_path / "rejected-receipt-chain.sqlite3"))
    assert rejected_store.provision(
        registry_id=first.registry_id, sequence=first.sequence,
        checkpoint_sha256="c" * 64, updated_at_utc=first.issued_at_utc)
    assert rejected_store.restore_checkpoint_chain_bundle_with_receipt(
        bundle, first, issued_at_utc="2026-11-24T08:03:00.000000Z",
        receipt_private_key=authority_sk, **kwargs) is None
    assert rejected_store.read(first.registry_id)["checkpoint_sha256"] == "c" * 64



def test_checkpoint_chain_restore_receipts_are_durably_logged_with_the_head(tmp_path):
    from mosaic.verification.recovery_operator_lifecycle import (
        OperatorLifecycleCheckpointChainBundle,
        RecoveryOperatorLifecycleTrustAnchorStore,
        SignedOperatorLifecycleCheckpointChainRestoreReceipt,
        verify_operator_lifecycle_checkpoint_chain_restore_receipt,
        verify_operator_lifecycle_restore_ledger,
    )
    authority_sk, authority = identity("durable-chain-log-authority")
    _, operator = identity("durable-chain-log-operator")
    ring = {"durable-chain-log-authority": authority}
    first = SignedOperatorLifecycleCheckpoint.sign(
        registry_id="durable-chain-log-registry", sequence=90,
        previous_checkpoint_sha256="d" * 64,
        issued_at_utc="2026-11-24T08:00:00.000000Z",
        authority_key_id="durable-chain-log-authority", operator_keys=[operator],
        private_key=authority_sk)
    second = SignedOperatorLifecycleCheckpoint.sign(
        registry_id=first.registry_id, sequence=91,
        previous_checkpoint_sha256=first.digest(),
        issued_at_utc="2026-11-24T08:01:00.000000Z",
        authority_key_id="durable-chain-log-authority", operator_keys=[operator],
        private_key=authority_sk)
    bundle = OperatorLifecycleCheckpointChainBundle.from_checkpoints(
        starting_checkpoint=first, checkpoints=[second])
    store = RecoveryOperatorLifecycleTrustAnchorStore(str(tmp_path / "durable-log.sqlite3"))
    assert store.provision(
        registry_id=first.registry_id, sequence=first.sequence,
        checkpoint_sha256=first.digest(), updated_at_utc=first.issued_at_utc)
    kwargs = dict(
        authority_keyring=ring, expected_registry_id=first.registry_id,
        expected_starting_checkpoint_sha256=first.digest(),
        expected_ending_checkpoint_sha256=second.digest(),
        expected_ending_sequence=second.sequence,
        authorization_time_utc="2026-11-24T08:04:00.000000Z")
    receipt = store.restore_checkpoint_chain_bundle_with_receipt(
        bundle, first, issued_at_utc="2026-11-24T08:02:00.000000Z",
        receipt_private_key=authority_sk, **kwargs)
    assert isinstance(receipt, SignedOperatorLifecycleCheckpointChainRestoreReceipt)
    records = store.read_checkpoint_chain_restore_receipts(first.registry_id)
    assert len(records) == 1
    assert records[0]["bundle_sha256"] == bundle.digest()
    assert records[0]["ending_checkpoint_sha256"] == second.digest()
    persisted = SignedOperatorLifecycleCheckpointChainRestoreReceipt.model_validate(records[0])
    assert verify_operator_lifecycle_checkpoint_chain_restore_receipt(
        persisted, bundle, first, **kwargs)

    # An exact replay with a distinct signed receipt is retained as a second event.
    replay = store.restore_checkpoint_chain_bundle_with_receipt(
        bundle, first, issued_at_utc="2026-11-24T08:03:00.000000Z",
        receipt_private_key=authority_sk, **kwargs)
    assert replay is not None
    assert len(store.read_checkpoint_chain_restore_receipts(first.registry_id)) == 2

    # Rejected imports cannot append an event or alter the retained head.
    rejected = store.restore_checkpoint_chain_bundle_with_receipt(
        bundle, first, issued_at_utc="2026-11-24T08:03:30.000000Z",
        receipt_private_key=authority_sk,
        **{**kwargs, "expected_ending_checkpoint_sha256": "0" * 64})
    assert rejected is None
    assert len(store.read_checkpoint_chain_restore_receipts(first.registry_id)) == 2
    assert store.read(first.registry_id)["checkpoint_sha256"] == second.digest()

    ledger = store.read_checkpoint_chain_restore_ledger(first.registry_id)
    assert [item["event_sequence"] for item in ledger] == [1, 2]
    assert ledger[0]["previous_receipt_sha256"] is None
    assert ledger[1]["previous_receipt_sha256"] == ledger[0]["ledger_entry_sha256"]
    verified = verify_operator_lifecycle_restore_ledger(
        ledger, expected_registry_id=first.registry_id,
        expected_event_sequence=2,
        expected_ledger_entry_sha256=ledger[-1]["ledger_entry_sha256"],
        expected_checkpoint_sha256=second.digest(), authority_keyring=ring)
    assert verified.accepted

    # A caller-held head detects truncation; internal hashes detect edits and reorder.
    assert not verify_operator_lifecycle_restore_ledger(
        ledger[:1], expected_registry_id=first.registry_id,
        expected_event_sequence=2,
        expected_ledger_entry_sha256=ledger[-1]["ledger_entry_sha256"],
        expected_checkpoint_sha256=second.digest(), authority_keyring=ring).accepted
    tampered = [dict(item) for item in ledger]
    tampered[0]["receipt_sha256"] = "0" * 64
    assert not verify_operator_lifecycle_restore_ledger(
        tampered, expected_registry_id=first.registry_id,
        expected_event_sequence=2,
        expected_ledger_entry_sha256=ledger[-1]["ledger_entry_sha256"],
        authority_keyring=ring).accepted
    assert not verify_operator_lifecycle_restore_ledger(
        list(reversed(ledger)), expected_registry_id=first.registry_id,
        expected_event_sequence=2,
        expected_ledger_entry_sha256=ledger[-1]["ledger_entry_sha256"],
        authority_keyring=ring).accepted


def test_portable_restore_ledger_head_is_signed_and_externally_pinned(tmp_path):
    from mosaic.verification.recovery_operator_lifecycle import (
        OperatorLifecycleCheckpointChainBundle,
        RecoveryOperatorLifecycleTrustAnchorStore,
        verify_operator_lifecycle_restore_ledger_head,
    )
    authority_sk, authority = identity("portable-ledger-receipt-authority")
    ledger_sk, ledger_authority = identity("portable-ledger-head-authority")
    _, operator = identity("portable-ledger-operator")
    receipt_ring = {"portable-ledger-receipt-authority": authority}
    ledger_ring = {"portable-ledger-head-authority": ledger_authority}
    first = SignedOperatorLifecycleCheckpoint.sign(
        registry_id="portable-ledger-registry", sequence=100,
        previous_checkpoint_sha256="a" * 64,
        issued_at_utc="2026-11-24T08:00:00.000000Z",
        authority_key_id="portable-ledger-receipt-authority",
        operator_keys=[operator], private_key=authority_sk)
    second = SignedOperatorLifecycleCheckpoint.sign(
        registry_id=first.registry_id, sequence=101,
        previous_checkpoint_sha256=first.digest(),
        issued_at_utc="2026-11-24T08:01:00.000000Z",
        authority_key_id="portable-ledger-receipt-authority",
        operator_keys=[operator], private_key=authority_sk)
    bundle = OperatorLifecycleCheckpointChainBundle.from_checkpoints(
        starting_checkpoint=first, checkpoints=[second])
    store = RecoveryOperatorLifecycleTrustAnchorStore(str(tmp_path / "portable-head.sqlite3"))
    assert store.export_restore_ledger_head(
        registry_id=first.registry_id,
        ledger_authority_key_id="portable-ledger-head-authority",
        issued_at_utc="2026-11-24T08:02:00.000000Z",
        private_key=ledger_sk, receipt_authority_keyring=receipt_ring) is None
    assert store.provision(
        registry_id=first.registry_id, sequence=first.sequence,
        checkpoint_sha256=first.digest(), updated_at_utc=first.issued_at_utc)
    receipt = store.restore_checkpoint_chain_bundle_with_receipt(
        bundle, first, authority_keyring=receipt_ring,
        expected_registry_id=first.registry_id,
        expected_starting_checkpoint_sha256=first.digest(),
        expected_ending_checkpoint_sha256=second.digest(),
        expected_ending_sequence=second.sequence,
        issued_at_utc="2026-11-24T08:02:00.000000Z",
        receipt_private_key=authority_sk,
        authorization_time_utc="2026-11-24T08:03:00.000000Z")
    assert receipt is not None
    head = store.export_restore_ledger_head(
        registry_id=first.registry_id,
        ledger_authority_key_id="portable-ledger-head-authority",
        issued_at_utc="2026-11-24T08:04:00.000000Z",
        private_key=ledger_sk, receipt_authority_keyring=receipt_ring)
    assert head is not None
    ledger = store.read_checkpoint_chain_restore_ledger(first.registry_id)
    terminal = ledger[-1]
    kwargs = dict(
        authority_keyring=ledger_ring,
        expected_registry_id=first.registry_id,
        expected_event_sequence=terminal["event_sequence"],
        expected_ledger_entry_sha256=terminal["ledger_entry_sha256"],
        expected_receipt_sha256=terminal["receipt_sha256"],
        authorization_time_utc="2026-11-24T08:05:00.000000Z")
    assert verify_operator_lifecycle_restore_ledger_head(head, **kwargs)
    assert not verify_operator_lifecycle_restore_ledger_head(
        head, **{**kwargs, "expected_event_sequence": 2})
    assert not verify_operator_lifecycle_restore_ledger_head(
        head, **{**kwargs, "expected_ledger_entry_sha256": "0" * 64})
    assert not verify_operator_lifecycle_restore_ledger_head(
        head, **{**kwargs, "authority_keyring": receipt_ring})
    altered = head.model_copy(update={"receipt_sha256": "0" * 64})
    assert not verify_operator_lifecycle_restore_ledger_head(altered, **kwargs)
    assert store.export_restore_ledger_head(
        registry_id=first.registry_id,
        ledger_authority_key_id="portable-ledger-head-authority",
        issued_at_utc="2026-11-24T08:06:00.000000Z",
        private_key=ledger_sk, receipt_authority_keyring={}) is None
