import copy

from mosaic.verification.recovery_operator_lifecycle import (
    SignedOperatorLifecycleCheckpoint, verify_operator_lifecycle_checkpoint,
)
from test_recovery_policy_checkpoint_rebootstrap import identity


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
