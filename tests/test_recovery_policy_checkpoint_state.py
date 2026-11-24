from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
import base64

from mosaic.verification.policy_governance import PolicyPublisherKey
from mosaic.verification.policy_witness_recovery_governance import PolicyWitnessRecoveryPolicy
from mosaic.verification.policy_witness_recovery_policy_registry import (
    SignedPolicyWitnessRecoveryPolicyCheckpoint,
    SignedPolicyWitnessRecoveryPolicyEntry,
)
from mosaic.verification.recovery_policy_checkpoint_state import RecoveryPolicyCheckpointStore


def _identity(name):
    private = Ed25519PrivateKey.generate()
    raw = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    key = PolicyPublisherKey(
        key_id=name, public_key_b64=base64.b64encode(public).decode(),
        activated_at_utc="2026-01-01T00:00:00.000000Z",
    )
    return raw, key


def _entry(seq, previous, private):
    return SignedPolicyWitnessRecoveryPolicyEntry.sign(
        registry_id="recovery-policy", sequence=seq,
        previous_entry_sha256=previous,
        policy=PolicyWitnessRecoveryPolicy(minimum_approvals=seq + 1),
        published_at_utc=f"2026-11-{seq + 1:02d}T00:00:00.000000Z",
        publisher_key_id="publisher", private_key=private,
    )


def _checkpoint(entry, private):
    return SignedPolicyWitnessRecoveryPolicyCheckpoint.sign(
        entry=entry, issued_at_utc="2026-11-24T06:00:00Z",
        signer_key_id="checkpoint", private_key=private,
    )


def test_checkpoint_store_pins_advances_and_survives_restart(tmp_path):
    publisher_private, publisher = _identity("publisher")
    checkpoint_private, checkpoint_key = _identity("checkpoint")
    first = _entry(0, None, publisher_private)
    second = _entry(1, first.digest(), publisher_private)
    cp0, cp1 = _checkpoint(first, checkpoint_private), _checkpoint(second, checkpoint_private)
    store = RecoveryPolicyCheckpointStore(tmp_path / "policy-state.sqlite3")
    assert store.pin_checkpoint([first], checkpoint=cp0, publisher_keyring={"publisher": publisher},
                                checkpoint_keyring={"checkpoint": checkpoint_key})
    assert store.matches_trusted_checkpoint(cp0)
    assert store.pin_checkpoint([first, second], checkpoint=cp1, publisher_keyring={"publisher": publisher},
                                checkpoint_keyring={"checkpoint": checkpoint_key})
    reopened = RecoveryPolicyCheckpointStore(tmp_path / "policy-state.sqlite3")
    assert reopened.matches_trusted_checkpoint(cp1)
    assert not reopened.matches_trusted_checkpoint(cp0)


def test_checkpoint_store_rejects_rollback_and_records_incident(tmp_path):
    publisher_private, publisher = _identity("publisher")
    checkpoint_private, checkpoint_key = _identity("checkpoint")
    first = _entry(0, None, publisher_private)
    second = _entry(1, first.digest(), publisher_private)
    cp0, cp1 = _checkpoint(first, checkpoint_private), _checkpoint(second, checkpoint_private)
    store = RecoveryPolicyCheckpointStore(tmp_path / "rollback.sqlite3")
    assert store.pin_checkpoint([first, second], checkpoint=cp1, publisher_keyring={"publisher": publisher},
                                checkpoint_keyring={"checkpoint": checkpoint_key})
    assert not store.pin_checkpoint([first], checkpoint=cp0, publisher_keyring={"publisher": publisher},
                                    checkpoint_keyring={"checkpoint": checkpoint_key})
    assert store.matches_trusted_checkpoint(cp1)
    assert store.incidents("recovery-policy")[0]["reason"] == "rollback_attempt"


def test_checkpoint_store_quarantines_same_sequence_equivocation(tmp_path):
    publisher_private, publisher = _identity("publisher")
    checkpoint_private, checkpoint_key = _identity("checkpoint")
    first = _entry(0, None, publisher_private)
    conflicting = SignedPolicyWitnessRecoveryPolicyEntry.sign(
        registry_id="recovery-policy", sequence=0, previous_entry_sha256=None,
        policy=PolicyWitnessRecoveryPolicy(minimum_approvals=5),
        published_at_utc="2026-11-01T00:00:00Z",
        publisher_key_id="publisher", private_key=publisher_private,
    )
    cp0, fork = _checkpoint(first, checkpoint_private), _checkpoint(conflicting, checkpoint_private)
    store = RecoveryPolicyCheckpointStore(tmp_path / "equivocation.sqlite3")
    assert store.pin_checkpoint([first], checkpoint=cp0, publisher_keyring={"publisher": publisher},
                                checkpoint_keyring={"checkpoint": checkpoint_key})
    assert not store.pin_checkpoint([conflicting], checkpoint=fork, publisher_keyring={"publisher": publisher},
                                    checkpoint_keyring={"checkpoint": checkpoint_key})
    assert store.is_quarantined("recovery-policy")
    assert not store.matches_trusted_checkpoint(cp0)
