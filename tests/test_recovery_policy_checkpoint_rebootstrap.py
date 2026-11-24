import base64
import hashlib
import sqlite3

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from mosaic.verification.lean_runner_signature import _canonical
from mosaic.verification.policy_governance import PolicyPublisherKey
from mosaic.verification.policy_witness_recovery_governance import PolicyWitnessRecoveryPolicy
from mosaic.verification.policy_witness_recovery_policy_registry import (
    SignedPolicyWitnessRecoveryPolicyCheckpoint, SignedPolicyWitnessRecoveryPolicyEntry,
)
from mosaic.verification.recovery_policy_checkpoint_state import RecoveryPolicyCheckpointStore
from mosaic.verification.recovery_policy_checkpoint_recovery import (
    RecoveryPolicyCheckpointRebootstrapApproval,
    RecoveryPolicyCheckpointRebootstrapIntent,
    RecoveryPolicyCheckpointRebootstrapPolicy,
    rebootstrap_recovery_policy_checkpoint_store,
)


def identity(name):
    private = Ed25519PrivateKey.generate()
    raw = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return raw, PolicyPublisherKey(key_id=name, public_key_b64=base64.b64encode(public).decode(),
        activated_at_utc="2026-01-01T00:00:00.000000Z")


def entry(private, policy_value, sequence=0, previous=None):
    return SignedPolicyWitnessRecoveryPolicyEntry.sign(
        registry_id="registry", sequence=sequence, previous_entry_sha256=previous,
        policy=PolicyWitnessRecoveryPolicy(minimum_approvals=policy_value),
        published_at_utc=f"2026-11-{sequence + 1:02d}T00:00:00.000000Z",
        publisher_key_id="publisher", private_key=private)


def checkpoint(e, private):
    return SignedPolicyWitnessRecoveryPolicyCheckpoint.sign(
        entry=e, issued_at_utc="2026-11-24T06:00:00Z",
        signer_key_id="checkpoint", private_key=private)


def test_threshold_rebootstrap_preserves_incidents_and_starts_new_epoch(tmp_path):
    pub_sk, pub = identity("publisher")
    cp_sk, cp_key = identity("checkpoint")
    op1_sk, op1 = identity("operator-1")
    op2_sk, op2 = identity("operator-2")
    first = entry(pub_sk, 1)
    fork = entry(pub_sk, 3)
    old_cp, new_cp = checkpoint(first, cp_sk), checkpoint(fork, cp_sk)
    db_path = tmp_path / "rebootstrap.sqlite3"
    store = RecoveryPolicyCheckpointStore(db_path)
    assert store.pin_checkpoint([first], checkpoint=old_cp, publisher_keyring={"publisher": pub},
                                checkpoint_keyring={"checkpoint": cp_key})
    assert not store.pin_checkpoint([fork], checkpoint=new_cp, publisher_keyring={"publisher": pub},
                                    checkpoint_keyring={"checkpoint": cp_key})
    incidents_before = store.incidents("registry")
    assert store.is_quarantined("registry")

    def cp_hash(value):
        return hashlib.sha256(value.model_dump_json().encode()).hexdigest()

    intent = RecoveryPolicyCheckpointRebootstrapIntent.sign(
        registry_id="registry", retained_checkpoint_sha256=cp_hash(old_cp),
        incident_history_sha256=hashlib.sha256(_canonical(incidents_before)).hexdigest(),
        selected_checkpoint_sha256=cp_hash(new_cp),
        evidence_sha256="a" * 64,
        reason="Independent investigation selected the alternate signed registry history.",
        operator_key_id="operator-1", approved_at_utc="2026-11-24T07:00:00Z",
        private_key=op1_sk)
    approval = RecoveryPolicyCheckpointRebootstrapApproval.sign(
        intent=intent, operator_key_id="operator-2",
        approved_at_utc="2026-11-24T07:01:00Z", private_key=op2_sk)
    assert rebootstrap_recovery_policy_checkpoint_store(
        store, [fork], checkpoint=new_cp, publisher_keyring={"publisher": pub},
        checkpoint_keyring={"checkpoint": cp_key}, intent=intent, approvals=[approval],
        policy=RecoveryPolicyCheckpointRebootstrapPolicy(minimum_approvals=2),
        operator_keyring={"operator-1": op1, "operator-2": op2})
    assert not store.is_quarantined("registry")
    assert store.matches_trusted_checkpoint(new_cp)
    assert store.incidents("registry") == incidents_before

    extended = entry(pub_sk, 4, sequence=1, previous=fork.digest())
    extended_cp = checkpoint(extended, cp_sk)
    assert store.pin_checkpoint([fork, extended], checkpoint=extended_cp,
                                publisher_keyring={"publisher": pub},
                                checkpoint_keyring={"checkpoint": cp_key})
    reopened = RecoveryPolicyCheckpointStore(db_path)
    assert reopened.matches_trusted_checkpoint(extended_cp)
    with sqlite3.connect(db_path) as db:
        assert db.execute("SELECT COUNT(*) FROM recovery_policy_rebootstrap_audit").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM recovery_policy_epoch_entries WHERE registry_id='registry' AND epoch=0").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM recovery_policy_epoch_entries WHERE registry_id='registry' AND epoch=1").fetchone()[0] == 2


def test_rebootstrap_rejects_insufficient_approvals_and_stale_incident_digest(tmp_path):
    pub_sk, pub = identity("publisher")
    cp_sk, cp_key = identity("checkpoint")
    op1_sk, op1 = identity("operator-1")
    op2_sk, op2 = identity("operator-2")
    first, fork = entry(pub_sk, 1), entry(pub_sk, 3)
    old_cp, new_cp = checkpoint(first, cp_sk), checkpoint(fork, cp_sk)
    store = RecoveryPolicyCheckpointStore(tmp_path / "reject.sqlite3")
    assert store.pin_checkpoint([first], checkpoint=old_cp, publisher_keyring={"publisher": pub},
                                checkpoint_keyring={"checkpoint": cp_key})
    assert not store.pin_checkpoint([fork], checkpoint=new_cp, publisher_keyring={"publisher": pub},
                                    checkpoint_keyring={"checkpoint": cp_key})
    incidents = store.incidents("registry")
    intent = RecoveryPolicyCheckpointRebootstrapIntent.sign(
        registry_id="registry",
        retained_checkpoint_sha256=hashlib.sha256(old_cp.model_dump_json().encode()).hexdigest(),
        incident_history_sha256=hashlib.sha256(_canonical(incidents)).hexdigest(),
        selected_checkpoint_sha256=hashlib.sha256(new_cp.model_dump_json().encode()).hexdigest(),
        evidence_sha256="b" * 64,
        reason="A separately reviewed incident package supports this selected registry history.",
        operator_key_id="operator-1", approved_at_utc="2026-11-24T07:00:00Z",
        private_key=op1_sk)
    assert not rebootstrap_recovery_policy_checkpoint_store(
        store, [fork], checkpoint=new_cp, publisher_keyring={"publisher": pub},
        checkpoint_keyring={"checkpoint": cp_key}, intent=intent, approvals=[],
        policy=RecoveryPolicyCheckpointRebootstrapPolicy(minimum_approvals=2),
        operator_keyring={"operator-1": op1, "operator-2": op2})
    approval = RecoveryPolicyCheckpointRebootstrapApproval.sign(
        intent=intent, operator_key_id="operator-2",
        approved_at_utc="2026-11-24T07:01:00Z", private_key=op2_sk)
    assert not rebootstrap_recovery_policy_checkpoint_store(
        store, [fork], checkpoint=new_cp, publisher_keyring={"publisher": pub},
        checkpoint_keyring={"checkpoint": cp_key}, intent=intent, approvals=[approval],
        policy=RecoveryPolicyCheckpointRebootstrapPolicy(minimum_approvals=2),
        operator_keyring={"operator-1": op1, "operator-2": op2})
    assert store.is_quarantined("registry")
