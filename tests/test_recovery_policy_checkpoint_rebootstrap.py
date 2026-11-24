import base64
import hashlib
import copy
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
    export_rebootstrap_audit,
    verify_rebootstrap_audit_export,
    verify_rebootstrap_audit_export_report,
    report_rebootstrap_proposal_conflicts,
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
    # Preserve an independently restorable pre-rebootstrap database image.
    rollback_image = tmp_path / "pre-rebootstrap-backup.sqlite3"
    with sqlite3.connect(db_path) as source, sqlite3.connect(rollback_image) as backup:
        source.backup(backup)

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
    with sqlite3.connect(db_path) as db:
        db.execute("""
            CREATE TRIGGER fail_rebootstrap_audit BEFORE INSERT ON recovery_policy_rebootstrap_audit
            BEGIN SELECT RAISE(ABORT, 'simulated interrupted audit persistence'); END
        """)
    import pytest
    with pytest.raises(sqlite3.IntegrityError):
        rebootstrap_recovery_policy_checkpoint_store(
            store, [fork], checkpoint=new_cp, publisher_keyring={"publisher": pub},
            checkpoint_keyring={"checkpoint": cp_key}, intent=intent, approvals=[approval],
            policy=RecoveryPolicyCheckpointRebootstrapPolicy(minimum_approvals=2),
            operator_keyring={"operator-1": op1, "operator-2": op2})
    assert store.is_quarantined("registry")
    with sqlite3.connect(db_path) as db:
        assert db.execute("SELECT COUNT(*) FROM recovery_policy_epoch_entries WHERE registry_id='registry' AND epoch=1").fetchone()[0] == 0
        db.execute("DROP TRIGGER fail_rebootstrap_audit")
    assert rebootstrap_recovery_policy_checkpoint_store(
        store, [fork], checkpoint=new_cp, publisher_keyring={"publisher": pub},
        checkpoint_keyring={"checkpoint": cp_key}, intent=intent, approvals=[approval],
        policy=RecoveryPolicyCheckpointRebootstrapPolicy(minimum_approvals=2),
        operator_keyring={"operator-1": op1, "operator-2": op2})
    assert not store.is_quarantined("registry")
    assert store.matches_trusted_checkpoint(new_cp)
    assert store.incidents("registry") == incidents_before
    audit_export = export_rebootstrap_audit(store, registry_id="registry")
    audit_head = audit_export["head_sha256"]
    audit_kwargs = {
        "operator_keyring": {"operator-1": op1, "operator-2": op2},
        "publisher_keyring": {"publisher": pub},
        "checkpoint_keyring": {"checkpoint": cp_key},
    }
    assert verify_rebootstrap_audit_export(audit_export, **audit_kwargs,
                                           expected_head_sha256=audit_head)
    report = verify_rebootstrap_audit_export_report(
        audit_export, **audit_kwargs, expected_head_sha256=audit_head)
    assert report.status == "verified"
    assert report.record_count == report.verified_record_count == 1
    assert report.legacy_record_count == 0
    assert report.is_verified
    altered = copy.deepcopy(audit_export)
    altered["records"][0]["audit"]["intent"]["reason"] = "forged reason"
    assert not verify_rebootstrap_audit_export(altered, **audit_kwargs)
    truncated = copy.deepcopy(audit_export)
    truncated["records"] = []
    truncated["record_count"] = 0
    truncated["head_sha256"] = "0" * 64
    assert not verify_rebootstrap_audit_export(truncated, **audit_kwargs,
                                               expected_head_sha256=audit_head)

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

    # A rollback to the independently retained old DB image must fail the
    # external audit-head comparison, even though that old image is self-consistent.
    with sqlite3.connect(db_path) as restored, sqlite3.connect(rollback_image) as backup:
        backup.backup(restored)
    rolled_back_export = export_rebootstrap_audit(
        RecoveryPolicyCheckpointStore(db_path), registry_id="registry")
    rollback_report = verify_rebootstrap_audit_export_report(
        rolled_back_export, **audit_kwargs, expected_head_sha256=audit_head)
    assert rollback_report.status == "invalid"
    assert not rollback_report.is_verified


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
    # Simulate a newly recorded incident after the operators reviewed the intent.
    with sqlite3.connect(store.database_path) as db:
        db.execute("UPDATE recovery_policy_incidents SET reason='changed_after_approval' WHERE registry_id='registry'")
    assert not rebootstrap_recovery_policy_checkpoint_store(
        store, [fork], checkpoint=new_cp, publisher_keyring={"publisher": pub},
        checkpoint_keyring={"checkpoint": cp_key}, intent=intent, approvals=[approval],
        policy=RecoveryPolicyCheckpointRebootstrapPolicy(minimum_approvals=2),
        operator_keyring={"operator-1": op1, "operator-2": op2})
    assert store.is_quarantined("registry")



def test_legacy_audit_rows_are_explicitly_unverifiable_not_verified(tmp_path):
    store = RecoveryPolicyCheckpointStore(tmp_path / "legacy.sqlite3")
    with sqlite3.connect(store.database_path) as db:
        db.execute(
            "INSERT INTO recovery_policy_rebootstrap_audit "
            "(intent_sha256, registry_id, epoch, audit_json) VALUES (?, ?, ?, ?)",
            ("a" * 64, "registry", 1,
             '{"schema_version":"1.0","intent":{},"approvals":[],"epoch":1,"checkpoint_sha256":"' + "b" * 64 + '"}'),
        )
    exported = export_rebootstrap_audit(store, registry_id="registry")
    report = verify_rebootstrap_audit_export_report(
        exported, operator_keyring={}, publisher_keyring={}, checkpoint_keyring=None)
    assert report.status == "legacy_unverifiable"
    assert report.record_count == 1
    assert report.legacy_record_count == 1
    assert report.verified_record_count == 0
    assert not report.is_verified
    assert not verify_rebootstrap_audit_export(
        exported, operator_keyring={}, publisher_keyring={}, checkpoint_keyring=None)



def test_concurrent_rebootstrap_from_independent_stores_commits_exactly_once(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    pub_sk, pub = identity("publisher")
    cp_sk, cp_key = identity("checkpoint")
    op1_sk, op1 = identity("operator-1")
    op2_sk, op2 = identity("operator-2")
    original, selected = entry(pub_sk, 1), entry(pub_sk, 5)
    original_cp, selected_cp = checkpoint(original, cp_sk), checkpoint(selected, cp_sk)
    db_path = tmp_path / "concurrent-rebootstrap.sqlite3"
    initial = RecoveryPolicyCheckpointStore(db_path)
    publisher_ring = {"publisher": pub}
    checkpoint_ring = {"checkpoint": cp_key}
    operator_ring = {"operator-1": op1, "operator-2": op2}
    assert initial.pin_checkpoint([original], checkpoint=original_cp,
                                  publisher_keyring=publisher_ring,
                                  checkpoint_keyring=checkpoint_ring)
    assert not initial.pin_checkpoint([selected], checkpoint=selected_cp,
                                      publisher_keyring=publisher_ring,
                                      checkpoint_keyring=checkpoint_ring)
    incidents = initial.incidents("registry")
    intent = RecoveryPolicyCheckpointRebootstrapIntent.sign(
        registry_id="registry",
        retained_checkpoint_sha256=hashlib.sha256(original_cp.model_dump_json().encode()).hexdigest(),
        incident_history_sha256=hashlib.sha256(_canonical(incidents)).hexdigest(),
        selected_checkpoint_sha256=hashlib.sha256(selected_cp.model_dump_json().encode()).hexdigest(),
        evidence_sha256="c" * 64,
        reason="Concurrent recovery test uses an independently reviewed alternate registry history.",
        operator_key_id="operator-1", approved_at_utc="2026-11-24T07:00:00Z",
        private_key=op1_sk)
    approval = RecoveryPolicyCheckpointRebootstrapApproval.sign(
        intent=intent, operator_key_id="operator-2",
        approved_at_utc="2026-11-24T07:01:00Z", private_key=op2_sk)
    policy = RecoveryPolicyCheckpointRebootstrapPolicy(minimum_approvals=2)
    # Distinct store objects force independent SQLite connections to race.
    stores = [RecoveryPolicyCheckpointStore(db_path), RecoveryPolicyCheckpointStore(db_path)]
    barrier = Barrier(2)

    def attempt(store):
        barrier.wait(timeout=10)
        return rebootstrap_recovery_policy_checkpoint_store(
            store, [selected], checkpoint=selected_cp,
            publisher_keyring=publisher_ring, checkpoint_keyring=checkpoint_ring,
            intent=intent, approvals=[approval], policy=policy,
            operator_keyring=operator_ring)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, stores))
    assert sorted(results) == [False, True]
    assert not initial.is_quarantined("registry")
    assert initial.matches_trusted_checkpoint(selected_cp)
    with sqlite3.connect(db_path) as db:
        assert db.execute(
            "SELECT COUNT(*) FROM recovery_policy_rebootstrap_audit WHERE registry_id='registry'"
        ).fetchone()[0] == 1
        assert db.execute(
            "SELECT COUNT(*) FROM recovery_policy_epoch_entries WHERE registry_id='registry' AND epoch=1"
        ).fetchone()[0] == 1
    # Replaying the exact same signed proposal after success is rejected.
    assert not rebootstrap_recovery_policy_checkpoint_store(
        RecoveryPolicyCheckpointStore(db_path), [selected], checkpoint=selected_cp,
        publisher_keyring=publisher_ring, checkpoint_keyring=checkpoint_ring,
        intent=intent, approvals=[approval], policy=policy,
        operator_keyring=operator_ring)



def test_competing_valid_recovery_proposals_leave_only_winner_state(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    pub_sk, pub = identity("publisher")
    cp_sk, cp_key = identity("checkpoint")
    operator_secrets = {}
    operator_ring = {}
    for name in ("operator-a1", "operator-a2", "operator-b1", "operator-b2"):
        secret, record = identity(name)
        operator_secrets[name] = secret
        operator_ring[name] = record

    original = entry(pub_sk, 1)
    fork_a = entry(pub_sk, 3)
    fork_b = entry(pub_sk, 7)
    original_cp = checkpoint(original, cp_sk)
    fork_a_cp = checkpoint(fork_a, cp_sk)
    fork_b_cp = checkpoint(fork_b, cp_sk)
    db_path = tmp_path / "competing-proposals.sqlite3"
    store = RecoveryPolicyCheckpointStore(db_path)
    publisher_ring = {"publisher": pub}
    checkpoint_ring = {"checkpoint": cp_key}
    assert store.pin_checkpoint([original], checkpoint=original_cp,
                                publisher_keyring=publisher_ring,
                                checkpoint_keyring=checkpoint_ring)
    assert not store.pin_checkpoint([fork_a], checkpoint=fork_a_cp,
                                    publisher_keyring=publisher_ring,
                                    checkpoint_keyring=checkpoint_ring)
    assert store.is_quarantined("registry")
    incident_snapshot = store.incidents("registry")
    retained_hash = hashlib.sha256(original_cp.model_dump_json().encode()).hexdigest()
    incident_hash = hashlib.sha256(_canonical(incident_snapshot)).hexdigest()

    intent_a = RecoveryPolicyCheckpointRebootstrapIntent.sign(
        registry_id="registry", retained_checkpoint_sha256=retained_hash,
        incident_history_sha256=incident_hash,
        selected_checkpoint_sha256=hashlib.sha256(fork_a_cp.model_dump_json().encode()).hexdigest(),
        evidence_sha256="d" * 64,
        reason="Proposal A selects the independently verified alternate policy history.",
        operator_key_id="operator-a1", approved_at_utc="2026-11-24T07:10:00Z",
        private_key=operator_secrets["operator-a1"])
    approval_a = RecoveryPolicyCheckpointRebootstrapApproval.sign(
        intent=intent_a, operator_key_id="operator-a2",
        approved_at_utc="2026-11-24T07:11:00Z",
        private_key=operator_secrets["operator-a2"])
    intent_b = RecoveryPolicyCheckpointRebootstrapIntent.sign(
        registry_id="registry", retained_checkpoint_sha256=retained_hash,
        incident_history_sha256=incident_hash,
        selected_checkpoint_sha256=hashlib.sha256(fork_b_cp.model_dump_json().encode()).hexdigest(),
        evidence_sha256="e" * 64,
        reason="Proposal B selects a different independently verified policy history.",
        operator_key_id="operator-b1", approved_at_utc="2026-11-24T07:12:00Z",
        private_key=operator_secrets["operator-b1"])
    approval_b = RecoveryPolicyCheckpointRebootstrapApproval.sign(
        intent=intent_b, operator_key_id="operator-b2",
        approved_at_utc="2026-11-24T07:13:00Z",
        private_key=operator_secrets["operator-b2"])

    proposals = [
        ([fork_a], fork_a_cp, intent_a, [approval_a]),
        ([fork_b], fork_b_cp, intent_b, [approval_b]),
    ]
    barrier = Barrier(2)
    policy = RecoveryPolicyCheckpointRebootstrapPolicy(minimum_approvals=2)

    def attempt(index):
        entries, selected_cp, intent, approvals = proposals[index]
        independent_store = RecoveryPolicyCheckpointStore(db_path)
        barrier.wait(timeout=10)
        return rebootstrap_recovery_policy_checkpoint_store(
            independent_store, entries, checkpoint=selected_cp,
            publisher_keyring=publisher_ring, checkpoint_keyring=checkpoint_ring,
            intent=intent, approvals=approvals, policy=policy,
            operator_keyring=operator_ring)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, (0, 1)))
    assert sorted(results) == [False, True]

    winning_index = results.index(True)
    winning_entries, winning_checkpoint, winning_intent, winning_approvals = proposals[winning_index]
    losing_index = 1 - winning_index
    losing_entries, losing_checkpoint, losing_intent, losing_approvals = proposals[losing_index]
    reopened = RecoveryPolicyCheckpointStore(db_path)
    assert not reopened.is_quarantined("registry")
    assert reopened.matches_trusted_checkpoint(winning_checkpoint)
    assert not reopened.matches_trusted_checkpoint(losing_checkpoint)
    assert reopened.incidents("registry") == incident_snapshot

    audit_export = export_rebootstrap_audit(reopened, registry_id="registry")
    audit_head = audit_export["head_sha256"]
    assert audit_export["record_count"] == 1
    audit = audit_export["records"][0]["audit"]
    assert audit["intent"]["selected_checkpoint_sha256"] == hashlib.sha256(
        winning_checkpoint.model_dump_json().encode()).hexdigest()
    assert audit["intent"]["selected_checkpoint_sha256"] != hashlib.sha256(
        losing_checkpoint.model_dump_json().encode()).hexdigest()
    assert audit["intent"]["operator_key_id"] == winning_intent.operator_key_id
    assert verify_rebootstrap_audit_export(
        audit_export, operator_keyring=operator_ring,
        publisher_keyring=publisher_ring, checkpoint_keyring=checkpoint_ring,
        expected_head_sha256=audit_head)
    conflict_report = report_rebootstrap_proposal_conflicts(
        [intent_a, intent_b], audit_export)
    assert conflict_report.conflicting
    assert conflict_report.proposal_count == 2
    assert conflict_report.distinct_proposal_count == 2
    assert conflict_report.winning_intent_sha256 == winning_intent.digest()
    assert conflict_report.losing_intent_sha256 == (losing_intent.digest(),)
    assert conflict_report.unattributed_intent_sha256 == ()

    with sqlite3.connect(db_path) as db:
        assert db.execute(
            "SELECT COUNT(*) FROM recovery_policy_rebootstrap_audit WHERE registry_id='registry'"
        ).fetchone()[0] == 1
        assert db.execute(
            "SELECT COUNT(*) FROM recovery_policy_epoch_entries WHERE registry_id='registry' AND epoch=1"
        ).fetchone()[0] == len(winning_entries)
        persisted = db.execute(
            "SELECT checkpoint_sha256, quarantined, epoch FROM recovery_policy_heads WHERE registry_id='registry'"
        ).fetchone()
        assert persisted[0] == hashlib.sha256(winning_checkpoint.model_dump_json().encode()).hexdigest()
        assert persisted[1:] == (0, 1)

    # The losing proposal remains invalid after the winner commits; it cannot
    # rewrite the audit chain or mutate the trusted checkpoint.
    before = (audit_head, reopened.matches_trusted_checkpoint(winning_checkpoint),
              reopened.incidents("registry"))
    assert not rebootstrap_recovery_policy_checkpoint_store(
        RecoveryPolicyCheckpointStore(db_path), losing_entries,
        checkpoint=losing_checkpoint, publisher_keyring=publisher_ring,
        checkpoint_keyring=checkpoint_ring, intent=losing_intent,
        approvals=losing_approvals, policy=policy, operator_keyring=operator_ring)
    after_export = export_rebootstrap_audit(RecoveryPolicyCheckpointStore(db_path), registry_id="registry")
    after_store = RecoveryPolicyCheckpointStore(db_path)
    after = (after_export["head_sha256"], after_store.matches_trusted_checkpoint(winning_checkpoint),
             after_store.incidents("registry"))
    assert after == before
    assert after_export["records"] == audit_export["records"]



def test_operator_revocation_after_signing_blocks_rebootstrap_execution(tmp_path):
    pub_sk, pub = identity("publisher")
    cp_sk, cp_key = identity("checkpoint")
    op1_sk, op1 = identity("operator-1")
    op2_sk, op2 = identity("operator-2")
    first, fork = entry(pub_sk, 1), entry(pub_sk, 6)
    old_cp, new_cp = checkpoint(first, cp_sk), checkpoint(fork, cp_sk)
    store = RecoveryPolicyCheckpointStore(tmp_path / "revoked-operator.sqlite3")
    publisher_ring = {"publisher": pub}
    checkpoint_ring = {"checkpoint": cp_key}
    assert store.pin_checkpoint([first], checkpoint=old_cp,
                                publisher_keyring=publisher_ring,
                                checkpoint_keyring=checkpoint_ring)
    assert not store.pin_checkpoint([fork], checkpoint=new_cp,
                                    publisher_keyring=publisher_ring,
                                    checkpoint_keyring=checkpoint_ring)
    intent = RecoveryPolicyCheckpointRebootstrapIntent.sign(
        registry_id="registry",
        retained_checkpoint_sha256=hashlib.sha256(old_cp.model_dump_json().encode()).hexdigest(),
        incident_history_sha256=hashlib.sha256(_canonical(store.incidents("registry"))).hexdigest(),
        selected_checkpoint_sha256=hashlib.sha256(new_cp.model_dump_json().encode()).hexdigest(),
        evidence_sha256="f" * 64,
        reason="The selected recovery history was reviewed before operator key revocation.",
        operator_key_id="operator-1", approved_at_utc="2026-11-24T07:00:00Z",
        private_key=op1_sk)
    approval = RecoveryPolicyCheckpointRebootstrapApproval.sign(
        intent=intent, operator_key_id="operator-2",
        approved_at_utc="2026-11-24T07:01:00Z", private_key=op2_sk)
    # The signature remains historically valid, but this key was revoked
    # before the explicitly supplied execution/authorization time.
    revoked_op2 = op2.model_copy(update={"revoked_at_utc": "2026-11-24T07:30:00.000000Z"})
    operator_ring = {"operator-1": op1, "operator-2": revoked_op2}
    assert approval.verify(intent, operator_ring)
    assert not rebootstrap_recovery_policy_checkpoint_store(
        store, [fork], checkpoint=new_cp, publisher_keyring=publisher_ring,
        checkpoint_keyring=checkpoint_ring, intent=intent, approvals=[approval],
        policy=RecoveryPolicyCheckpointRebootstrapPolicy(minimum_approvals=2),
        operator_keyring=operator_ring,
        authorization_time_utc="2026-11-24T08:00:00.000000Z")
    assert store.is_quarantined("registry")
    assert not store.matches_trusted_checkpoint(new_cp)
    assert export_rebootstrap_audit(store, registry_id="registry")["record_count"] == 0

    # A replacement lifecycle snapshot without the revoked signer is not
    # sufficient: the exact approval still names the revoked key identity.
    assert not rebootstrap_recovery_policy_checkpoint_store(
        store, [fork], checkpoint=new_cp, publisher_keyring=publisher_ring,
        checkpoint_keyring=checkpoint_ring, intent=intent, approvals=[approval],
        policy=RecoveryPolicyCheckpointRebootstrapPolicy(minimum_approvals=2),
        operator_keyring=operator_ring,
        authorization_time_utc="2026-11-24T07:31:00.000000Z")
