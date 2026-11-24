import base64
import hashlib

from mosaic.verification.lean_runner_signature import _canonical, generate_ed25519_keypair
from mosaic.verification.policy_governance import PolicyPublisherKey
from mosaic.verification.policy_registry import SignedPolicyRegistryEntry
from mosaic.verification.policy_transparency import PolicyRegistryCheckpoint
from mosaic.verification.policy_witness_recovery import SignedPolicyWitnessRecoveryAuthorization
from mosaic.verification.policy_witness_state import PolicyWitnessStateStore
from mosaic.verification.trust_policy import HistoricalTrustPolicy, HistoricalTrustPolicyRecord


LOG_PRIVATE, LOG_PUBLIC = generate_ed25519_keypair()
ENTRY_PRIVATE, ENTRY_PUBLIC = generate_ed25519_keypair()
WITNESS_PRIVATE, WITNESS_PUBLIC = generate_ed25519_keypair()
OPERATOR_PRIVATE, OPERATOR_PUBLIC = generate_ed25519_keypair()


def key(key_id, public):
    return PolicyPublisherKey(
        key_id=key_id, public_key_b64=base64.b64encode(public).decode("ascii"),
        activated_at_utc="2026-11-01T00:00:00.000000Z",
    )


SIGNERS = {"entry-publisher": key("entry-publisher", ENTRY_PUBLIC),
           "log-signer": key("log-signer", LOG_PUBLIC)}
WITNESS_KEY = key("witness-1", WITNESS_PUBLIC)
OPERATOR_KEY = key("operator-1", OPERATOR_PUBLIC)


def entry(version):
    policy = HistoricalTrustPolicy(
        policy_id="witness-recovery-test", policy_version=f"1.0.{version}",
        allowed_kernel_ids=("Lean",), allowed_checker_ids=("lean",),
    )
    record = HistoricalTrustPolicyRecord(
        policy_sha256=policy.digest(), policy=policy,
        activated_at_utc="2026-11-01T00:00:00Z",
    )
    return SignedPolicyRegistryEntry.sign(
        sequence=0, previous_entry_sha256=None, policy_record=record,
        published_at_utc="2026-11-24T01:00:00.000000Z",
        publisher_key_id="entry-publisher", private_key=ENTRY_PRIVATE,
    )


def checkpoint(item):
    return PolicyRegistryCheckpoint.sign(
        log_id="mosaic-policy-log-recovery", sequence=0,
        head_entry_sha256=item.entry_sha256(),
        previous_checkpoint_sha256=None,
        issued_at_utc="2026-11-24T02:00:00Z",
        signer_key_id="log-signer", private_key=LOG_PRIVATE,
    )


def endorse(store, cp, item):
    return store.endorse(
        cp, entries=[item], signer_keyring=SIGNERS, witness_key=WITNESS_KEY,
        witness_private_key=WITNESS_PRIVATE, witnessed_at_utc="2026-11-24T03:00:00Z",
    )


def snapshot_for(path, item):
    store = PolicyWitnessStateStore(path)
    cp = checkpoint(item)
    assert endorse(store, cp, item) is not None
    return store.export_signed_snapshot(
        cp.log_id, witness_key_id="witness-1",
        witness_private_key=WITNESS_PRIVATE, exported_at_utc="2026-11-24T04:00:00Z",
    )


def make_authorization(snapshot, incidents, evidence=b"independent-review-record"):
    incident_digest = hashlib.sha256(_canonical(incidents)).hexdigest()
    snapshot_digest = hashlib.sha256(
        _canonical(snapshot.model_dump(mode="json"))
    ).hexdigest()
    return SignedPolicyWitnessRecoveryAuthorization.sign(
        log_id=snapshot.log_id, selected_snapshot_sha256=snapshot_digest,
        incident_history_sha256=incident_digest,
        evidence_sha256=hashlib.sha256(evidence).hexdigest(),
        reason="Independent review selected this authenticated registry history.",
        operator_key_id="operator-1", approved_at_utc="2026-11-24T05:00:00Z",
        private_key=OPERATOR_PRIVATE,
    )


def test_signed_recovery_reopens_witness_and_preserves_incidents(tmp_path):
    left_item, selected_item = entry(1), entry(2)
    left, selected = checkpoint(left_item), checkpoint(selected_item)
    target = PolicyWitnessStateStore(tmp_path / "target.sqlite3")
    assert endorse(target, left, left_item) is not None
    assert endorse(target, selected, selected_item) is None
    assert target.is_quarantined(left.log_id)
    source_snapshot = snapshot_for(tmp_path / "source.sqlite3", selected_item)
    incidents = target.incidents(left.log_id)
    auth = make_authorization(source_snapshot, incidents)
    assert target.recover_from_signed_snapshot(
        source_snapshot, witness_keyring={"witness-1": WITNESS_KEY},
        signer_keyring=SIGNERS, operator_keyring={"operator-1": OPERATOR_KEY},
        authorization=auth, entries=[selected_item],
    )
    assert target.get_head(left.log_id) == selected
    assert not target.is_quarantined(left.log_id)
    assert target.incidents(left.log_id) == incidents
    records = target.recovery_records(left.log_id)
    assert len(records) == 1
    assert records[0]["authorization_sha256"] == auth.digest()
    assert auth.model_validate_json(records[0]["authorization_json"]).verify(
        {"operator-1": OPERATOR_KEY}
    )


def test_recovery_rejects_tampering_stale_incidents_and_wrong_operator(tmp_path):
    left_item, selected_item = entry(1), entry(2)
    left, selected = checkpoint(left_item), checkpoint(selected_item)
    target = PolicyWitnessStateStore(tmp_path / "target.sqlite3")
    assert endorse(target, left, left_item) is not None
    assert endorse(target, selected, selected_item) is None
    source_snapshot = snapshot_for(tmp_path / "source.sqlite3", selected_item)
    incidents = target.incidents(left.log_id)
    auth = make_authorization(source_snapshot, incidents)
    bad = auth.model_copy(update={"reason": "altered approval"})
    kwargs = {
        "witness_keyring": {"witness-1": WITNESS_KEY},
        "signer_keyring": SIGNERS,
        "operator_keyring": {"operator-1": OPERATOR_KEY},
        "entries": [selected_item],
    }
    assert not target.recover_from_signed_snapshot(
        source_snapshot, authorization=bad, **kwargs
    )
    _, wrong_public = generate_ed25519_keypair()
    assert not target.recover_from_signed_snapshot(
        source_snapshot, authorization=auth,
        operator_keyring={"operator-1": key("operator-1", wrong_public)},
        witness_keyring=kwargs["witness_keyring"],
        signer_keyring=SIGNERS, entries=[selected_item],
    )
    changed_incidents = incidents + [{"reason": "new incident"}]
    stale = make_authorization(source_snapshot, changed_incidents)
    assert not target.recover_from_signed_snapshot(
        source_snapshot, authorization=stale, **kwargs
    )
    assert target.is_quarantined(left.log_id)
    assert target.recovery_records(left.log_id) == []


def test_recovery_cannot_be_replayed_or_run_without_quarantine(tmp_path):
    item = entry(1)
    cp = checkpoint(item)
    target = PolicyWitnessStateStore(tmp_path / "target.sqlite3")
    source_snapshot = snapshot_for(tmp_path / "source.sqlite3", item)
    auth = make_authorization(source_snapshot, [])
    kwargs = {
        "witness_keyring": {"witness-1": WITNESS_KEY},
        "signer_keyring": SIGNERS, "operator_keyring": {"operator-1": OPERATOR_KEY},
        "authorization": auth, "entries": [item],
    }
    assert not target.recover_from_signed_snapshot(source_snapshot, **kwargs)
    assert endorse(target, cp, item) is not None
    assert not target.recover_from_signed_snapshot(source_snapshot, **kwargs)


from mosaic.verification.policy_witness_recovery_governance import (
    PolicyWitnessRecoveryPolicy, SignedPolicyWitnessRecoveryApproval,
    verify_policy_witness_recovery_approvals,
)


def test_recovery_governance_requires_distinct_operator_quorum(tmp_path):
    _, second_public = generate_ed25519_keypair()
    second_private, second_public = generate_ed25519_keypair()
    _, third_public = generate_ed25519_keypair()
    third_private, third_public = generate_ed25519_keypair()
    operators = {
        "operator-1": OPERATOR_KEY,
        "operator-2": key("operator-2", second_public),
        "operator-3": key("operator-3", third_public),
    }
    item = entry(1)
    snapshot = snapshot_for(tmp_path / "quorum-source.sqlite3", item)
    authorization = make_authorization(snapshot, [])
    policy = PolicyWitnessRecoveryPolicy(
        minimum_approvals=3, required_operator_key_ids=("operator-3",),
    )
    approval2 = SignedPolicyWitnessRecoveryApproval.sign(
        authorization=authorization, operator_key_id="operator-2",
        approved_at_utc="2026-11-24T05:10:00Z", private_key=second_private,
    )
    approval3 = SignedPolicyWitnessRecoveryApproval.sign(
        authorization=authorization, operator_key_id="operator-3",
        approved_at_utc="2026-11-24T05:11:00Z", private_key=third_private,
    )
    common = {
        "authorization": authorization, "policy": policy,
        "operator_keyring": operators,
        "witness_keyring": {"witness-1": WITNESS_KEY},
        "signer_keyring": SIGNERS,
    }
    assert not verify_policy_witness_recovery_approvals(
        approvals=[approval2], **common
    )
    assert verify_policy_witness_recovery_approvals(
        approvals=[approval2, approval3], **common
    )
    duplicate = SignedPolicyWitnessRecoveryApproval.sign(
        authorization=authorization, operator_key_id="operator-1",
        approved_at_utc="2026-11-24T05:12:00Z", private_key=OPERATOR_PRIVATE,
    )
    assert not verify_policy_witness_recovery_approvals(
        approvals=[approval2, duplicate], **common
    )


def test_recovery_governance_rejects_revoked_and_reused_keys(tmp_path):
    second_private, second_public = generate_ed25519_keypair()
    item = entry(1)
    snapshot = snapshot_for(tmp_path / "revoked-source.sqlite3", item)
    authorization = make_authorization(snapshot, [])
    approval = SignedPolicyWitnessRecoveryApproval.sign(
        authorization=authorization, operator_key_id="operator-2",
        approved_at_utc="2026-11-24T05:10:00Z", private_key=second_private,
    )
    policy = PolicyWitnessRecoveryPolicy(minimum_approvals=2)
    assert not verify_policy_witness_recovery_approvals(
        authorization, policy=policy, approvals=[approval],
        operator_keyring={
            "operator-1": OPERATOR_KEY,
            "operator-2": key("operator-2", OPERATOR_PUBLIC),
        },
        witness_keyring={"witness-1": WITNESS_KEY}, signer_keyring=SIGNERS,
    )
    revoked = PolicyPublisherKey(
        key_id="operator-2",
        public_key_b64=base64.b64encode(second_public).decode("ascii"),
        activated_at_utc="2026-11-01T00:00:00.000000Z",
        revoked_at_utc="2026-11-24T05:00:00.000000Z",
    )
    assert not verify_policy_witness_recovery_approvals(
        authorization, policy=policy, approvals=[approval],
        operator_keyring={"operator-1": OPERATOR_KEY, "operator-2": revoked},
        witness_keyring={"witness-1": WITNESS_KEY}, signer_keyring=SIGNERS,
    )


def test_recovery_persists_every_coapproval_in_audit(tmp_path):
    selected_item, competing_item = entry(2), entry(3)
    selected_cp, competing_cp = checkpoint(selected_item), checkpoint(competing_item)
    target = PolicyWitnessStateStore(tmp_path / "audited-target.sqlite3")
    assert endorse(target, selected_cp, selected_item) is not None
    assert endorse(target, competing_cp, competing_item) is None
    selected_snapshot = snapshot_for(tmp_path / "audited-source.sqlite3", selected_item)
    auth = make_authorization(selected_snapshot, target.incidents(selected_cp.log_id))
    approver_private, approver_public = generate_ed25519_keypair()
    approver_key = key("operator-2", approver_public)
    approval = SignedPolicyWitnessRecoveryApproval.sign(
        authorization=auth, operator_key_id="operator-2",
        approved_at_utc="2026-11-24T05:20:00Z", private_key=approver_private,
    )
    assert target.recover_from_signed_snapshot(
        selected_snapshot, witness_keyring={"witness-1": WITNESS_KEY},
        signer_keyring=SIGNERS,
        operator_keyring={"operator-1": OPERATOR_KEY, "operator-2": approver_key},
        authorization=auth, entries=[selected_item],
        recovery_policy=PolicyWitnessRecoveryPolicy(minimum_approvals=2),
        approvals=[approval],
    )
    import json
    stored = json.loads(target.recovery_records(selected_cp.log_id)[0]["approvals_json"])
    assert stored == [approval.model_dump(mode="json")]
    assert SignedPolicyWitnessRecoveryApproval.model_validate(stored[0]).verify(
        auth, {"operator-2": approver_key}
    )
