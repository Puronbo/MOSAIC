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
