import base64

from mosaic.verification.lean_runner_signature import generate_ed25519_keypair
from mosaic.verification.policy_governance import PolicyPublisherKey
from mosaic.verification.policy_registry import SignedPolicyRegistryEntry
from mosaic.verification.policy_transparency import PolicyRegistryCheckpoint
from mosaic.verification.policy_witness_state import PolicyWitnessStateStore
from mosaic.verification.trust_policy import HistoricalTrustPolicy, HistoricalTrustPolicyRecord


LOG_PRIVATE, LOG_PUBLIC = generate_ed25519_keypair()
ENTRY_PRIVATE, ENTRY_PUBLIC = generate_ed25519_keypair()
WITNESS_PRIVATE, WITNESS_PUBLIC = generate_ed25519_keypair()


def key(key_id, public):
    return PolicyPublisherKey(
        key_id=key_id, public_key_b64=base64.b64encode(public).decode("ascii"),
        activated_at_utc="2026-11-01T00:00:00.000000Z",
    )


SIGNERS = {"entry-publisher": key("entry-publisher", ENTRY_PUBLIC),
           "log-signer": key("log-signer", LOG_PUBLIC)}
WITNESS_KEY = key("witness-1", WITNESS_PUBLIC)


def entry(sequence, previous=None, version=0):
    policy = HistoricalTrustPolicy(
        policy_id="independent-witness-test", policy_version=f"1.0.{version}",
        allowed_kernel_ids=("Lean",), allowed_checker_ids=("lean",),
    )
    record = HistoricalTrustPolicyRecord(
        policy_sha256=policy.digest(), policy=policy,
        activated_at_utc="2026-11-01T00:00:00Z",
    )
    return SignedPolicyRegistryEntry.sign(
        sequence=sequence, previous_entry_sha256=previous,
        policy_record=record,
        published_at_utc=f"2026-11-24T01:0{sequence}:00.000000Z",
        publisher_key_id="entry-publisher", private_key=ENTRY_PRIVATE,
    )


def checkpoint(entries, previous=None):
    sequence = len(entries) - 1
    return PolicyRegistryCheckpoint.sign(
        log_id="mosaic-policy-log-main", sequence=sequence,
        head_entry_sha256=entries[-1].entry_sha256(),
        previous_checkpoint_sha256=previous.digest() if previous else None,
        issued_at_utc=f"2026-11-24T02:0{sequence}:00Z",
        signer_key_id="log-signer", private_key=LOG_PRIVATE,
    )


def endorse(store, cp, entries):
    return store.endorse(
        cp, entries=entries, signer_keyring=SIGNERS,
        witness_key=WITNESS_KEY, witness_private_key=WITNESS_PRIVATE,
        witnessed_at_utc="2026-11-24T03:00:00Z",
    )


def test_witness_advances_only_verified_extension_and_survives_restart(tmp_path):
    path = tmp_path / "witness.sqlite3"
    first_entry = entry(0)
    first = checkpoint([first_entry])
    store = PolicyWitnessStateStore(path)
    signature = endorse(store, first, [first_entry])
    assert signature is not None and signature.verify(first, {"witness-1": WITNESS_KEY})
    second_entry = entry(1, first_entry.entry_sha256())
    second = checkpoint([first_entry, second_entry], first)
    assert endorse(store, second, [first_entry, second_entry]) is not None
    restarted = PolicyWitnessStateStore(path)
    assert restarted.get_head(first.log_id) == second


def test_witness_rejects_replay_and_unlinked_or_invalid_extension(tmp_path):
    first_entry = entry(0)
    first = checkpoint([first_entry])
    store = PolicyWitnessStateStore(tmp_path / "witness.sqlite3")
    assert endorse(store, first, [first_entry]) is not None
    assert endorse(store, first, [first_entry]) is None
    later_entry = entry(1, first_entry.entry_sha256())
    unlinked = checkpoint([first_entry, later_entry])
    assert endorse(store, unlinked, [first_entry, later_entry]) is None
    assert store.get_head(first.log_id) == first


def test_valid_same_sequence_fork_quarantines_witness(tmp_path):
    left_entry, right_entry = entry(0, version=1), entry(0, version=2)
    left, right = checkpoint([left_entry]), checkpoint([right_entry])
    store = PolicyWitnessStateStore(tmp_path / "witness.sqlite3")
    assert endorse(store, left, [left_entry]) is not None
    assert endorse(store, right, [right_entry]) is None
    assert store.is_quarantined(left.log_id)
    assert store.get_head(left.log_id) == left
    assert len(store.incidents(left.log_id)) == 1
    assert endorse(store, left, [left_entry]) is None


def test_invalid_fork_cannot_quarantine_and_wrong_private_key_cannot_endorse(tmp_path):
    first_entry = entry(0)
    first = checkpoint([first_entry])
    store = PolicyWitnessStateStore(tmp_path / "witness.sqlite3")
    assert endorse(store, first, [first_entry]) is not None
    fork_entry = entry(0, version=2)
    fork = checkpoint([fork_entry])
    assert store.endorse(
        fork, entries=[], signer_keyring=SIGNERS, witness_key=WITNESS_KEY,
        witness_private_key=WITNESS_PRIVATE,
        witnessed_at_utc="2026-11-24T03:00:00Z",
    ) is None
    assert not store.is_quarantined(first.log_id)
    _, wrong_public = generate_ed25519_keypair()
    wrong = key("witness-1", wrong_public)
    assert store.endorse(
        first, entries=[first_entry], signer_keyring=SIGNERS,
        witness_key=wrong, witness_private_key=WITNESS_PRIVATE,
        witnessed_at_utc="2026-11-24T03:00:00Z",
    ) is None

def test_same_head_checkpoint_refresh_is_not_misclassified_as_fork(tmp_path):
    first_entry = entry(0)
    first = checkpoint([first_entry])
    refreshed = PolicyRegistryCheckpoint.sign(
        log_id=first.log_id, sequence=first.sequence,
        head_entry_sha256=first.head_entry_sha256,
        previous_checkpoint_sha256=None,
        issued_at_utc="2026-11-24T04:00:00Z",
        signer_key_id="log-signer", private_key=LOG_PRIVATE,
    )
    store = PolicyWitnessStateStore(tmp_path / "witness.sqlite3")
    assert endorse(store, first, [first_entry]) is not None
    assert endorse(store, refreshed, [first_entry]) is None
    assert not store.is_quarantined(first.log_id)
    assert store.get_head(first.log_id) == first

def test_signed_snapshot_bootstraps_empty_store_and_preserves_head(tmp_path):
    first_entry = entry(0)
    first = checkpoint([first_entry])
    source = PolicyWitnessStateStore(tmp_path / "source.sqlite3")
    assert endorse(source, first, [first_entry]) is not None
    snapshot = source.export_signed_snapshot(
        first.log_id, witness_key_id="witness-1",
        witness_private_key=WITNESS_PRIVATE,
        exported_at_utc="2026-11-24T04:00:00Z",
    )
    assert snapshot is not None and snapshot.verify({"witness-1": WITNESS_KEY})
    target = PolicyWitnessStateStore(tmp_path / "target.sqlite3")
    assert target.import_signed_snapshot(
        snapshot, witness_keyring={"witness-1": WITNESS_KEY},
        entries=[first_entry], signer_keyring=SIGNERS,
    )
    assert target.get_head(first.log_id) == first


def test_snapshot_import_rejects_tampering_and_rollback(tmp_path):
    first_entry = entry(0)
    first = checkpoint([first_entry])
    source = PolicyWitnessStateStore(tmp_path / "source.sqlite3")
    assert endorse(source, first, [first_entry]) is not None
    old_snapshot = source.export_signed_snapshot(
        first.log_id, witness_key_id="witness-1",
        witness_private_key=WITNESS_PRIVATE,
        exported_at_utc="2026-11-24T04:00:00Z",
    )
    second_entry = entry(1, first_entry.entry_sha256())
    second = checkpoint([first_entry, second_entry], first)
    assert endorse(source, second, [first_entry, second_entry]) is not None
    new_snapshot = source.export_signed_snapshot(
        second.log_id, witness_key_id="witness-1",
        witness_private_key=WITNESS_PRIVATE,
        exported_at_utc="2026-11-24T04:01:00Z",
    )
    target = PolicyWitnessStateStore(tmp_path / "target.sqlite3")
    kwargs = {"witness_keyring": {"witness-1": WITNESS_KEY},
              "signer_keyring": SIGNERS}
    assert target.import_signed_snapshot(
        new_snapshot, entries=[first_entry, second_entry], **kwargs
    )
    assert not target.import_signed_snapshot(
        old_snapshot, entries=[first_entry], **kwargs
    )
    tampered = new_snapshot.model_copy(update={"quarantined": True})
    assert not tampered.verify({"witness-1": WITNESS_KEY})
    assert target.get_head(first.log_id) == second
    assert not target.is_quarantined(first.log_id)


def test_snapshot_cannot_clear_existing_quarantine(tmp_path):
    first_entry = entry(0, version=1)
    fork_entry = entry(0, version=2)
    first, fork = checkpoint([first_entry]), checkpoint([fork_entry])
    source = PolicyWitnessStateStore(tmp_path / "source.sqlite3")
    target = PolicyWitnessStateStore(tmp_path / "target.sqlite3")
    assert endorse(source, first, [first_entry]) is not None
    assert endorse(target, first, [first_entry]) is not None
    assert endorse(target, fork, [fork_entry]) is None
    assert target.is_quarantined(first.log_id)
    snapshot = source.export_signed_snapshot(
        first.log_id, witness_key_id="witness-1",
        witness_private_key=WITNESS_PRIVATE,
        exported_at_utc="2026-11-24T04:00:00Z",
    )
    assert not target.import_signed_snapshot(
        snapshot, witness_keyring={"witness-1": WITNESS_KEY},
        entries=[first_entry], signer_keyring=SIGNERS,
    )
    assert target.is_quarantined(first.log_id)
