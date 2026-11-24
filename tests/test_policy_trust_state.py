import base64

from mosaic.verification.lean_runner_signature import generate_ed25519_keypair
from mosaic.verification.policy_registry import SignedPolicyRegistryEntry
from mosaic.verification.policy_governance import PolicyPublisherKey
from mosaic.verification.policy_transparency import PolicyRegistryCheckpoint
from mosaic.verification.policy_trust_state import PolicyCheckpointStore
from mosaic.verification.trust_policy import HistoricalTrustPolicy, HistoricalTrustPolicyRecord


LOG_PRIVATE, LOG_PUBLIC = generate_ed25519_keypair()
ENTRY_PRIVATE, ENTRY_PUBLIC = generate_ed25519_keypair()


def key(key_id, public):
    return PolicyPublisherKey(
        key_id=key_id, public_key_b64=base64.b64encode(public).decode("ascii"),
        activated_at_utc="2026-11-01T00:00:00.000000Z",
    )


KEYRING = {
    "entry-publisher": key("entry-publisher", ENTRY_PUBLIC),
    "log-signer": key("log-signer", LOG_PUBLIC),
}


def entry(sequence, previous=None, version=0):
    policy = HistoricalTrustPolicy(
        policy_id="persistent-state-test", policy_version=f"1.0.{version}",
        allowed_kernel_ids=("Lean",), allowed_checker_ids=("lean",),
    )
    record = HistoricalTrustPolicyRecord(
        policy_sha256=policy.digest(), policy=policy,
        activated_at_utc="2026-11-01T00:00:00Z",
    )
    return SignedPolicyRegistryEntry.sign(
        sequence=sequence, previous_entry_sha256=previous,
        policy_record=record, published_at_utc=f"2026-11-24T01:0{sequence}:00.000000Z",
        publisher_key_id="entry-publisher", private_key=ENTRY_PRIVATE,
    )


def cp(entries, previous=None):
    sequence = len(entries) - 1
    return PolicyRegistryCheckpoint.sign(
        log_id="mosaic-policy-log-main", sequence=sequence,
        head_entry_sha256=entries[-1].entry_sha256(),
        previous_checkpoint_sha256=previous.digest() if previous else None,
        issued_at_utc=f"2026-11-24T02:0{sequence}:00Z",
        signer_key_id="log-signer", private_key=LOG_PRIVATE,
    )


def test_checkpoint_persists_across_store_restart(tmp_path):
    entries = [entry(0)]
    checkpoint = cp(entries)
    path = tmp_path / "trust-state.sqlite3"
    first = PolicyCheckpointStore(path)
    assert first.accept_checkpoint(checkpoint, entries=entries, signer_keyring=KEYRING)
    second = PolicyCheckpointStore(path)
    assert second.get_head(checkpoint.log_id) == checkpoint
    assert not second.is_quarantined(checkpoint.log_id)


def test_rejects_replayed_and_older_checkpoint_without_mutating_head(tmp_path):
    first_entry = entry(0)
    second_entry = entry(1, first_entry.entry_sha256())
    first = cp([first_entry])
    second = cp([first_entry, second_entry], first)
    store = PolicyCheckpointStore(tmp_path / "state.sqlite3")
    assert store.accept_checkpoint(first, entries=[first_entry], signer_keyring=KEYRING)
    assert store.accept_checkpoint(
        second, entries=[first_entry, second_entry], signer_keyring=KEYRING
    )
    assert not store.accept_checkpoint(
        first, entries=[first_entry], signer_keyring=KEYRING
    )
    assert store.get_head(first.log_id) == second


def test_same_sequence_conflicting_signed_head_quarantines_without_overwrite(tmp_path):
    left_entries = [entry(0, version=1)]
    right_entries = [entry(0, version=2)]
    left = cp(left_entries)
    right = cp(right_entries)
    store = PolicyCheckpointStore(tmp_path / "state.sqlite3")
    assert store.accept_checkpoint(left, entries=left_entries, signer_keyring=KEYRING)
    assert not store.accept_checkpoint(right, entries=right_entries, signer_keyring=KEYRING)
    assert store.is_quarantined(left.log_id)
    assert store.get_head(left.log_id) == left
    incidents = store.incidents(left.log_id)
    assert len(incidents) == 1
    assert incidents[0]["existing_head_sha256"] == left.head_entry_sha256
    assert incidents[0]["conflicting_head_sha256"] == right.head_entry_sha256


def test_quarantine_blocks_all_automatic_advancement(tmp_path):
    left_entries = [entry(0, version=1)]
    right_entries = [entry(0, version=2)]
    left = cp(left_entries)
    right = cp(right_entries)
    store = PolicyCheckpointStore(tmp_path / "state.sqlite3")
    assert store.accept_checkpoint(left, entries=left_entries, signer_keyring=KEYRING)
    assert not store.accept_checkpoint(right, entries=right_entries, signer_keyring=KEYRING)
    later_entry = entry(1, right_entries[0].entry_sha256(), version=3)
    later = cp([right_entries[0], later_entry], right)
    assert not store.accept_checkpoint(
        later, entries=[right_entries[0], later_entry], signer_keyring=KEYRING
    )


def test_recovery_requires_explicit_operator_confirmation_and_reason(tmp_path):
    left_entries = [entry(0, version=1)]
    right_entries = [entry(0, version=2)]
    left = cp(left_entries)
    right = cp(right_entries)
    store = PolicyCheckpointStore(tmp_path / "state.sqlite3")
    assert store.accept_checkpoint(left, entries=left_entries, signer_keyring=KEYRING)
    assert not store.accept_checkpoint(right, entries=right_entries, signer_keyring=KEYRING)
    assert not store.recover_from_conflict(
        right, entries=right_entries, signer_keyring=KEYRING,
        operator_reason="investigation", operator_confirmed=False,
    )
    assert not store.recover_from_conflict(
        right, entries=right_entries, signer_keyring=KEYRING,
        operator_reason=" ", operator_confirmed=True,
    )
    assert store.is_quarantined(left.log_id)


def test_explicit_recovery_is_audited_and_reopens_log(tmp_path):
    left_entries = [entry(0, version=1)]
    right_entries = [entry(0, version=2)]
    left = cp(left_entries)
    right = cp(right_entries)
    store = PolicyCheckpointStore(tmp_path / "state.sqlite3")
    assert store.accept_checkpoint(left, entries=left_entries, signer_keyring=KEYRING)
    assert not store.accept_checkpoint(right, entries=right_entries, signer_keyring=KEYRING)
    assert store.recover_from_conflict(
        right, entries=right_entries, signer_keyring=KEYRING,
        operator_reason="independent review selected the alternate registry export",
        operator_confirmed=True,
    )
    assert store.get_head(left.log_id) == right
    assert not store.is_quarantined(left.log_id)
    incidents = store.incidents(left.log_id)
    assert len(incidents) == 2
    assert incidents[-1]["reason"].startswith("explicit recovery:")
