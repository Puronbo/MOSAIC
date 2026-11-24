import base64

from mosaic.verification.lean_runner_signature import generate_ed25519_keypair
from mosaic.verification.policy_registry import SignedPolicyRegistryEntry
from mosaic.verification.policy_governance import PolicyPublisherKey
from mosaic.verification.policy_transparency import (
    PolicyCheckpointWitness, PolicyRegistryCheckpoint,
    find_checkpoint_equivocations, verify_policy_checkpoint,
)
from mosaic.verification.trust_policy import HistoricalTrustPolicy, HistoricalTrustPolicyRecord


LOG_PRIVATE, LOG_PUBLIC = generate_ed25519_keypair()
W1_PRIVATE, W1_PUBLIC = generate_ed25519_keypair()
W2_PRIVATE, W2_PUBLIC = generate_ed25519_keypair()
ENTRY_PRIVATE, ENTRY_PUBLIC = generate_ed25519_keypair()


def key(key_id, public, activated="2026-11-01T00:00:00.000000Z", revoked=None):
    return PolicyPublisherKey(
        key_id=key_id, public_key_b64=base64.b64encode(public).decode("ascii"),
        activated_at_utc=activated, revoked_at_utc=revoked,
    )


def make_entry(sequence, previous=None, marker="a"):
    policy = HistoricalTrustPolicy(
        policy_id="transparency-test", policy_version=f"1.0.{sequence}{marker}",
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


def checkpoint(entries, previous=None, sequence=None, marker=None):
    seq = len(entries) - 1 if sequence is None else sequence
    head = entries[seq].entry_sha256() if marker is None else marker
    return PolicyRegistryCheckpoint.sign(
        log_id="mosaic-policy-log-main", sequence=seq,
        head_entry_sha256=head,
        previous_checkpoint_sha256=previous.digest() if previous else None,
        issued_at_utc=f"2026-11-24T02:0{seq}:00Z",
        signer_key_id="log-signer", private_key=LOG_PRIVATE,
    )


SIGNERS = {
    "entry-publisher": key("entry-publisher", ENTRY_PUBLIC),
    "log-signer": key("log-signer", LOG_PUBLIC),
}
WITNESSES = {
    "witness-1": key("witness-1", W1_PUBLIC),
    "witness-2": key("witness-2", W2_PUBLIC),
}


def witness(cp, witness_id="witness-1", private=W1_PRIVATE, at="2026-11-24T02:01:00Z"):
    return PolicyCheckpointWitness.sign(
        checkpoint=cp, witness_key_id=witness_id,
        witnessed_at_utc=at, private_key=private,
    )


def test_signed_checkpoint_binds_registry_head_and_witness_quorum():
    entries = [make_entry(0)]
    cp = checkpoint(entries)
    proofs = [witness(cp), witness(cp, "witness-2", W2_PRIVATE)]
    assert verify_policy_checkpoint(
        cp, entries=entries, signer_keyring=SIGNERS, witnesses=proofs,
        witness_keyring=WITNESSES, minimum_witnesses=2,
    )


def test_rejects_wrong_head_sequence_and_signature():
    entries = [make_entry(0)]
    cp = checkpoint(entries)
    assert not verify_policy_checkpoint(
        cp.model_copy(update={"head_entry_sha256": "0" * 64}),
        entries=entries, signer_keyring=SIGNERS,
    )
    assert not verify_policy_checkpoint(
        cp.model_copy(update={"sequence": 1}),
        entries=entries, signer_keyring=SIGNERS,
    )
    assert not verify_policy_checkpoint(
        cp.model_copy(update={"signature_b64": base64.b64encode(b"x" * 64).decode()}),
        entries=entries, signer_keyring=SIGNERS,
    )


def test_witness_quorum_requires_distinct_trusted_valid_signatures():
    entries = [make_entry(0)]
    cp = checkpoint(entries)
    one = witness(cp)
    assert not verify_policy_checkpoint(
        cp, entries=entries, signer_keyring=SIGNERS, witnesses=[one],
        witness_keyring=WITNESSES, minimum_witnesses=2,
    )
    assert not verify_policy_checkpoint(
        cp, entries=entries, signer_keyring=SIGNERS, witnesses=[one, one],
        witness_keyring=WITNESSES, minimum_witnesses=2,
    )
    assert not verify_policy_checkpoint(
        cp, entries=entries, signer_keyring=SIGNERS, witnesses=[one],
        witness_keyring={}, minimum_witnesses=1,
    )


def test_witness_rejects_pre_checkpoint_and_revoked_keys():
    entries = [make_entry(0)]
    cp = checkpoint(entries)
    early = witness(cp, at="2026-11-24T01:59:00Z")
    assert not early.verify(cp, WITNESSES)
    revoked = {"witness-1": key(
        "witness-1", W1_PUBLIC, revoked="2026-11-24T02:00:00Z"
    )}
    assert not witness(cp).verify(cp, revoked)


def test_extension_requires_previous_checkpoint_and_exact_prefix():
    first = make_entry(0)
    entries = [first, make_entry(1, first.entry_sha256())]
    old = checkpoint([first])
    new = checkpoint(entries, previous=old)
    assert verify_policy_checkpoint(
        old, entries=[first], signer_keyring=SIGNERS,
    )
    assert verify_policy_checkpoint(
        new, entries=entries, signer_keyring=SIGNERS,
        previous_checkpoint=old,
    )
    assert not verify_policy_checkpoint(
        new, entries=entries, signer_keyring=SIGNERS,
    )
    wrong_old = old.model_copy(update={"head_entry_sha256": "0" * 64})
    assert not verify_policy_checkpoint(
        new, entries=entries, signer_keyring=SIGNERS,
        previous_checkpoint=wrong_old,
    )


def test_rejects_checkpoint_link_to_another_log_or_replayed_sequence():
    first = make_entry(0)
    entries = [first, make_entry(1, first.entry_sha256())]
    old = checkpoint([first])
    new = checkpoint(entries, previous=old)
    wrong_log = new.model_copy(update={"log_id": "other-log"})
    assert not verify_policy_checkpoint(
        wrong_log, entries=entries, signer_keyring=SIGNERS,
        previous_checkpoint=old,
    )
    replay = PolicyRegistryCheckpoint.sign(
        log_id=old.log_id, sequence=0, head_entry_sha256=old.head_entry_sha256,
        previous_checkpoint_sha256=old.digest(), issued_at_utc="2026-11-24T03:00:00Z",
        signer_key_id="log-signer", private_key=LOG_PRIVATE,
    )
    assert not verify_policy_checkpoint(
        replay, entries=[first], signer_keyring=SIGNERS,
        previous_checkpoint=old,
    )


def test_detects_same_sequence_conflicting_heads_but_not_duplicate_views():
    entries_a = [make_entry(0, marker="a")]
    entries_b = [make_entry(0, marker="b")]
    cp_a = checkpoint(entries_a)
    cp_b = checkpoint(entries_b)
    assert find_checkpoint_equivocations([cp_a, cp_a]) == []
    conflicts = find_checkpoint_equivocations([cp_a, cp_b])
    assert len(conflicts) == 1
    assert conflicts[0][:2] == (cp_a.log_id, 0)
    assert set(conflicts[0][2:]) == {
        cp_a.head_entry_sha256, cp_b.head_entry_sha256
    }


def test_equivocation_detector_separates_log_id_and_sequence():
    entries = [make_entry(0)]
    cp = checkpoint(entries)
    other_log = cp.model_copy(update={"log_id": "independent-log"})
    assert find_checkpoint_equivocations([cp, other_log]) == []
