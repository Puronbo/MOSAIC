"""Read-only reconciliation of independently signed policy-witness snapshots.
The report identifies agreement and divergence; it never selects a canonical
history, mutates a witness store, or treats a majority as proof of truth.
"""
from __future__ import annotations

from typing import Literal
from pydantic import BaseModel, ConfigDict, Field
from mosaic.verification.policy_governance import PolicyPublisherKey
from mosaic.verification.policy_registry import SignedPolicyRegistryEntry
from mosaic.verification.policy_transparency import PolicyRegistryCheckpoint, verify_policy_checkpoint
from mosaic.verification.policy_witness_snapshot import SignedPolicyWitnessSnapshot


class PolicyWitnessReconciliationReport(BaseModel):
    """Deterministic summary suitable for explicit operator review."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["1.0"] = "1.0"
    log_id: str = Field(min_length=1, max_length=200)
    status: Literal["invalid_input", "agreement", "compatible_extension", "divergence"]
    verified_witness_key_ids: tuple[str, ...] = ()
    rejected_witness_key_ids: tuple[str, ...] = ()
    common_prefix_length: int = Field(ge=0)
    divergence_sequence: int | None = Field(default=None, ge=0)
    head_checkpoint_sha256: tuple[str, ...] = ()
    quarantined_witness_key_ids: tuple[str, ...] = ()
    operator_action: str = Field(min_length=1, max_length=1000)


def reconcile_policy_witness_snapshots(
    snapshots: list[SignedPolicyWitnessSnapshot], *,
    witness_keyring: dict[str, PolicyPublisherKey],
    signer_keyring: dict[str, PolicyPublisherKey],
    entries: list[SignedPolicyRegistryEntry],
) -> PolicyWitnessReconciliationReport:
    """Verify and compare snapshots for one log without changing any state."""
    if not isinstance(snapshots, list) or not snapshots:
        return PolicyWitnessReconciliationReport(
            log_id="unavailable", status="invalid_input", common_prefix_length=0,
            operator_action="Supply at least one signed snapshot; no state was changed.",
        )
    if any(not isinstance(item, SignedPolicyWitnessSnapshot) for item in snapshots):
        return PolicyWitnessReconciliationReport(
            log_id="mixed-or-invalid", status="invalid_input", common_prefix_length=0,
            operator_action="Supply valid snapshots for exactly one log; no state was changed.",
        )
    log_ids = {item.log_id for item in snapshots}
    if len(log_ids) != 1:
        return PolicyWitnessReconciliationReport(
            log_id="mixed-or-invalid", status="invalid_input", common_prefix_length=0,
            operator_action="Supply snapshots for exactly one log; no state was changed.",
        )
    log_id = next(iter(log_ids))
    verified = []
    rejected = []
    seen_keys = set()
    for snapshot in snapshots:
        key_id = snapshot.witness_key_id
        if key_id in seen_keys:
            rejected.append(key_id)
            continue
        seen_keys.add(key_id)
        valid = snapshot.verify(witness_keyring)
        history = snapshot.checkpoint_history
        prior: PolicyRegistryCheckpoint | None = None
        if (not history or history[-1].digest() != snapshot.checkpoint.digest()
                or len(history) != snapshot.checkpoint.sequence + 1):
            valid = False
        if valid:
            for index, checkpoint in enumerate(history):
                if checkpoint.sequence != index or checkpoint.log_id != log_id:
                    valid = False
                    break
                if not verify_policy_checkpoint(
                    checkpoint, entries=entries[:index + 1],
                    signer_keyring=signer_keyring, previous_checkpoint=prior,
                ):
                    valid = False
                    break
                prior = checkpoint
        if valid:
            verified.append(snapshot)
        else:
            rejected.append(key_id)

    if rejected or len(verified) != len(snapshots):
        return PolicyWitnessReconciliationReport(
            log_id=log_id, status="invalid_input",
            verified_witness_key_ids=tuple(sorted(x.witness_key_id for x in verified)),
            rejected_witness_key_ids=tuple(sorted(rejected)), common_prefix_length=0,
            head_checkpoint_sha256=tuple(sorted(x.checkpoint.digest() for x in verified)),
            quarantined_witness_key_ids=tuple(sorted(
                x.witness_key_id for x in verified if x.quarantined
            )),
            operator_action=(
                "Reject this reconciliation result. Resolve invalid signatures, "
                "duplicate witness identities, or incomplete/unverifiable histories "
                "before comparing state; no state was changed."
            ),
        )

    histories = [tuple(item.digest() for item in snap.checkpoint_history)
                 for snap in verified]
    common = 0
    shortest = min(len(history) for history in histories)
    while common < shortest and len({history[common] for history in histories}) == 1:
        common += 1
    divergence = None
    if common < shortest:
        divergence = common
    if divergence is not None:
        status = "divergence"
        action = (
            "Preserve every snapshot and quarantine affected trust decisions. "
            "An authorized operator must investigate conflicting signed histories "
            "using independent evidence; do not choose by majority."
        )
    elif len(set(histories)) == 1:
        status = "agreement"
        action = (
            "Snapshots agree on the complete checkpoint history. This does not "
            "establish freshness; compare against an independently distributed "
            "freshness anchor before accepting the head."
        )
    else:
        status = "compatible_extension"
        action = (
            "Histories share a complete prefix and differ only by verified "
            "extensions. Evaluate the longest history against an independent "
            "freshness anchor; this report does not import or advance any witness."
        )
    return PolicyWitnessReconciliationReport(
        log_id=log_id, status=status,
        verified_witness_key_ids=tuple(sorted(x.witness_key_id for x in verified)),
        common_prefix_length=common, divergence_sequence=divergence,
        head_checkpoint_sha256=tuple(sorted(x.checkpoint.digest() for x in verified)),
        quarantined_witness_key_ids=tuple(sorted(
            x.witness_key_id for x in verified if x.quarantined
        )),
        operator_action=action,
    )
