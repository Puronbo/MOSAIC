import hashlib

import pytest
from pydantic import ValidationError

from mosaic.verification.evidence_envelope import (
    EvidenceEvent,
    EvidenceEventKind,
    EvidenceEventOutcome,
    create_evidence_envelope,
    profile_evidence_envelope,
    verify_evidence_envelope,
    evidence_bundle_to_envelope,
)


ARTIFACT = hashlib.sha256(b"result artifact").hexdigest()
PROOF = hashlib.sha256(b"proof source").hexdigest()


def event(kind, outcome, **extra):
    return EvidenceEvent(
        event_id=f"event-{kind.value.lower()}",
        kind=kind,
        outcome=outcome,
        artifact_sha256=ARTIFACT,
        method="declared procedure",
        tool_id="mosaic-test",
        tool_version="1.0",
        **extra,
    )


def test_computation_independent_check_and_integrity_are_separate_flags():
    envelope = create_evidence_envelope(
        envelope_id="env-1",
        claim="The computed result passed an independent check.",
        artifact_sha256=ARTIFACT,
        events=(
            event(EvidenceEventKind.COMPUTATION, EvidenceEventOutcome.PRODUCED),
            event(EvidenceEventKind.INDEPENDENT_CHECK, EvidenceEventOutcome.PASSED),
        ),
    )
    profile = profile_evidence_envelope(envelope)
    assert profile.computation_recorded
    assert profile.independent_check_pass_recorded
    assert not profile.kernel_pass_recorded
    assert profile.integrity_digest_valid
    assert verify_evidence_envelope(envelope)


def test_kernel_event_requires_kernel_identity_and_proof_digest():
    with pytest.raises(ValidationError, match="kernel identity"):
        event(EvidenceEventKind.FORMAL_KERNEL_CHECK, EvidenceEventOutcome.PASSED)


def test_kernel_event_is_recorded_not_independently_proven_by_envelope():
    kernel_event = event(
        EvidenceEventKind.FORMAL_KERNEL_CHECK,
        EvidenceEventOutcome.PASSED,
        kernel_id="Lean",
        kernel_version="4.19.0",
        proof_artifact_sha256=PROOF,
    )
    envelope = create_evidence_envelope(
        envelope_id="env-kernel",
        claim="A Lean kernel pass was recorded for this proof artifact.",
        artifact_sha256=ARTIFACT,
        events=(kernel_event,),
    )
    profile = profile_evidence_envelope(envelope)
    assert profile.kernel_pass_recorded
    assert profile.integrity_digest_valid
    assert verify_evidence_envelope(envelope)


def test_integrity_digest_detects_payload_changes():
    envelope = create_evidence_envelope(
        envelope_id="env-tamper",
        claim="A computed result.",
        artifact_sha256=ARTIFACT,
        events=(event(EvidenceEventKind.COMPUTATION, EvidenceEventOutcome.PRODUCED),),
    )
    tampered = envelope.model_copy(update={"claim": "A different claim."})
    assert not verify_evidence_envelope(tampered)
    assert not profile_evidence_envelope(tampered).integrity_digest_valid


def test_all_events_must_bind_to_same_artifact():
    other_artifact = hashlib.sha256(b"other").hexdigest()
    mismatched = event(
        EvidenceEventKind.COMPUTATION,
        EvidenceEventOutcome.PRODUCED,
    ).model_copy(update={"artifact_sha256": other_artifact})
    with pytest.raises(ValueError, match="envelope artifact"):
        create_evidence_envelope(
            envelope_id="env-mismatch",
            claim="Mismatched evidence.",
            artifact_sha256=ARTIFACT,
            events=(mismatched,),
        )


def test_failed_check_is_not_reported_as_passed():
    envelope = create_evidence_envelope(
        envelope_id="env-failed",
        claim="The independent check failed.",
        artifact_sha256=ARTIFACT,
        events=(event(EvidenceEventKind.INDEPENDENT_CHECK, EvidenceEventOutcome.FAILED),),
    )
    profile = profile_evidence_envelope(envelope)
    assert profile.independent_check_failure_recorded
    assert not profile.independent_check_pass_recorded

def test_existing_registered_checker_bundle_converts_to_envelope():
    import json

    from mosaic.core.requests import MathRequest
    from mosaic.core.types import Operation
    from mosaic.verification.evidence import evidence_from_check
    from mosaic.verification.task_bound import verify_task_bound_candidate

    request = MathRequest(
        operation=Operation.SIMPLIFY,
        expression="(x + 1)**2",
        variable="x",
    )
    raw = json.dumps({
        "operation": "simplify",
        "expression": "(x + 1)**2",
        "variable": "x",
        "result": "x**2 + 2*x + 1",
    })
    checked = verify_task_bound_candidate(request, raw)
    bundle = evidence_from_check(checked, request, raw)
    envelope = evidence_bundle_to_envelope(
        bundle,
        envelope_id="task-bound-001",
        claim="The proposed polynomial transformation passed registered checks.",
    )
    assert verify_evidence_envelope(envelope)
    profile = profile_evidence_envelope(envelope)
    assert profile.independent_check_pass_recorded
    assert not profile.kernel_pass_recorded


def test_duplicate_event_ids_are_rejected():
    first = event(EvidenceEventKind.COMPUTATION, EvidenceEventOutcome.PRODUCED)
    duplicate = first.model_copy(update={"kind": EvidenceEventKind.COMPUTATION})
    with pytest.raises(ValueError, match="identifiers must be unique"):
        create_evidence_envelope(
            envelope_id="env-duplicate",
            claim="Duplicate event ids.",
            artifact_sha256=ARTIFACT,
            events=(first, duplicate),
        )


def test_inconclusive_check_remains_inconclusive_in_profile():
    envelope = create_evidence_envelope(
        envelope_id="env-inconclusive",
        claim="The checker could not decide.",
        artifact_sha256=ARTIFACT,
        events=(event(
            EvidenceEventKind.INDEPENDENT_CHECK,
            EvidenceEventOutcome.INCONCLUSIVE,
        ),),
    )
    profile = profile_evidence_envelope(envelope)
    assert profile.independent_check_inconclusive_recorded
    assert not profile.independent_check_pass_recorded
    assert not profile.independent_check_failure_recorded
