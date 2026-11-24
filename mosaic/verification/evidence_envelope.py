"""Integrity-bound envelope for computation and verification provenance.

An envelope records evidence events and their artifact binding. Its digest
protects record integrity, not truth or authorship. Kernel-check fields record
a reported execution; this module does not execute or independently validate
Lean proofs.
"""
import hashlib
import json
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator


class EvidenceEventKind(StrEnum):
    COMPUTATION = "COMPUTATION"
    INDEPENDENT_CHECK = "INDEPENDENT_CHECK"
    FORMAL_KERNEL_CHECK = "FORMAL_KERNEL_CHECK"


class EvidenceEventOutcome(StrEnum):
    PRODUCED = "PRODUCED"
    PASSED = "PASSED"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"


class EvidenceEvent(BaseModel):
    """A provenance event referring to one exact result artifact."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str = Field(min_length=1, max_length=120)
    kind: EvidenceEventKind
    outcome: EvidenceEventOutcome
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    method: str = Field(min_length=1, max_length=300)
    tool_id: str = Field(min_length=1, max_length=160)
    tool_version: str = Field(min_length=1, max_length=80)
    kernel_id: str | None = Field(default=None, max_length=160)
    kernel_version: str | None = Field(default=None, max_length=80)
    proof_artifact_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    runner_proof_source: str | None = Field(default=None, max_length=10000)
    runner_id: str | None = Field(default=None, max_length=160)
    runner_receipt_id: str | None = Field(default=None, max_length=120)
    runner_request_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    runner_mac_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    runner_signature_b64: str | None = Field(default=None, max_length=256)
    runner_signature_algorithm: str | None = Field(default=None, max_length=32)
    runner_key_id: str | None = Field(default=None, max_length=160)

    @model_validator(mode="after")
    def validate_event(self):
        if self.kind == EvidenceEventKind.COMPUTATION and self.outcome != EvidenceEventOutcome.PRODUCED:
            raise ValueError("computation events must have outcome PRODUCED")
        if self.kind == EvidenceEventKind.INDEPENDENT_CHECK and self.outcome not in {
            EvidenceEventOutcome.PASSED, EvidenceEventOutcome.FAILED,
            EvidenceEventOutcome.INCONCLUSIVE,
        }:
            raise ValueError("independent-check events must have a check outcome")
        if self.kind == EvidenceEventKind.FORMAL_KERNEL_CHECK:
            if self.outcome not in {EvidenceEventOutcome.PASSED, EvidenceEventOutcome.FAILED}:
                raise ValueError("kernel-check events must have outcome PASSED or FAILED")
            if not self.kernel_id or not self.kernel_version or not self.proof_artifact_sha256:
                raise ValueError("kernel events require kernel identity, version, and proof artifact digest")
            runner_identity = (
                self.runner_id, self.runner_receipt_id, self.runner_request_sha256,
            )
            if any(value is not None for value in runner_identity) and not all(
                value is not None for value in runner_identity
            ):
                raise ValueError("runner identity and request metadata must be supplied together")
            signature_fields = (
                self.runner_signature_b64, self.runner_signature_algorithm,
                self.runner_key_id,
            )
            if any(value is not None for value in signature_fields) and not all(
                value is not None for value in signature_fields
            ):
                raise ValueError("signed runner metadata must be supplied as a complete set")
            if self.runner_signature_algorithm not in {None, "Ed25519"}:
                raise ValueError("unsupported runner signature algorithm")
            if self.runner_mac_sha256 is not None and not all(
                value is not None for value in runner_identity
            ):
                raise ValueError("HMAC metadata requires runner identity and request hash")
            if all(value is not None for value in signature_fields) and not all(
                value is not None for value in runner_identity
            ):
                raise ValueError("signed runner metadata requires receipt identity and request hash")
            if self.runner_signature_algorithm == "Ed25519" and not self.runner_proof_source:
                raise ValueError("Ed25519 runner events must retain the exact signed proof source")
            if self.runner_proof_source is not None and hashlib.sha256(
                self.runner_proof_source.encode("utf-8")
            ).hexdigest() != self.proof_artifact_sha256:
                raise ValueError("retained runner proof source does not match its digest")
            if any(value is not None for value in runner_identity) and (
                self.runner_mac_sha256 is None and not all(
                    value is not None for value in signature_fields
                )
            ):
                raise ValueError("runner metadata requires an HMAC or public-key signature")
        elif any(value is not None for value in (
            self.kernel_id, self.kernel_version, self.proof_artifact_sha256,
            self.runner_id, self.runner_receipt_id, self.runner_request_sha256,
            self.runner_mac_sha256, self.runner_signature_b64,
            self.runner_signature_algorithm, self.runner_key_id,
            self.runner_proof_source,
        )):
            raise ValueError("kernel metadata is only valid for FORMAL_KERNEL_CHECK")
        return self


class EvidenceEnvelope(BaseModel):
    """A claim, artifact, provenance events, and canonical integrity digest."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "1.0"
    envelope_id: str = Field(min_length=1, max_length=120)
    claim: str = Field(min_length=1, max_length=2000)
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    events: tuple[EvidenceEvent, ...] = Field(min_length=1, max_length=100)
    integrity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class EvidenceProfile(BaseModel):
    """Independent flags, not a single trust score or ordered assurance tier."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    computation_recorded: bool
    independent_check_pass_recorded: bool
    independent_check_failure_recorded: bool
    independent_check_inconclusive_recorded: bool
    kernel_pass_recorded: bool
    kernel_failure_recorded: bool
    integrity_digest_valid: bool


def _canonical_payload(envelope: EvidenceEnvelope) -> bytes:
    payload = envelope.model_dump(mode="json", exclude={"integrity_sha256"})
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def create_evidence_envelope(
    *,
    envelope_id: str,
    claim: str,
    artifact_sha256: str,
    events: tuple[EvidenceEvent, ...],
) -> EvidenceEnvelope:
    """Create an envelope whose events all bind to the same result artifact."""
    if not events:
        raise ValueError("at least one evidence event is required")
    event_ids = [event.event_id for event in events]
    if len(event_ids) != len(set(event_ids)):
        raise ValueError("evidence event identifiers must be unique")
    if any(event.artifact_sha256 != artifact_sha256 for event in events):
        raise ValueError("all evidence events must refer to the envelope artifact")
    unsigned = EvidenceEnvelope(
        envelope_id=envelope_id,
        claim=claim,
        artifact_sha256=artifact_sha256,
        events=events,
        integrity_sha256="0" * 64,
    )
    digest = hashlib.sha256(_canonical_payload(unsigned)).hexdigest()
    return unsigned.model_copy(update={"integrity_sha256": digest})


def verify_evidence_envelope(envelope: EvidenceEnvelope) -> bool:
    """Verify canonical digest and artifact binding, not the truth of the claim."""
    try:
        if hashlib.sha256(_canonical_payload(envelope)).hexdigest() != envelope.integrity_sha256:
            return False
        event_ids = [event.event_id for event in envelope.events]
        return (
            bool(envelope.events)
            and len(event_ids) == len(set(event_ids))
            and all(event.artifact_sha256 == envelope.artifact_sha256 for event in envelope.events)
        )
    except (ArithmeticError, TypeError, ValueError):
        return False


def profile_evidence_envelope(envelope: EvidenceEnvelope) -> EvidenceProfile:
    """Report which evidence types are recorded without conflating their meaning."""
    return EvidenceProfile(
        computation_recorded=any(
            event.kind == EvidenceEventKind.COMPUTATION
            and event.outcome == EvidenceEventOutcome.PRODUCED
            for event in envelope.events
        ),
        independent_check_pass_recorded=any(
            event.kind == EvidenceEventKind.INDEPENDENT_CHECK
            and event.outcome == EvidenceEventOutcome.PASSED
            for event in envelope.events
        ),
        independent_check_failure_recorded=any(
            event.kind == EvidenceEventKind.INDEPENDENT_CHECK
            and event.outcome == EvidenceEventOutcome.FAILED
            for event in envelope.events
        ),
        independent_check_inconclusive_recorded=any(
            event.kind == EvidenceEventKind.INDEPENDENT_CHECK
            and event.outcome == EvidenceEventOutcome.INCONCLUSIVE
            for event in envelope.events
        ),
        kernel_pass_recorded=any(
            event.kind == EvidenceEventKind.FORMAL_KERNEL_CHECK
            and event.outcome == EvidenceEventOutcome.PASSED
            for event in envelope.events
        ),
        kernel_failure_recorded=any(
            event.kind == EvidenceEventKind.FORMAL_KERNEL_CHECK
            and event.outcome == EvidenceEventOutcome.FAILED
            for event in envelope.events
        ),
        integrity_digest_valid=verify_evidence_envelope(envelope),
    )



def evidence_bundle_to_envelope(
    bundle,
    *,
    envelope_id: str,
    claim: str,
):
    """Wrap registered checker evidence in an integrity-bound envelope.

    The bundle must contain evidence items tied to one exact candidate. This
    adapter preserves support/refutation/unresolved findings as distinct
    outcomes and does not treat model opinions as checker evidence.
    """
    if not bundle.items:
        raise ValueError("evidence bundle contains no checker items")
    candidate_hashes = {item.candidate_sha256 for item in bundle.items}
    if len(candidate_hashes) != 1:
        raise ValueError("evidence bundle must refer to one candidate artifact")
    artifact_hash = next(iter(candidate_hashes))
    events = []
    for item in bundle.items:
        outcome = {
            "supports": EvidenceEventOutcome.PASSED,
            "refutes": EvidenceEventOutcome.FAILED,
            "unresolved": EvidenceEventOutcome.INCONCLUSIVE,
        }[item.finding]
        events.append(EvidenceEvent(
            event_id=item.evidence_id,
            kind=EvidenceEventKind.INDEPENDENT_CHECK,
            outcome=outcome,
            artifact_sha256=artifact_hash,
            method=f"Registered checker finding: {item.finding}",
            tool_id=item.checker_id,
            tool_version="registered-source",
        ))
    return create_evidence_envelope(
        envelope_id=envelope_id,
        claim=claim,
        artifact_sha256=artifact_hash,
        events=tuple(events),
    )

def verify_transformation_with_evidence(
    request,
    result: str,
    *,
    envelope_id: str,
    event_id: str,
    claim: str,
):
    """Run MOSAIC's request-bound Lean path and envelope its completed result.

    Only FORMALLY_VERIFIED and REJECTED subprocess outcomes produce kernel
    events. Unsupported input, missing Lean, timeouts, and execution errors
    return the verification result with no event/envelope. This is an
    in-process provenance adapter, not a cryptographic attestation boundary:
    callers must trust the MOSAIC process and its configured Lean executable.
    """
    import hashlib

    from mosaic.verification.lean_transformations import (
        verify_request_transformation_with_lean,
    )
    from mosaic.verification.obligations import request_fingerprint

    verification = verify_request_transformation_with_lean(request, result)
    check = verification.check
    obligation = verification.obligation
    if (
        check is None
        or obligation is None
        or verification.status not in {"FORMALLY_VERIFIED", "REJECTED"}
        or check.status != verification.status
        or not check.proof_source_sha256
        or not check.lean_version
    ):
        return verification, None

    artifact_hash = hashlib.sha256(result.encode("utf-8")).hexdigest()
    request_hash = hashlib.sha256(request.expression.encode("utf-8")).hexdigest()
    if obligation.candidate_sha256 != artifact_hash:
        raise ValueError("Lean obligation is not bound to the supplied candidate artifact")
    if obligation.request_sha256 != request_fingerprint(request):
        raise ValueError("Lean obligation is not bound to the supplied mathematical request")
    if check.lhs_sha256 != request_hash or check.rhs_sha256 != artifact_hash:
        raise ValueError("Lean check hashes do not match the exact request and candidate")
    if check.checker_id != obligation.checker_id:
        raise ValueError("Lean checker identity does not match the verified obligation")

    mathlib_revision = getattr(check, "mathlib_revision", None)
    tool_version = check.lean_version
    if mathlib_revision:
        tool_version = f"{tool_version}; Mathlib {mathlib_revision}"

    event = EvidenceEvent(
        event_id=event_id,
        kind=EvidenceEventKind.FORMAL_KERNEL_CHECK,
        outcome=(
            EvidenceEventOutcome.PASSED
            if verification.status == "FORMALLY_VERIFIED"
            else EvidenceEventOutcome.FAILED
        ),
        artifact_sha256=artifact_hash,
        method=f"Request-bound Lean obligation {obligation.obligation_id}",
        tool_id=check.checker_id,
        tool_version=tool_version,
        kernel_id="Lean",
        kernel_version=tool_version,
        proof_artifact_sha256=check.proof_source_sha256,
    )
    envelope = create_evidence_envelope(
        envelope_id=envelope_id,
        claim=claim,
        artifact_sha256=artifact_hash,
        events=(event,),
    )
    return verification, envelope

