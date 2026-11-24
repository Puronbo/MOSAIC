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

    @model_validator(mode="after")
    def validate_event(self):
        if self.kind == EvidenceEventKind.COMPUTATION and self.outcome != EvidenceEventOutcome.PRODUCED:
            raise ValueError("computation events must have outcome PRODUCED")
        if self.kind == EvidenceEventKind.INDEPENDENT_CHECK and self.outcome not in {
            EvidenceEventOutcome.PASSED, EvidenceEventOutcome.FAILED
        }:
            raise ValueError("independent-check events must have outcome PASSED or FAILED")
        if self.kind == EvidenceEventKind.FORMAL_KERNEL_CHECK:
            if self.outcome not in {EvidenceEventOutcome.PASSED, EvidenceEventOutcome.FAILED}:
                raise ValueError("kernel-check events must have outcome PASSED or FAILED")
            if not self.kernel_id or not self.kernel_version or not self.proof_artifact_sha256:
                raise ValueError("kernel events require kernel identity, version, and proof artifact digest")
        elif any(value is not None for value in (self.kernel_id, self.kernel_version, self.proof_artifact_sha256)):
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
        return bool(envelope.events) and all(
            event.artifact_sha256 == envelope.artifact_sha256
            for event in envelope.events
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
