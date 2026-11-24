"""Typed evidence envelopes with explicit, non-collapsed trust distinctions.

Evidence labels describe what was done to an artifact. They do not make an
untrusted assertion true; kernel records are provenance claims unless backed
by an independently trusted kernel execution and artifact.
"""
import hashlib
import json
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator


class EvidenceKind(StrEnum):
    COMPUTATION = "COMPUTATION"
    INDEPENDENT_CHECK = "INDEPENDENT_CHECK"
    FORMAL_KERNEL_CHECK = "FORMAL_KERNEL_CHECK"


class EvidenceOutcome(StrEnum):
    PRODUCED = "PRODUCED"
    PASSED = "PASSED"
    FAILED = "FAILED"


class EvidenceRecord(BaseModel):
    """One typed evidence event tied to the artifact it concerns."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_id: str = Field(min_length=1, max_length=120)
    kind: EvidenceKind
    outcome: EvidenceOutcome
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    method: str = Field(min_length=1, max_length=300)
    tool_id: str = Field(min_length=1, max_length=160)
    tool_version: str = Field(min_length=1, max_length=80)
    kernel_id: str | None = Field(default=None, max_length=160)
    kernel_version: str | None = Field(default=None, max_length=80)
    proof_artifact_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_evidence_kind(self):
        if self.kind == EvidenceKind.COMPUTATION and self.outcome != EvidenceOutcome.PRODUCED:
            raise ValueError("computation evidence must have outcome PRODUCED")
        if self.kind == EvidenceKind.INDEPENDENT_CHECK and self.outcome not in {
            EvidenceOutcome.PASSED, EvidenceOutcome.FAILED
        }:
            raise ValueError("independent checks must have outcome PASSED or FAILED")
        if self.kind == EvidenceKind.FORMAL_KERNEL_CHECK:
            if self.outcome not in {EvidenceOutcome.PASSED, EvidenceOutcome.FAILED}:
                raise ValueError("kernel checks must have outcome PASSED or FAILED")
            if not self.kernel_id or not self.kernel_version or not self.proof_artifact_sha256:
                raise ValueError("kernel evidence requires kernel identity, version, and proof artifact digest")
        elif any(value is not None for value in (self.kernel_id, self.kernel_version, self.proof_artifact_sha256)):
            raise ValueError("kernel metadata is only valid for FORMAL_KERNEL_CHECK")
        return self


class EvidenceEnvelope(BaseModel):
    """A claim plus its evidence events and a canonical integrity digest."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "1.0"
    envelope_id: str = Field(min_length=1, max_length=120)
    claim: str = Field(min_length=1, max_length=2000)
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    records: tuple[EvidenceRecord, ...] = Field(min_length=1, max_length=100)
    integrity_sha256: str


class EvidenceProfile(BaseModel):
    """Facts present in an envelope; deliberately not a single trust score."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    computation_recorded: bool
    independent_check_passed: bool
    independent_check_failed: bool
    formal_kernel_check_passed: bool
    formal_kernel_check_failed: bool
    integrity_digest_valid: bool


def _canonical_payload(envelope: EvidenceEnvelope) -> bytes:
    payload = envelope.model_dump(mode="json", exclude={"integrity_sha256"})
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def create_evidence_envelope(
    *,
    envelope_id: str,
    claim: str,
    artifact_sha256: str,
    records: tuple[EvidenceRecord, ...],
) -> EvidenceEnvelope:
    """Build a canonical envelope; all records must refer to the same artifact."""
    if not records:
        raise ValueError("at least one evidence record is required")
    if any(record.artifact_sha256 != artifact_sha256 for record in records):
        raise ValueError("all evidence records must refer to the envelope artifact")
    unsigned = EvidenceEnvelope(
        envelope_id=envelope_id,
        claim=claim,
        artifact_sha256=artifact_sha256,
        records=records,
        integrity_sha256="",
    )
    digest = hashlib.sha256(_canonical_payload(unsigned)).hexdigest()
    return unsigned.model_copy(update={"integrity_sha256": digest})


def verify_evidence_envelope(envelope: EvidenceEnvelope) -> bool:
    """Check digest and evidence-to-artifact binding, not the truth of the claim."""
    try:
        if hashlib.sha256(_canonical_payload(envelope)).hexdigest() != envelope.integrity_sha256:
            return False
        return bool(envelope.records) and all(
            record.artifact_sha256 == envelope.artifact_sha256
            for record in envelope.records
        )
    except (ArithmeticError, TypeError, ValueError):
        return False


def profile_evidence_envelope(envelope: EvidenceEnvelope) -> EvidenceProfile:
    """Summarize recorded evidence without treating hash integrity as proof."""
    digest_valid = verify_evidence_envelope(envelope)
    return EvidenceProfile(
        computation_recorded=any(
            item.kind == EvidenceKind.COMPUTATION and item.outcome == EvidenceOutcome.PRODUCED
            for item in envelope.records
        ),
        independent_check_passed=any(
            item.kind == EvidenceKind.INDEPENDENT_CHECK and item.outcome == EvidenceOutcome.PASSED
            for item in envelope.records
        ),
        independent_check_failed=any(
            item.kind == EvidenceKind.INDEPENDENT_CHECK and item.outcome == EvidenceOutcome.FAILED
            for item in envelope.records
        ),
        formal_kernel_check_passed=any(
            item.kind == EvidenceKind.FORMAL_KERNEL_CHECK and item.outcome == EvidenceOutcome.PASSED
            for item in envelope.records
        ),
        formal_kernel_check_failed=any(
            item.kind == EvidenceKind.FORMAL_KERNEL_CHECK and item.outcome == EvidenceOutcome.FAILED
            for item in envelope.records
        ),
        integrity_digest_valid=digest_valid,
    )
