"""Portable, integrity-checkable acceptance records for field refinement runs.

The digest detects payload changes; it does not establish mathematical truth.
The verifier recomputes the stated numerical criteria from the embedded report.
"""
import hashlib
import json
from decimal import Decimal
from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from mosaic.core.field_refinement import FieldRefinementResult


class RefinementDecision(StrEnum):
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class FieldRefinementCertificate(BaseModel):
    """Self-contained assessment payload with a canonical SHA-256 digest."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str
    assessment_id: str
    model_id: str
    potential_id: str
    initial_configuration_id: str
    field_difference_tolerance: Decimal
    velocity_difference_tolerance: Decimal
    relative_energy_drift_tolerance: Decimal
    finest_field_difference: Decimal | None
    finest_velocity_difference: Decimal | None
    maximum_absolute_relative_energy_drift: Decimal | None
    decision: RefinementDecision
    reasons: tuple[str, ...]
    refinement: FieldRefinementResult
    sha256: str


def _canonical_payload(certificate: FieldRefinementCertificate) -> bytes:
    payload = certificate.model_dump(mode="json", exclude={"sha256"})
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _finite_positive(name: str, value: Decimal) -> None:
    if not isinstance(value, Decimal) or not value.is_finite() or value <= 0:
        raise ValueError(f"{name} must be a finite positive Decimal")


def _metrics(refinement: FieldRefinementResult) -> tuple[Decimal | None, Decimal | None, Decimal | None]:
    if len(refinement.levels) < 2:
        raise ValueError("refinement report must contain at least two levels")
    finest_comparison = refinement.levels[-2]
    field_difference = finest_comparison.maximum_field_difference_from_finer
    velocity_difference = finest_comparison.maximum_velocity_difference_from_finer
    drifts = [
        abs(level.trajectory.relative_total_energy_drift)
        for level in refinement.levels
        if level.trajectory.relative_total_energy_drift is not None
    ]
    energy_drift = max(drifts) if len(drifts) == len(refinement.levels) else None
    return field_difference, velocity_difference, energy_drift


def _decision(
    field_difference: Decimal | None,
    velocity_difference: Decimal | None,
    energy_drift: Decimal | None,
    field_tolerance: Decimal,
    velocity_tolerance: Decimal,
    energy_tolerance: Decimal,
) -> tuple[RefinementDecision, tuple[str, ...]]:
    failures = []
    unknowns = []
    if field_difference is None:
        unknowns.append("Finest field comparison is unavailable.")
    elif field_difference > field_tolerance:
        failures.append("Finest field difference exceeds its tolerance.")
    if velocity_difference is None:
        unknowns.append("Finest velocity comparison is unavailable.")
    elif velocity_difference > velocity_tolerance:
        failures.append("Finest velocity difference exceeds its tolerance.")
    if energy_drift is None:
        unknowns.append("Relative energy drift is undefined for at least one refinement level.")
    elif energy_drift > energy_tolerance:
        failures.append("Maximum absolute relative energy drift exceeds its tolerance.")
    if failures:
        return RefinementDecision.REJECTED, tuple(failures + unknowns)
    if unknowns:
        return RefinementDecision.INCONCLUSIVE, tuple(unknowns)
    return RefinementDecision.ACCEPTED, ("All declared numerical acceptance criteria are satisfied.",)


def create_field_refinement_certificate(
    refinement: FieldRefinementResult,
    *,
    assessment_id: str,
    field_difference_tolerance: Decimal,
    velocity_difference_tolerance: Decimal,
    relative_energy_drift_tolerance: Decimal,
) -> FieldRefinementCertificate:
    """Create a self-contained assessment and integrity digest."""
    if not assessment_id or not assessment_id.strip():
        raise ValueError("assessment_id must be nonblank")
    _finite_positive("field_difference_tolerance", field_difference_tolerance)
    _finite_positive("velocity_difference_tolerance", velocity_difference_tolerance)
    _finite_positive("relative_energy_drift_tolerance", relative_energy_drift_tolerance)

    field_difference, velocity_difference, energy_drift = _metrics(refinement)
    decision, reasons = _decision(
        field_difference,
        velocity_difference,
        energy_drift,
        field_difference_tolerance,
        velocity_difference_tolerance,
        relative_energy_drift_tolerance,
    )
    unsigned = FieldRefinementCertificate(
        schema_version="1.0",
        assessment_id=assessment_id,
        model_id=refinement.model_id,
        potential_id=refinement.potential_id,
        initial_configuration_id=refinement.initial_configuration_id,
        field_difference_tolerance=field_difference_tolerance,
        velocity_difference_tolerance=velocity_difference_tolerance,
        relative_energy_drift_tolerance=relative_energy_drift_tolerance,
        finest_field_difference=field_difference,
        finest_velocity_difference=velocity_difference,
        maximum_absolute_relative_energy_drift=energy_drift,
        decision=decision,
        reasons=reasons,
        refinement=refinement,
        sha256="",
    )
    digest = hashlib.sha256(_canonical_payload(unsigned)).hexdigest()
    return unsigned.model_copy(update={"sha256": digest})


def verify_field_refinement_certificate(certificate: FieldRefinementCertificate) -> bool:
    """Verify digest, identity consistency, and all reported decision metrics."""
    try:
        if hashlib.sha256(_canonical_payload(certificate)).hexdigest() != certificate.sha256:
            return False
        refinement = certificate.refinement
        if (
            certificate.model_id != refinement.model_id
            or certificate.potential_id != refinement.potential_id
            or certificate.initial_configuration_id != refinement.initial_configuration_id
        ):
            return False
        field_difference, velocity_difference, energy_drift = _metrics(refinement)
        if (
            certificate.finest_field_difference != field_difference
            or certificate.finest_velocity_difference != velocity_difference
            or certificate.maximum_absolute_relative_energy_drift != energy_drift
        ):
            return False
        decision, reasons = _decision(
            field_difference,
            velocity_difference,
            energy_drift,
            certificate.field_difference_tolerance,
            certificate.velocity_difference_tolerance,
            certificate.relative_energy_drift_tolerance,
        )
        return certificate.decision == decision and certificate.reasons == reasons
    except (ArithmeticError, TypeError, ValueError):
        return False
