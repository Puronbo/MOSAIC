from decimal import Decimal
import hashlib
import json

import pytest

from mosaic.core.field_configuration import FieldConfiguration1D, LatticeBoundary
from mosaic.core.field_refinement import assess_field_timestep_refinement
from mosaic.core.field_refinement_certificate import (
    RefinementDecision,
    create_field_refinement_certificate,
    verify_field_refinement_certificate,
)
from mosaic.core.scalar_potential import PolynomialTerm, ScalarPotential


def make_refinement():
    potential = ScalarPotential(
        potential_id="quadratic",
        model_id="model",
        field_name="phi",
        field_unit="phi",
        energy_unit="energy",
        domain_min=Decimal("-10"),
        domain_max=Decimal("10"),
        terms=(PolynomialTerm(coefficient=Decimal("0.5"), power=2),),
    )
    configuration = FieldConfiguration1D(
        configuration_id="initial",
        model_id="model",
        potential_id="quadratic",
        coordinates=(Decimal("0"), Decimal("1"), Decimal("2")),
        field_values=(Decimal("1"), Decimal("0"), Decimal("-1")),
        coordinate_unit="m",
        field_unit="phi",
        boundary=LatticeBoundary.OPEN,
    )
    return assess_field_timestep_refinement(
        configuration,
        potential,
        initial_velocities=(Decimal("0"),) * 3,
        base_time_step=Decimal("0.001"),
        refinement_ratio=2,
        levels=3,
        time_unit="s",
        inertia_coefficient=Decimal("1"),
        inertia_coefficient_unit="inertia",
        velocity_unit="phi/s",
        kinetic_coefficient=Decimal("1"),
        kinetic_coefficient_unit="kinetic",
        output_configuration_id_prefix="certificate",
    )


def make_certificate():
    return create_field_refinement_certificate(
        make_refinement(),
        assessment_id="assessment-001",
        field_difference_tolerance=Decimal("1"),
        velocity_difference_tolerance=Decimal("1"),
        relative_energy_drift_tolerance=Decimal("1"),
    )


def test_certificate_is_self_contained_and_verifiable():
    certificate = make_certificate()
    assert certificate.decision == RefinementDecision.ACCEPTED
    assert len(certificate.sha256) == 64
    assert certificate.refinement.levels
    assert verify_field_refinement_certificate(certificate)


def test_certificate_digest_detects_payload_tampering():
    certificate = make_certificate()
    tampered = certificate.model_copy(update={"assessment_id": "changed"})
    assert not verify_field_refinement_certificate(tampered)


def test_certificate_verifier_recomputes_acceptance_metrics():
    certificate = make_certificate()
    tampered = certificate.model_copy(update={
        "decision": RefinementDecision.REJECTED,
        "reasons": ("fabricated rejection",),
    })
    payload = tampered.model_dump(mode="json", exclude={"sha256"})
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    tampered = tampered.model_copy(update={"sha256": digest})
    assert not verify_field_refinement_certificate(tampered)


def test_certificate_rejects_nonpositive_tolerances():
    with pytest.raises(ValueError, match="field_difference_tolerance"):
        create_field_refinement_certificate(
            make_refinement(),
            assessment_id="assessment-002",
            field_difference_tolerance=Decimal("0"),
            velocity_difference_tolerance=Decimal("1"),
            relative_energy_drift_tolerance=Decimal("1"),
        )
