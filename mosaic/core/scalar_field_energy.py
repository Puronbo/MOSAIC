"""Discrete energy diagnostics for finite 1D scalar-field configurations.

This is a declared lattice functional. Unit strings are provenance/contract
labels, not a dimensional-analysis engine; callers remain responsible for
choosing dimensionally compatible coefficients and conventions.
"""
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from mosaic.core.field_configuration import FieldConfiguration1D, LatticeBoundary
from mosaic.core.scalar_potential import ScalarPotential


class ScalarFieldEnergyAssessment(BaseModel):
    """Components of a declared discrete scalar-field energy functional."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    configuration_id: str
    model_id: str
    potential_id: str
    gradient_contribution: Decimal
    potential_contribution: Decimal
    total: Decimal
    energy_unit: str
    kinetic_coefficient_unit: str
    quadrature: str


def assess_discrete_field_energy(
    configuration: FieldConfiguration1D,
    potential: ScalarPotential,
    *,
    kinetic_coefficient: Decimal,
    kinetic_coefficient_unit: str,
) -> ScalarFieldEnergyAssessment:
    """Evaluate E = integral [K/2 (dphi/dx)^2 + V(phi)] dx on the lattice.

    OPEN uses trapezoidal quadrature for V and adjacent edges for the gradient.
    PERIODIC uses a periodic rectangular sum for V and includes the wrap edge.
    The declared potential energy_unit is interpreted as an energy density per
    coordinate unit in this functional. Unit compatibility is caller-declared,
    not automatically derived from unit strings.
    """
    if (
        not isinstance(kinetic_coefficient, Decimal)
        or not kinetic_coefficient.is_finite()
        or kinetic_coefficient < 0
    ):
        raise ValueError("kinetic_coefficient must be a finite nonnegative Decimal")
    if not kinetic_coefficient_unit or not kinetic_coefficient_unit.strip():
        raise ValueError("kinetic_coefficient_unit must be nonblank")

    configuration.validate_against(potential)
    dx = configuration.spacing
    values = configuration.field_values

    differences = [
        right - left for left, right in zip(values, values[1:])
    ]
    if configuration.boundary == LatticeBoundary.PERIODIC:
        differences.append(values[0] - values[-1])

    gradient = sum(
        kinetic_coefficient * difference * difference / (Decimal("2") * dx)
        for difference in differences
    )

    potential_samples = tuple(potential.evaluate(value) for value in values)
    if configuration.boundary == LatticeBoundary.PERIODIC:
        potential_integral = sum(potential_samples) * dx
        quadrature = "PERIODIC_RECTANGULAR"
    else:
        potential_integral = (
            (potential_samples[0] + potential_samples[-1]) / Decimal("2")
            + sum(potential_samples[1:-1])
        ) * dx
        quadrature = "OPEN_TRAPEZOIDAL"

    total = gradient + potential_integral
    if not gradient.is_finite() or not potential_integral.is_finite() or not total.is_finite():
        raise ValueError("discrete energy evaluation exceeded Decimal range")

    return ScalarFieldEnergyAssessment(
        configuration_id=configuration.configuration_id,
        model_id=configuration.model_id,
        potential_id=configuration.potential_id,
        gradient_contribution=gradient,
        potential_contribution=potential_integral,
        total=total,
        energy_unit=potential.energy_unit,
        kinetic_coefficient_unit=kinetic_coefficient_unit,
        quadrature=quadrature,
    )
