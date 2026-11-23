"""Explicit inertial evolution for a declared finite 1D scalar field.

This is a finite-dimensional, caller-parameterized mechanical update. It is
not a continuum field equation, relativistic model, or quantum-field solver.
"""
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field

from mosaic.core.field_configuration import FieldConfiguration1D, LatticeBoundary
from mosaic.core.scalar_field_energy import assess_discrete_field_energy
from mosaic.core.scalar_potential import ScalarPotential


class FieldDynamicsResult(BaseModel):
    """One explicit inertial update with auditable initial/final data."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    input_configuration_id: str
    output_configuration_id: str
    model_id: str
    potential_id: str
    time_step: Decimal
    elapsed_time: Decimal
    time_unit: str
    inertia_coefficient: Decimal
    inertia_coefficient_unit: str
    velocity_unit: str
    field_energy_before: Decimal
    field_energy_after: Decimal
    kinetic_energy_before: Decimal
    kinetic_energy_after: Decimal
    total_energy_before: Decimal
    total_energy_after: Decimal
    energy_unit: str
    initial_field_values: tuple[Decimal, ...]
    final_field_values: tuple[Decimal, ...]
    initial_velocities: tuple[Decimal, ...]
    final_velocities: tuple[Decimal, ...]
    scheme: str = "SEMI_IMPLICIT_EULER"


def _energy_gradient(
    configuration: FieldConfiguration1D,
    potential: ScalarPotential,
    coefficient: Decimal,
) -> tuple[Decimal, ...]:
    values = configuration.field_values
    dx = configuration.spacing
    count = len(values)
    gradients = []
    for i, value in enumerate(values):
        if configuration.boundary == LatticeBoundary.PERIODIC:
            laplacian_term = Decimal("2") * value - values[(i - 1) % count] - values[(i + 1) % count]
            weight = Decimal("1")
        elif i == 0:
            laplacian_term = value - values[1]
            weight = Decimal("0.5")
        elif i == count - 1:
            laplacian_term = value - values[i - 1]
            weight = Decimal("0.5")
        else:
            laplacian_term = Decimal("2") * value - values[i - 1] - values[i + 1]
            weight = Decimal("1")
        derivative = coefficient * laplacian_term / dx + dx * weight * potential.first_derivative(value)
        if not derivative.is_finite():
            raise ValueError("discrete energy gradient exceeded Decimal range")
        gradients.append(derivative)
    return tuple(gradients)


def _quadrature_weights(configuration: FieldConfiguration1D) -> tuple[Decimal, ...]:
    if configuration.boundary == LatticeBoundary.PERIODIC:
        return (Decimal("1"),) * len(configuration.field_values)
    return tuple(
        Decimal("0.5") if i in (0, len(configuration.field_values) - 1) else Decimal("1")
        for i in range(len(configuration.field_values))
    )


def evolve_field_configuration(
    configuration: FieldConfiguration1D,
    potential: ScalarPotential,
    *,
    initial_velocities: tuple[Decimal, ...],
    time_step: Decimal,
    time_unit: str,
    inertia_coefficient: Decimal,
    inertia_coefficient_unit: str,
    velocity_unit: str,
    kinetic_coefficient: Decimal,
    kinetic_coefficient_unit: str,
    output_configuration_id: str,
) -> tuple[FieldConfiguration1D, tuple[Decimal, ...], FieldDynamicsResult]:
    """Advance one semi-implicit Euler step with explicit initial velocity.

    v[n+1] = v[n] - dt * grad(E_field) / M
    phi[n+1] = phi[n] + dt * v[n+1]

    The discrete kinetic diagnostic is M/2 * dx * sum(w_i v_i^2),
    with the same open/periodic quadrature convention as the field functional.
    No energy-conservation claim is made for this numerical integrator.
    """
    for name, value in (
        ("time_step", time_step),
        ("inertia_coefficient", inertia_coefficient),
        ("kinetic_coefficient", kinetic_coefficient),
    ):
        if not isinstance(value, Decimal) or not value.is_finite() or value <= 0:
            raise ValueError(f"{name} must be a finite positive Decimal")
    for name, value in (
        ("time_unit", time_unit),
        ("inertia_coefficient_unit", inertia_coefficient_unit),
        ("velocity_unit", velocity_unit),
        ("kinetic_coefficient_unit", kinetic_coefficient_unit),
        ("output_configuration_id", output_configuration_id),
    ):
        if not value or not value.strip():
            raise ValueError(f"{name} must be nonblank")
    if len(initial_velocities) != len(configuration.field_values):
        raise ValueError("initial_velocities must match the lattice sample count")
    if any(not isinstance(v, Decimal) or not v.is_finite() for v in initial_velocities):
        raise ValueError("initial_velocities must be finite Decimals")

    field_before = assess_discrete_field_energy(
        configuration, potential,
        kinetic_coefficient=kinetic_coefficient,
        kinetic_coefficient_unit=kinetic_coefficient_unit,
    )
    gradient = _energy_gradient(configuration, potential, kinetic_coefficient)
    final_velocities = tuple(
        velocity - time_step * force / inertia_coefficient
        for velocity, force in zip(initial_velocities, gradient)
    )
    final_values = tuple(
        value + time_step * velocity
        for value, velocity in zip(configuration.field_values, final_velocities)
    )
    if any(not x.is_finite() for x in (*final_velocities, *final_values)):
        raise ValueError("field update exceeded Decimal range")

    output = FieldConfiguration1D(
        configuration_id=output_configuration_id,
        model_id=configuration.model_id,
        potential_id=configuration.potential_id,
        coordinates=configuration.coordinates,
        field_values=final_values,
        coordinate_unit=configuration.coordinate_unit,
        field_unit=configuration.field_unit,
        boundary=configuration.boundary,
    )
    field_after = assess_discrete_field_energy(
        output, potential,
        kinetic_coefficient=kinetic_coefficient,
        kinetic_coefficient_unit=kinetic_coefficient_unit,
    )
    weights = _quadrature_weights(configuration)
    dx = configuration.spacing
    kinetic_before = inertia_coefficient * dx * sum(
        weight * velocity * velocity
        for weight, velocity in zip(weights, initial_velocities)
    ) / Decimal("2")
    kinetic_after = inertia_coefficient * dx * sum(
        weight * velocity * velocity
        for weight, velocity in zip(weights, final_velocities)
    ) / Decimal("2")
    total_before = field_before.total + kinetic_before
    total_after = field_after.total + kinetic_after
    if any(not x.is_finite() for x in (kinetic_before, kinetic_after, total_before, total_after)):
        raise ValueError("mechanical energy diagnostic exceeded Decimal range")

    result = FieldDynamicsResult(
        input_configuration_id=configuration.configuration_id,
        output_configuration_id=output.configuration_id,
        model_id=configuration.model_id,
        potential_id=configuration.potential_id,
        time_step=time_step,
        elapsed_time=time_step,
        time_unit=time_unit,
        inertia_coefficient=inertia_coefficient,
        inertia_coefficient_unit=inertia_coefficient_unit,
        velocity_unit=velocity_unit,
        field_energy_before=field_before.total,
        field_energy_after=field_after.total,
        kinetic_energy_before=kinetic_before,
        kinetic_energy_after=kinetic_after,
        total_energy_before=total_before,
        total_energy_after=total_after,
        energy_unit=field_before.energy_unit,
        initial_field_values=configuration.field_values,
        final_field_values=final_values,
        initial_velocities=initial_velocities,
        final_velocities=final_velocities,
    )
    return output, final_velocities, result
