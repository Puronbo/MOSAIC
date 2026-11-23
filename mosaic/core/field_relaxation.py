"""Bounded algorithmic gradient-flow steps for finite 1D scalar fields.

The iteration index is an optimization coordinate, not physical time. This
module performs a discrete energy descent step; it is not a field equation
solver or a claim about real-time dynamics.
"""
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field

from mosaic.core.field_configuration import FieldConfiguration1D, LatticeBoundary
from mosaic.core.scalar_field_energy import assess_discrete_field_energy
from mosaic.core.scalar_potential import ScalarPotential


class FieldRelaxationResult(BaseModel):
    """Auditable result of one backtracking gradient-descent iteration."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    input_configuration_id: str
    output_configuration_id: str
    model_id: str
    potential_id: str
    iteration_index: int = Field(ge=0)
    energy_before: Decimal
    energy_after: Decimal
    energy_unit: str
    accepted_step_size: Decimal
    mobility_unit: str
    backtracking_steps: int = Field(ge=0)
    field_values_before: tuple[Decimal, ...]
    field_values_after: tuple[Decimal, ...]
    status: str


def _discrete_energy_gradient(
    configuration: FieldConfiguration1D,
    potential: ScalarPotential,
    kinetic_coefficient: Decimal,
) -> tuple[Decimal, ...]:
    """Exact derivative of the declared discrete functional w.r.t. samples."""
    values = configuration.field_values
    dx = configuration.spacing
    count = len(values)
    result = []
    for index, value in enumerate(values):
        if configuration.boundary == LatticeBoundary.PERIODIC:
            previous = values[(index - 1) % count]
            following = values[(index + 1) % count]
            gradient_part = kinetic_coefficient * (
                Decimal("2") * value - previous - following
            ) / dx
            potential_weight = Decimal("1")
        else:
            if index == 0:
                gradient_part = kinetic_coefficient * (value - values[1]) / dx
                potential_weight = Decimal("0.5")
            elif index == count - 1:
                gradient_part = kinetic_coefficient * (value - values[index - 1]) / dx
                potential_weight = Decimal("0.5")
            else:
                gradient_part = kinetic_coefficient * (
                    Decimal("2") * value - values[index - 1] - values[index + 1]
                ) / dx
                potential_weight = Decimal("1")
        potential_part = dx * potential_weight * potential.first_derivative(value)
        derivative = gradient_part + potential_part
        if not derivative.is_finite():
            raise ValueError("discrete energy gradient exceeded Decimal range")
        result.append(derivative)
    return tuple(result)


def relax_field_configuration(
    configuration: FieldConfiguration1D,
    potential: ScalarPotential,
    *,
    kinetic_coefficient: Decimal,
    kinetic_coefficient_unit: str,
    initial_step_size: Decimal,
    mobility_unit: str,
    output_configuration_id: str,
    iteration_index: int = 0,
    max_backtracking_steps: int = 24,
) -> tuple[FieldConfiguration1D, FieldRelaxationResult]:
    """Attempt one energy-decreasing gradient-flow step with backtracking.

    The update is phi_new = phi_old - eta * grad(E). The positive step size
    eta and its unit are caller-declared. Backtracking halves eta until the
    evaluated discrete energy does not increase or the search budget ends.
    """
    for name, value in (
        ("kinetic_coefficient", kinetic_coefficient),
        ("initial_step_size", initial_step_size),
    ):
        if not isinstance(value, Decimal) or not value.is_finite() or value <= 0:
            raise ValueError(f"{name} must be a finite positive Decimal")
    if not kinetic_coefficient_unit.strip():
        raise ValueError("kinetic_coefficient_unit must be nonblank")
    if not mobility_unit.strip():
        raise ValueError("mobility_unit must be nonblank")
    if not output_configuration_id.strip():
        raise ValueError("output_configuration_id must be nonblank")
    if iteration_index < 0:
        raise ValueError("iteration_index must be nonnegative")
    if not 0 <= max_backtracking_steps <= 64:
        raise ValueError("max_backtracking_steps must be between 0 and 64")

    before = assess_discrete_field_energy(
        configuration, potential,
        kinetic_coefficient=kinetic_coefficient,
        kinetic_coefficient_unit=kinetic_coefficient_unit,
    )
    gradient = _discrete_energy_gradient(configuration, potential, kinetic_coefficient)
    step = initial_step_size

    for backtracks in range(max_backtracking_steps + 1):
        candidate_values = tuple(
            value - step * derivative
            for value, derivative in zip(configuration.field_values, gradient)
        )
        try:
            candidate = FieldConfiguration1D(
                configuration_id=output_configuration_id,
                model_id=configuration.model_id,
                potential_id=configuration.potential_id,
                coordinates=configuration.coordinates,
                field_values=candidate_values,
                coordinate_unit=configuration.coordinate_unit,
                field_unit=configuration.field_unit,
                boundary=configuration.boundary,
            )
            after = assess_discrete_field_energy(
                candidate, potential,
                kinetic_coefficient=kinetic_coefficient,
                kinetic_coefficient_unit=kinetic_coefficient_unit,
            )
        except (ValueError, ArithmeticError):
            step /= Decimal("2")
            continue

        if after.total <= before.total:
            status = "UNCHANGED" if after.total == before.total else "ENERGY_DECREASED"
            return candidate, FieldRelaxationResult(
                input_configuration_id=configuration.configuration_id,
                output_configuration_id=candidate.configuration_id,
                model_id=configuration.model_id,
                potential_id=configuration.potential_id,
                iteration_index=iteration_index,
                energy_before=before.total,
                energy_after=after.total,
                energy_unit=before.energy_unit,
                accepted_step_size=step,
                mobility_unit=mobility_unit,
                backtracking_steps=backtracks,
                field_values_before=configuration.field_values,
                field_values_after=candidate.field_values,
                status=status,
            )
        step /= Decimal("2")

    raise ValueError("no non-increasing energy step found within backtracking budget")
