"""Auditable multi-step trajectories for finite-lattice scalar fields."""
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field

from mosaic.core.field_configuration import FieldConfiguration1D
from mosaic.core.field_dynamics import FieldDynamicsResult, evolve_field_configuration
from mosaic.core.scalar_potential import ScalarPotential


class FieldTrajectoryResult(BaseModel):
    """Aggregate diagnostics and the complete ordered sequence of updates."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    initial_configuration_id: str
    final_configuration_id: str
    model_id: str
    potential_id: str
    step_count: int = Field(ge=1)
    time_step: Decimal
    elapsed_time: Decimal
    time_unit: str
    energy_unit: str
    initial_total_energy: Decimal
    final_total_energy: Decimal
    total_energy_drift: Decimal
    relative_total_energy_drift: Decimal | None
    minimum_total_energy: Decimal
    maximum_total_energy: Decimal
    steps: tuple[FieldDynamicsResult, ...]


def evolve_field_trajectory(
    configuration: FieldConfiguration1D,
    potential: ScalarPotential,
    *,
    initial_velocities: tuple[Decimal, ...],
    time_step: Decimal,
    step_count: int,
    time_unit: str,
    inertia_coefficient: Decimal,
    inertia_coefficient_unit: str,
    velocity_unit: str,
    kinetic_coefficient: Decimal,
    kinetic_coefficient_unit: str,
    output_configuration_id_prefix: str,
) -> tuple[FieldConfiguration1D, tuple[Decimal, ...], FieldTrajectoryResult]:
    """Run a fixed-step trajectory, retaining every intermediate update.

    This function does not adapt the time step or claim energy conservation.
    It records drift so callers can perform explicit refinement experiments.
    """
    if isinstance(step_count, bool) or not isinstance(step_count, int) or not 1 <= step_count <= 10000:
        raise ValueError("step_count must be an integer from 1 through 10000")
    if not output_configuration_id_prefix or not output_configuration_id_prefix.strip():
        raise ValueError("output_configuration_id_prefix must be nonblank")
    if not isinstance(time_step, Decimal) or not time_step.is_finite() or time_step <= 0:
        raise ValueError("time_step must be a finite positive Decimal")

    current_configuration = configuration
    current_velocities = initial_velocities
    records: list[FieldDynamicsResult] = []
    for index in range(1, step_count + 1):
        current_configuration, current_velocities, record = evolve_field_configuration(
            current_configuration,
            potential,
            initial_velocities=current_velocities,
            time_step=time_step,
            time_unit=time_unit,
            inertia_coefficient=inertia_coefficient,
            inertia_coefficient_unit=inertia_coefficient_unit,
            velocity_unit=velocity_unit,
            kinetic_coefficient=kinetic_coefficient,
            kinetic_coefficient_unit=kinetic_coefficient_unit,
            output_configuration_id=f"{output_configuration_id_prefix}-{index}",
        )
        records.append(record)

    energies = tuple(record.total_energy_after for record in records)
    initial_energy = records[0].total_energy_before
    final_energy = records[-1].total_energy_after
    drift = final_energy - initial_energy
    if not drift.is_finite():
        raise ValueError("trajectory energy drift exceeded Decimal range")
    relative_drift = None if initial_energy == 0 else drift / abs(initial_energy)
    if relative_drift is not None and not relative_drift.is_finite():
        raise ValueError("relative trajectory energy drift exceeded Decimal range")

    result = FieldTrajectoryResult(
        initial_configuration_id=configuration.configuration_id,
        final_configuration_id=current_configuration.configuration_id,
        model_id=configuration.model_id,
        potential_id=configuration.potential_id,
        step_count=step_count,
        time_step=time_step,
        elapsed_time=time_step * step_count,
        time_unit=time_unit,
        energy_unit=records[0].energy_unit,
        initial_total_energy=initial_energy,
        final_total_energy=final_energy,
        total_energy_drift=drift,
        relative_total_energy_drift=relative_drift,
        minimum_total_energy=min((initial_energy, *energies)),
        maximum_total_energy=max((initial_energy, *energies)),
        steps=tuple(records),
    )
    return current_configuration, current_velocities, result
