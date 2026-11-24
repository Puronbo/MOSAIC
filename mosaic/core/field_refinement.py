"""Fixed-horizon timestep refinement experiments for finite-lattice fields."""
from decimal import Decimal, localcontext

from pydantic import BaseModel, ConfigDict, Field

from mosaic.core.field_configuration import FieldConfiguration1D
from mosaic.core.field_trajectory import FieldTrajectoryResult, evolve_field_trajectory
from mosaic.core.scalar_potential import ScalarPotential


class FieldRefinementLevel(BaseModel):
    """One resolution level and its comparison against the next finer run."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    time_step: Decimal
    step_count: int = Field(ge=1)
    trajectory: FieldTrajectoryResult
    maximum_field_difference_from_finer: Decimal | None
    maximum_velocity_difference_from_finer: Decimal | None
    observed_field_order: Decimal | None
    observed_velocity_order: Decimal | None


class FieldRefinementResult(BaseModel):
    """Ordered fixed-horizon runs with pairwise endpoint errors."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    initial_configuration_id: str
    model_id: str
    potential_id: str
    elapsed_time: Decimal
    time_unit: str
    refinement_ratio: int
    levels: tuple[FieldRefinementLevel, ...]
    interpretation: str


def _max_difference(left: tuple[Decimal, ...], right: tuple[Decimal, ...]) -> Decimal:
    if len(left) != len(right):
        raise ValueError("refinement endpoints have incompatible sample counts")
    return max((abs(a - b) for a, b in zip(left, right)), default=Decimal("0"))


def _observed_order(coarse_error: Decimal | None, fine_error: Decimal | None) -> Decimal | None:
    if coarse_error is None or fine_error is None or coarse_error <= 0 or fine_error <= 0:
        return None
    if coarse_error <= fine_error:
        return None
    with localcontext() as context:
        context.prec += 8
        return (coarse_error / fine_error).ln() / Decimal(2).ln()


def assess_field_timestep_refinement(
    configuration: FieldConfiguration1D,
    potential: ScalarPotential,
    *,
    initial_velocities: tuple[Decimal, ...],
    base_time_step: Decimal,
    refinement_ratio: int,
    levels: int,
    time_unit: str,
    inertia_coefficient: Decimal,
    inertia_coefficient_unit: str,
    velocity_unit: str,
    kinetic_coefficient: Decimal,
    kinetic_coefficient_unit: str,
    output_configuration_id_prefix: str,
) -> FieldRefinementResult:
    """Run geometrically refined steps over exactly the same elapsed horizon.

    Level j uses dt=base_dt/refinement_ratio**j and an integer number of
    steps chosen to preserve the base run's elapsed time. Endpoint errors
    compare adjacent levels. Observed orders are reported only when both
    successive errors are positive and strictly decrease.
    """
    if not isinstance(base_time_step, Decimal) or not base_time_step.is_finite() or base_time_step <= 0:
        raise ValueError("base_time_step must be a finite positive Decimal")
    if isinstance(refinement_ratio, bool) or not isinstance(refinement_ratio, int) or refinement_ratio < 2:
        raise ValueError("refinement_ratio must be an integer of at least 2")
    if isinstance(levels, bool) or not isinstance(levels, int) or not 2 <= levels <= 6:
        raise ValueError("levels must be an integer from 2 through 6")
    if not output_configuration_id_prefix or not output_configuration_id_prefix.strip():
        raise ValueError("output_configuration_id_prefix must be nonblank")

    base_steps = 100
    total_time = base_time_step * base_steps
    raw_runs = []
    for index in range(levels):
        divisor = refinement_ratio ** index
        dt = base_time_step / Decimal(divisor)
        count = base_steps * divisor
        if count > 10000:
            raise ValueError("refinement level exceeds the 10000-step trajectory limit")
        final_configuration, final_velocities, trajectory = evolve_field_trajectory(
            configuration,
            potential,
            initial_velocities=initial_velocities,
            time_step=dt,
            step_count=count,
            time_unit=time_unit,
            inertia_coefficient=inertia_coefficient,
            inertia_coefficient_unit=inertia_coefficient_unit,
            velocity_unit=velocity_unit,
            kinetic_coefficient=kinetic_coefficient,
            kinetic_coefficient_unit=kinetic_coefficient_unit,
            output_configuration_id_prefix=f"{output_configuration_id_prefix}-L{index + 1}",
        )
        raw_runs.append((dt, count, final_configuration, final_velocities, trajectory))

    reports = []
    for index, (dt, count, final_configuration, final_velocities, trajectory) in enumerate(raw_runs):
        if index == len(raw_runs) - 1:
            field_error = velocity_error = None
            field_order = velocity_order = None
        else:
            finer_configuration = raw_runs[index + 1][2]
            finer_velocities = raw_runs[index + 1][3]
            field_error = _max_difference(final_configuration.field_values, finer_configuration.field_values)
            velocity_error = _max_difference(final_velocities, finer_velocities)
            field_order = None
            velocity_order = None
            if index > 0:
                previous = reports[index - 1]
                field_order = _observed_order(previous.maximum_field_difference_from_finer, field_error)
                velocity_order = _observed_order(previous.maximum_velocity_difference_from_finer, velocity_error)
        reports.append(FieldRefinementLevel(
            time_step=dt,
            step_count=count,
            trajectory=trajectory,
            maximum_field_difference_from_finer=field_error,
            maximum_velocity_difference_from_finer=velocity_error,
            observed_field_order=field_order,
            observed_velocity_order=velocity_order,
        ))

    return FieldRefinementResult(
        initial_configuration_id=configuration.configuration_id,
        model_id=configuration.model_id,
        potential_id=configuration.potential_id,
        elapsed_time=total_time,
        time_unit=time_unit,
        refinement_ratio=refinement_ratio,
        levels=tuple(reports),
        interpretation=(
            "Endpoint differences compare adjacent fixed-horizon runs. "
            "Observed order is descriptive only and is omitted unless successive "
            "positive errors decrease; it is not a convergence proof."
        ),
    )
