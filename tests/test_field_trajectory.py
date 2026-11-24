from decimal import Decimal

import pytest

from mosaic.core.field_configuration import FieldConfiguration1D, LatticeBoundary
from mosaic.core.field_trajectory import evolve_field_trajectory
from mosaic.core.scalar_potential import PolynomialTerm, ScalarPotential


def potential():
    return ScalarPotential(
        potential_id="quadratic",
        model_id="model",
        field_name="phi",
        field_unit="phi",
        energy_unit="energy",
        domain_min=Decimal("-10"),
        domain_max=Decimal("10"),
        terms=(PolynomialTerm(coefficient=Decimal("0.5"), power=2),),
    )


def configuration():
    return FieldConfiguration1D(
        configuration_id="initial",
        model_id="model",
        potential_id="quadratic",
        coordinates=(Decimal("0"), Decimal("1"), Decimal("2")),
        field_values=(Decimal("1"), Decimal("0"), Decimal("-1")),
        coordinate_unit="m",
        field_unit="phi",
        boundary=LatticeBoundary.OPEN,
    )


def run(dt, count, prefix):
    return evolve_field_trajectory(
        configuration(),
        potential(),
        initial_velocities=(Decimal("0"),) * 3,
        time_step=dt,
        step_count=count,
        time_unit="s",
        inertia_coefficient=Decimal("1"),
        inertia_coefficient_unit="inertia",
        velocity_unit="phi/s",
        kinetic_coefficient=Decimal("1"),
        kinetic_coefficient_unit="kinetic",
        output_configuration_id_prefix=prefix,
    )


def test_trajectory_retains_each_step_and_energy_diagnostics():
    final, velocities, result = run(Decimal("0.01"), 5, "trajectory")
    assert result.step_count == 5
    assert result.elapsed_time == Decimal("0.05")
    assert len(result.steps) == 5
    assert result.steps[0].input_configuration_id == "initial"
    assert result.steps[-1].output_configuration_id == "trajectory-5"
    assert result.final_configuration_id == final.configuration_id
    assert result.total_energy_drift == result.final_total_energy - result.initial_total_energy
    assert result.minimum_total_energy <= result.maximum_total_energy
    assert len(velocities) == 3


def test_refined_step_size_produces_close_final_configuration():
    coarse, _, _ = run(Decimal("0.01"), 10, "coarse")
    fine, _, _ = run(Decimal("0.005"), 20, "fine")
    differences = tuple(abs(a - b) for a, b in zip(coarse.field_values, fine.field_values))
    assert max(differences) < Decimal("0.001")


def test_zero_initial_energy_has_no_relative_drift_ratio():
    initial = configuration().model_copy(update={"field_values": (Decimal("0"),) * 3})
    _, _, result = evolve_field_trajectory(
        initial,
        potential(),
        initial_velocities=(Decimal("0"),) * 3,
        time_step=Decimal("0.01"),
        step_count=2,
        time_unit="s",
        inertia_coefficient=Decimal("1"),
        inertia_coefficient_unit="inertia",
        velocity_unit="phi/s",
        kinetic_coefficient=Decimal("1"),
        kinetic_coefficient_unit="kinetic",
        output_configuration_id_prefix="zero",
    )
    assert result.initial_total_energy == 0
    assert result.relative_total_energy_drift is None


def test_invalid_step_count_is_rejected():
    with pytest.raises(ValueError, match="step_count"):
        run(Decimal("0.01"), 0, "bad")
