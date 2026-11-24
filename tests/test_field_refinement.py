from decimal import Decimal

import pytest

from mosaic.core.field_configuration import FieldConfiguration1D, LatticeBoundary
from mosaic.core.field_refinement import assess_field_timestep_refinement
from mosaic.core.scalar_potential import PolynomialTerm, ScalarPotential


def make_inputs():
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
    return configuration, potential


def run(levels=3, ratio=2):
    configuration, potential = make_inputs()
    return assess_field_timestep_refinement(
        configuration,
        potential,
        initial_velocities=(Decimal("0"),) * 3,
        base_time_step=Decimal("0.001"),
        refinement_ratio=ratio,
        levels=levels,
        time_unit="s",
        inertia_coefficient=Decimal("1"),
        inertia_coefficient_unit="inertia",
        velocity_unit="phi/s",
        kinetic_coefficient=Decimal("1"),
        kinetic_coefficient_unit="kinetic",
        output_configuration_id_prefix="refine",
    )


def test_refinement_runs_preserve_common_elapsed_horizon():
    result = run()
    assert result.elapsed_time == Decimal("0.100")
    assert [level.step_count for level in result.levels] == [100, 200, 400]
    assert [level.time_step for level in result.levels] == [
        Decimal("0.001"),
        Decimal("0.0005"),
        Decimal("0.00025"),
    ]
    assert all(level.trajectory.elapsed_time == result.elapsed_time for level in result.levels)


def test_refinement_reports_endpoint_errors_and_order_when_available():
    result = run()
    coarse, middle, fine = result.levels
    assert coarse.maximum_field_difference_from_finer is not None
    assert middle.maximum_field_difference_from_finer is not None
    assert fine.maximum_field_difference_from_finer is None
    assert coarse.observed_field_order is None
    assert middle.observed_field_order is not None
    assert middle.observed_field_order > 0


def test_invalid_refinement_ratio_and_level_count_rejected():
    with pytest.raises(ValueError, match="refinement_ratio"):
        run(ratio=1)
    with pytest.raises(ValueError, match="levels"):
        run(levels=1)


def test_refinement_budget_is_bounded():
    with pytest.raises(ValueError, match="10000-step"):
        run(levels=6, ratio=4)
