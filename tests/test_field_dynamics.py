from decimal import Decimal

import pytest

from mosaic.core.field_configuration import FieldConfiguration1D, LatticeBoundary
from mosaic.core.field_dynamics import evolve_field_configuration
from mosaic.core.scalar_potential import PolynomialTerm, ScalarPotential


def make_potential():
    return ScalarPotential(
        potential_id="quadratic",
        model_id="model",
        field_name="phi",
        field_unit="phi",
        energy_unit="energy-density",
        domain_min=Decimal("-5"),
        domain_max=Decimal("5"),
        terms=(PolynomialTerm(coefficient=Decimal("0.5"), power=2),),
    )


def make_configuration(boundary=LatticeBoundary.OPEN):
    return FieldConfiguration1D(
        configuration_id="initial",
        model_id="model",
        potential_id="quadratic",
        coordinates=(Decimal("0"), Decimal("1"), Decimal("2")),
        field_values=(Decimal("1"),) * 3,
        coordinate_unit="m",
        field_unit="phi",
        boundary=boundary,
    )


def run_step(boundary=LatticeBoundary.OPEN, velocities=None):
    return evolve_field_configuration(
        make_configuration(boundary),
        make_potential(),
        initial_velocities=velocities or (Decimal("0"),) * 3,
        time_step=Decimal("0.1"),
        time_unit="s",
        inertia_coefficient=Decimal("1"),
        inertia_coefficient_unit="declared-inertia",
        velocity_unit="phi/s",
        kinetic_coefficient=Decimal("1"),
        kinetic_coefficient_unit="declared-kinetic",
        output_configuration_id="next",
    )


def test_open_inertial_step_uses_explicit_initial_conditions():
    output, velocities, result = run_step()
    assert velocities == (Decimal("-0.05"), Decimal("-0.1"), Decimal("-0.05"))
    assert output.field_values == (Decimal("0.995"), Decimal("0.99"), Decimal("0.995"))
    assert result.elapsed_time == Decimal("0.1")
    assert result.scheme == "SEMI_IMPLICIT_EULER"
    assert result.total_energy_before == result.field_energy_before


def test_periodic_inertial_step_returns_periodic_configuration():
    output, velocities, result = run_step(LatticeBoundary.PERIODIC)
    assert velocities == (Decimal("-0.1"),) * 3
    assert output.boundary == LatticeBoundary.PERIODIC
    assert result.total_energy_after == result.field_energy_after + result.kinetic_energy_after


def test_inertial_step_requires_velocity_for_each_sample():
    with pytest.raises(ValueError, match="match the lattice"):
        run_step(velocities=(Decimal("0"),))


def test_inertial_step_rejects_nonpositive_time_step():
    with pytest.raises(ValueError, match="time_step"):
        evolve_field_configuration(
            make_configuration(),
            make_potential(),
            initial_velocities=(Decimal("0"),) * 3,
            time_step=Decimal("0"),
            time_unit="s",
            inertia_coefficient=Decimal("1"),
            inertia_coefficient_unit="declared-inertia",
            velocity_unit="phi/s",
            kinetic_coefficient=Decimal("1"),
            kinetic_coefficient_unit="declared-kinetic",
            output_configuration_id="next",
        )
