from decimal import Decimal

import pytest

from mosaic.core.field_configuration import FieldConfiguration1D, LatticeBoundary
from mosaic.core.field_relaxation import relax_field_configuration
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
        configuration_id="input",
        model_id="model",
        potential_id="quadratic",
        coordinates=(Decimal("0"), Decimal("1"), Decimal("2")),
        field_values=(Decimal("1"), Decimal("1"), Decimal("1")),
        coordinate_unit="m",
        field_unit="phi",
        boundary=boundary,
    )


def test_open_gradient_flow_reduces_discrete_energy():
    output, result = relax_field_configuration(
        make_configuration(),
        make_potential(),
        kinetic_coefficient=Decimal("1"),
        kinetic_coefficient_unit="declared",
        initial_step_size=Decimal("0.1"),
        mobility_unit="iteration-unit",
        output_configuration_id="output",
    )
    assert result.energy_after < result.energy_before
    assert result.status == "ENERGY_DECREASED"
    assert output.field_values == (Decimal("0.95"), Decimal("0.9"), Decimal("0.95"))
    assert result.iteration_index == 0
    assert result.backtracking_steps == 0


def test_periodic_gradient_flow_reduces_energy():
    output, result = relax_field_configuration(
        make_configuration(LatticeBoundary.PERIODIC),
        make_potential(),
        kinetic_coefficient=Decimal("1"),
        kinetic_coefficient_unit="declared",
        initial_step_size=Decimal("0.1"),
        mobility_unit="iteration-unit",
        output_configuration_id="periodic-output",
        iteration_index=3,
    )
    assert output.field_values == (Decimal("0.9"),) * 3
    assert result.energy_after < result.energy_before
    assert result.iteration_index == 3


def test_relaxation_rejects_nonpositive_step_size():
    with pytest.raises(ValueError, match="initial_step_size"):
        relax_field_configuration(
            make_configuration(),
            make_potential(),
            kinetic_coefficient=Decimal("1"),
            kinetic_coefficient_unit="declared",
            initial_step_size=Decimal("0"),
            mobility_unit="iteration-unit",
            output_configuration_id="output",
        )


def test_relaxation_rejects_blank_mobility_unit():
    with pytest.raises(ValueError, match="mobility_unit"):
        relax_field_configuration(
            make_configuration(),
            make_potential(),
            kinetic_coefficient=Decimal("1"),
            kinetic_coefficient_unit="declared",
            initial_step_size=Decimal("0.1"),
            mobility_unit=" ",
            output_configuration_id="output",
        )
