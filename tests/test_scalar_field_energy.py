from decimal import Decimal

import pytest

from mosaic.core.field_configuration import FieldConfiguration1D, LatticeBoundary
from mosaic.core.scalar_field_energy import assess_discrete_field_energy
from mosaic.core.scalar_potential import PolynomialTerm, ScalarPotential


def make_potential():
    return ScalarPotential(
        potential_id="zero-potential",
        model_id="field-model",
        field_name="phi",
        field_unit="phi",
        energy_unit="energy-density",
        domain_min=Decimal("-5"),
        domain_max=Decimal("5"),
        terms=(PolynomialTerm(coefficient=Decimal("0"), power=0),),
    )


def make_config(boundary=LatticeBoundary.OPEN, field_values=None):
    return FieldConfiguration1D(
        configuration_id="configuration-1",
        model_id="field-model",
        potential_id="zero-potential",
        coordinates=(Decimal("0"), Decimal("1"), Decimal("2")),
        field_values=field_values or (Decimal("0"), Decimal("1"), Decimal("2")),
        coordinate_unit="m",
        field_unit="phi",
        boundary=boundary,
    )


def test_open_lattice_energy_is_gradient_only_for_zero_potential():
    result = assess_discrete_field_energy(
        make_config(),
        make_potential(),
        kinetic_coefficient=Decimal("2"),
        kinetic_coefficient_unit="energy-density * m^2 / phi^2",
    )
    assert result.gradient_contribution == Decimal("2")
    assert result.potential_contribution == Decimal("0")
    assert result.total == Decimal("2")
    assert result.quadrature == "OPEN_TRAPEZOIDAL"


def test_periodic_energy_includes_wraparound_gradient_edge():
    result = assess_discrete_field_energy(
        make_config(LatticeBoundary.PERIODIC),
        make_potential(),
        kinetic_coefficient=Decimal("2"),
        kinetic_coefficient_unit="energy-density * m^2 / phi^2",
    )
    assert result.gradient_contribution == Decimal("6")
    assert result.total == Decimal("6")
    assert result.quadrature == "PERIODIC_RECTANGULAR"


def test_potential_integral_uses_open_trapezoidal_weights():
    constant = ScalarPotential(
        potential_id="constant-density",
        model_id="field-model",
        field_name="phi",
        field_unit="phi",
        energy_unit="energy-density",
        domain_min=Decimal("-5"),
        domain_max=Decimal("5"),
        terms=(PolynomialTerm(coefficient=Decimal("3"), power=0),),
    )
    result = assess_discrete_field_energy(
        make_config(field_values=(Decimal("0"),) * 3, potential_id="constant-density"),
        constant,
        kinetic_coefficient=Decimal("1"),
        kinetic_coefficient_unit="declared-unit",
    )
    assert result.potential_contribution == Decimal("6")
    assert result.total == Decimal("6")


@pytest.mark.parametrize("coefficient", [Decimal("-1"), Decimal("NaN"), Decimal("Infinity")])
def test_invalid_kinetic_coefficient_is_rejected(coefficient):
    with pytest.raises(ValueError, match="finite nonnegative"):
        assess_discrete_field_energy(
            make_config(),
            make_potential(),
            kinetic_coefficient=coefficient,
            kinetic_coefficient_unit="unit",
        )


def test_blank_kinetic_coefficient_unit_is_rejected():
    with pytest.raises(ValueError, match="nonblank"):
        assess_discrete_field_energy(
            make_config(),
            make_potential(),
            kinetic_coefficient=Decimal("1"),
            kinetic_coefficient_unit=" ",
        )


def test_model_binding_is_enforced():
    wrong_model = make_config().model_copy(update={"model_id": "other"})
    with pytest.raises(ValueError, match="model_id"):
        assess_discrete_field_energy(
            wrong_model,
            make_potential(),
            kinetic_coefficient=Decimal("1"),
            kinetic_coefficient_unit="unit",
        )
