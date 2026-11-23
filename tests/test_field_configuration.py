from decimal import Decimal

import pytest
from pydantic import ValidationError

from mosaic.core.field_configuration import FieldConfiguration1D, LatticeBoundary
from mosaic.core.scalar_potential import PolynomialTerm, ScalarPotential


def config(**overrides):
    values = {
        "configuration_id": "profile-1",
        "model_id": "toy-model",
        "potential_id": "quadratic",
        "coordinates": (Decimal("0"), Decimal("1"), Decimal("2")),
        "field_values": (Decimal("0"), Decimal("1"), Decimal("2")),
        "coordinate_unit": "m",
        "field_unit": "phi",
    }
    values.update(overrides)
    return FieldConfiguration1D(**values)


def potential():
    return ScalarPotential(
        potential_id="quadratic",
        model_id="toy-model",
        field_name="phi",
        field_unit="phi",
        energy_unit="energy",
        domain_min=Decimal("-3"),
        domain_max=Decimal("3"),
        terms=(PolynomialTerm(coefficient=Decimal("1"), power=2),),
    )


def test_open_lattice_gradient_functional():
    assert config().discrete_gradient_functional() == Decimal("1")


def test_periodic_lattice_includes_wraparound_edge():
    periodic = config(boundary=LatticeBoundary.PERIODIC)
    assert periodic.discrete_gradient_functional() == Decimal("3")


def test_uniform_spacing_is_required():
    with pytest.raises(ValidationError, match="uniformly spaced"):
        config(coordinates=(Decimal("0"), Decimal("1"), Decimal("3")))


def test_coordinates_must_increase():
    with pytest.raises(ValidationError, match="strictly increasing"):
        config(coordinates=(Decimal("0"), Decimal("0"), Decimal("1")))


def test_sample_counts_must_match():
    with pytest.raises(ValidationError, match="equal lengths"):
        config(field_values=(Decimal("0"), Decimal("1")))


def test_nonfinite_samples_are_rejected():
    with pytest.raises(ValidationError, match="finite Decimals"):
        config(field_values=(Decimal("0"), Decimal("NaN"), Decimal("2")))


def test_configuration_binds_to_its_potential():
    lattice = config()
    lattice.validate_against(potential())


def test_model_or_potential_mismatch_is_rejected():
    with pytest.raises(ValueError, match="model_id"):
        config(model_id="other-model").validate_against(potential())
    with pytest.raises(ValueError, match="potential_id"):
        config(potential_id="other-potential").validate_against(potential())


def test_field_sample_must_be_inside_potential_domain():
    lattice = config(field_values=(Decimal("0"), Decimal("1"), Decimal("4")))
    with pytest.raises(ValueError, match="outside the potential domain"):
        lattice.validate_against(potential())
