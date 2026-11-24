from decimal import Decimal

from mosaic.core.field_configuration import FieldConfiguration1D, LatticeBoundary
from mosaic.core.field_stability import (
    FieldStabilityStatus,
    assess_field_time_step,
)
from mosaic.core.scalar_potential import PolynomialTerm, ScalarPotential


def make_potential(coefficient=Decimal("0.5")):
    return ScalarPotential(
        potential_id="quadratic",
        model_id="model",
        field_name="phi",
        field_unit="phi",
        energy_unit="energy",
        domain_min=Decimal("-2"),
        domain_max=Decimal("2"),
        terms=(PolynomialTerm(coefficient=coefficient, power=2),),
    )


def make_configuration(boundary=LatticeBoundary.OPEN):
    return FieldConfiguration1D(
        configuration_id="config",
        model_id="model",
        potential_id="quadratic",
        coordinates=(Decimal("0"), Decimal("1"), Decimal("2")),
        field_values=(Decimal("0"),) * 3,
        coordinate_unit="m",
        field_unit="phi",
        boundary=boundary,
    )


def assess(boundary=LatticeBoundary.OPEN, dt=Decimal("0.1"), potential=None):
    return assess_field_time_step(
        make_configuration(boundary),
        potential or make_potential(),
        kinetic_coefficient=Decimal("1"),
        inertia_coefficient=Decimal("1"),
        time_step=dt,
    )


def test_open_lattice_conservative_bound():
    result = assess()
    assert result.status == FieldStabilityStatus.CERTIFIED_WITHIN_BOUND
    assert result.maximum_squared_frequency_bound == Decimal("9")
    assert result.lower_bound_potential_curvature == Decimal("1")
    assert result.time_step_upper_bound is not None
    assert result.time_step < result.time_step_upper_bound


def test_periodic_lattice_uses_periodic_weight_bound():
    result = assess(LatticeBoundary.PERIODIC)
    assert result.status == FieldStabilityStatus.CERTIFIED_WITHIN_BOUND
    assert result.maximum_squared_frequency_bound == Decimal("5")


def test_time_step_at_or_above_bound_is_not_certified():
    result = assess(dt=Decimal("1"))
    assert result.status == FieldStabilityStatus.TIME_STEP_EXCEEDS_BOUND


def test_negative_potential_curvature_prevents_certification():
    result = assess(potential=make_potential(Decimal("-0.5")))
    assert result.status == FieldStabilityStatus.NOT_CERTIFIED_NONCONVEX_DOMAIN
    assert result.time_step_upper_bound is None


def test_configuration_and_potential_must_match():
    other = make_potential()
    other = other.model_copy(update={"model_id": "other-model"})
    try:
        assess(potential=other)
    except ValueError as error:
        assert "model_id" in str(error)
    else:
        raise AssertionError("mismatched model should be rejected")
