from decimal import Decimal

import pytest
from pydantic import ValidationError

from mosaic.core.scalar_potential import (
    CurvatureAssessment,
    PolynomialTerm,
    ScalarPotential,
    assess_stationary_point,
)


def potential(terms):
    return ScalarPotential(
        potential_id="double-well",
        model_id="toy-scalar-model",
        field_name="phi",
        field_unit="field units",
        energy_unit="energy units",
        domain_min=Decimal("-3"),
        domain_max=Decimal("3"),
        terms=tuple(
            PolynomialTerm(coefficient=Decimal(coefficient), power=power)
            for coefficient, power in terms
        ),
    )


def test_evaluates_polynomial_and_derivatives():
    model = potential([("1", 4), ("-2", 2), ("1", 0)])
    x = Decimal("2")
    assert model.evaluate(x) == Decimal("9")
    assert model.first_derivative(x) == Decimal("24")
    assert model.second_derivative(x) == Decimal("44")


def test_positive_curvature_at_stationary_point():
    model = potential([("1", 2), ("0", 0)])
    result = assess_stationary_point(model, Decimal("0"))
    assert result.curvature == CurvatureAssessment.POSITIVE_CURVATURE
    assert result.first_derivative == 0


def test_negative_curvature_at_stationary_point():
    model = potential([("-1", 2), ("0", 0)])
    result = assess_stationary_point(model, Decimal("0"))
    assert result.curvature == CurvatureAssessment.NEGATIVE_CURVATURE


def test_zero_curvature_is_not_called_stable():
    model = potential([("1", 4), ("0", 0)])
    result = assess_stationary_point(model, Decimal("0"))
    assert result.curvature == CurvatureAssessment.NEAR_ZERO_CURVATURE


def test_rejects_nonstationary_point():
    model = potential([("1", 2), ("0", 0)])
    with pytest.raises(ValueError, match="not stationary"):
        assess_stationary_point(model, Decimal("1"))


def test_stationarity_tolerance_is_explicit():
    model = potential([("1", 2), ("0", 0)])
    result = assess_stationary_point(
        model,
        Decimal("0.0001"),
        stationarity_tolerance=Decimal("0.001"),
    )
    assert result.first_derivative == Decimal("0.0002")


def test_rejects_out_of_domain_value():
    model = potential([("1", 2)])
    with pytest.raises(ValueError, match="outside"):
        model.evaluate(Decimal("4"))


def test_rejects_duplicate_powers():
    with pytest.raises(ValidationError):
        potential([("1", 2), ("2", 2)])


def test_rejects_invalid_domain():
    with pytest.raises(ValidationError):
        ScalarPotential(
            potential_id="bad",
            model_id="m",
            field_name="phi",
            field_unit="u",
            energy_unit="e",
            domain_min=Decimal("2"),
            domain_max=Decimal("1"),
            terms=(PolynomialTerm(coefficient=Decimal("1"), power=2),),
        )


def test_rejects_negative_tolerance():
    model = potential([("1", 2)])
    with pytest.raises(ValueError, match="nonnegative"):
        assess_stationary_point(
            model,
            Decimal("0"),
            curvature_tolerance=Decimal("-1"),
        )
