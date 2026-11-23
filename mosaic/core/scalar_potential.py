"""Bounded polynomial scalar potentials and local derivative assessments.

This module evaluates a declared one-dimensional potential. Positive curvature
at a stationary point is a local diagnostic, not a complete proof of vacuum
stability, dynamical stability, or physical truth.
"""
from decimal import Decimal, InvalidOperation
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class PolynomialTerm(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    coefficient: Decimal
    power: int = Field(ge=0, le=16)

    @field_validator("coefficient")
    @classmethod
    def finite_coefficient(cls, value: Decimal) -> Decimal:
        if not value.is_finite():
            raise ValueError("polynomial coefficients must be finite")
        return value


class ScalarPotential(BaseModel):
    """A univariate polynomial potential with explicit units and domain."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    potential_id: str = Field(min_length=1, max_length=120)
    model_id: str = Field(min_length=1, max_length=120)
    field_name: str = Field(min_length=1, max_length=80)
    field_unit: str = Field(min_length=1, max_length=40)
    energy_unit: str = Field(min_length=1, max_length=40)
    domain_min: Decimal
    domain_max: Decimal
    terms: tuple[PolynomialTerm, ...] = Field(min_length=1, max_length=32)
    assumptions: tuple[str, ...] = Field(default=(), max_length=20)

    @field_validator("domain_min", "domain_max")
    @classmethod
    def finite_domain(cls, value: Decimal) -> Decimal:
        if not value.is_finite():
            raise ValueError("domain bounds must be finite")
        return value

    @model_validator(mode="after")
    def validate_potential(self):
        if self.domain_min >= self.domain_max:
            raise ValueError("domain_min must be less than domain_max")
        powers = [term.power for term in self.terms]
        if len(powers) != len(set(powers)):
            raise ValueError("polynomial powers must be unique")
        if any(not item.strip() for item in self.assumptions):
            raise ValueError("assumptions must be nonblank")
        return self

    def _evaluate(self, field_value: Decimal, derivative_order: int) -> Decimal:
        if not isinstance(field_value, Decimal) or not field_value.is_finite():
            raise ValueError("field_value must be a finite Decimal")
        if not self.domain_min <= field_value <= self.domain_max:
            raise ValueError("field_value lies outside the declared domain")
        if derivative_order not in (0, 1, 2):
            raise ValueError("only derivative orders 0, 1, and 2 are supported")

        result = Decimal("0")
        for term in self.terms:
            power = term.power
            coefficient = term.coefficient
            if derivative_order == 1:
                if power == 0:
                    continue
                coefficient *= power
                power -= 1
            elif derivative_order == 2:
                if power < 2:
                    continue
                coefficient *= power * (power - 1)
                power -= 2
            result += coefficient * (field_value ** power)
        if not result.is_finite():
            raise ValueError("potential evaluation exceeded Decimal range")
        return result

    def evaluate(self, field_value: Decimal) -> Decimal:
        return self._evaluate(field_value, 0)

    def first_derivative(self, field_value: Decimal) -> Decimal:
        return self._evaluate(field_value, 1)

    def second_derivative(self, field_value: Decimal) -> Decimal:
        return self._evaluate(field_value, 2)


class CurvatureAssessment(StrEnum):
    POSITIVE_CURVATURE = "POSITIVE_CURVATURE"
    NEGATIVE_CURVATURE = "NEGATIVE_CURVATURE"
    NEAR_ZERO_CURVATURE = "NEAR_ZERO_CURVATURE"


class StationaryPointAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    potential_id: str
    model_id: str
    field_value: Decimal
    potential_value: Decimal
    first_derivative: Decimal
    second_derivative: Decimal
    stationarity_tolerance: Decimal
    curvature_tolerance: Decimal
    curvature: CurvatureAssessment
    field_unit: str
    energy_unit: str


def assess_stationary_point(
    potential: ScalarPotential,
    field_value: Decimal,
    *,
    stationarity_tolerance: Decimal = Decimal("0"),
    curvature_tolerance: Decimal = Decimal("0"),
) -> StationaryPointAssessment:
    """Evaluate local derivatives; do not infer global/dynamical stability."""
    for name, tolerance in (
        ("stationarity_tolerance", stationarity_tolerance),
        ("curvature_tolerance", curvature_tolerance),
    ):
        if (
            not isinstance(tolerance, Decimal)
            or not tolerance.is_finite()
            or tolerance < 0
        ):
            raise ValueError(f"{name} must be a finite nonnegative Decimal")

    value = potential.evaluate(field_value)
    first = potential.first_derivative(field_value)
    second = potential.second_derivative(field_value)
    if abs(first) > stationarity_tolerance:
        raise ValueError("field value is not stationary within the given tolerance")

    if second > curvature_tolerance:
        curvature = CurvatureAssessment.POSITIVE_CURVATURE
    elif second < -curvature_tolerance:
        curvature = CurvatureAssessment.NEGATIVE_CURVATURE
    else:
        curvature = CurvatureAssessment.NEAR_ZERO_CURVATURE

    return StationaryPointAssessment(
        potential_id=potential.potential_id,
        model_id=potential.model_id,
        field_value=field_value,
        potential_value=value,
        first_derivative=first,
        second_derivative=second,
        stationarity_tolerance=stationarity_tolerance,
        curvature_tolerance=curvature_tolerance,
        curvature=curvature,
        field_unit=potential.field_unit,
        energy_unit=potential.energy_unit,
    )
