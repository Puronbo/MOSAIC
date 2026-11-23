"""Finite one-dimensional scalar-field configurations.

The discrete gradient functional is a lattice quantity, not a continuum
field-theory solver or a physical energy unless a separately declared
dimensionful kinetic coefficient and unit convention are supplied.
"""
from decimal import Decimal
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mosaic.core.scalar_potential import ScalarPotential


class LatticeBoundary(StrEnum):
    OPEN = "OPEN"
    PERIODIC = "PERIODIC"


class FieldConfiguration1D(BaseModel):
    """A uniformly spaced finite 1D lattice and its scalar-field samples."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    configuration_id: str = Field(min_length=1, max_length=120)
    model_id: str = Field(min_length=1, max_length=120)
    potential_id: str = Field(min_length=1, max_length=120)
    coordinates: tuple[Decimal, ...] = Field(min_length=2, max_length=256)
    field_values: tuple[Decimal, ...] = Field(min_length=2, max_length=256)
    coordinate_unit: str = Field(min_length=1, max_length=40)
    field_unit: str = Field(min_length=1, max_length=40)
    boundary: LatticeBoundary = LatticeBoundary.OPEN

    @field_validator("coordinates", "field_values")
    @classmethod
    def finite_samples(cls, values: tuple[Decimal, ...]) -> tuple[Decimal, ...]:
        if any(not isinstance(value, Decimal) or not value.is_finite() for value in values):
            raise ValueError("lattice samples must be finite Decimals")
        return values

    @model_validator(mode="after")
    def validate_lattice(self):
        if len(self.coordinates) != len(self.field_values):
            raise ValueError("coordinates and field_values must have equal lengths")
        spacings = tuple(
            right - left
            for left, right in zip(self.coordinates, self.coordinates[1:])
        )
        if any(spacing <= 0 for spacing in spacings):
            raise ValueError("coordinates must be strictly increasing")
        if any(spacing != spacings[0] for spacing in spacings[1:]):
            raise ValueError("coordinates must be uniformly spaced")
        return self

    @property
    def spacing(self) -> Decimal:
        return self.coordinates[1] - self.coordinates[0]

    def validate_against(self, potential: ScalarPotential) -> None:
        if self.model_id != potential.model_id:
            raise ValueError("field configuration and potential model_id differ")
        if self.potential_id != potential.potential_id:
            raise ValueError("field configuration and potential_id differ")
        if self.field_unit != potential.field_unit:
            raise ValueError("field configuration and potential field_unit differ")
        if any(
            value < potential.domain_min or value > potential.domain_max
            for value in self.field_values
        ):
            raise ValueError("a field sample lies outside the potential domain")

    def discrete_gradient_functional(self) -> Decimal:
        """Return 1/2 sum((delta phi)^2 / delta x) on the declared lattice.

        OPEN sums adjacent pairs. PERIODIC additionally joins the last sample
        to the first, interpreting the ring length as N times the spacing.
        Units are field_unit^2 / coordinate_unit; no kinetic coefficient is
        implied, so this is not labelled physical energy.
        """
        differences = [
            right - left
            for left, right in zip(self.field_values, self.field_values[1:])
        ]
        if self.boundary == LatticeBoundary.PERIODIC:
            differences.append(self.field_values[0] - self.field_values[-1])
        result = sum(
            (difference * difference) / self.spacing
            for difference in differences
        ) / Decimal("2")
        if not result.is_finite():
            raise ValueError("gradient functional exceeded Decimal range")
        return result
