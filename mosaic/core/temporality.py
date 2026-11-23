"""Explicit temporal relations for state-changing systems.

A timestamp is a coordinate supplied by a clock, not a definition of time.
This module compares coordinates only within the same declared clock and
keeps causal dependency separate from temporal ordering.
"""
from decimal import Decimal
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator


class TemporalOrder(StrEnum):
    BEFORE = "BEFORE"
    AFTER = "AFTER"
    SAME_COORDINATE = "SAME_COORDINATE"
    INDETERMINATE = "INDETERMINATE"


class TemporalPoint(BaseModel):
    """A clock-relative coordinate with a bounded measurement uncertainty.

    Coordinates are expressed in seconds on the named clock's scale. They are
    not asserted to be universal instants or interchangeable across clocks.
    """
    model_config = ConfigDict(extra="forbid", frozen=True)

    clock_id: str = Field(min_length=1, max_length=120)
    coordinate_seconds: Decimal
    uncertainty_seconds: Decimal = Decimal("0")

    @model_validator(mode="after")
    def validate_measurement(self):
        if not self.coordinate_seconds.is_finite():
            raise ValueError("temporal coordinate must be finite")
        if not self.uncertainty_seconds.is_finite() or self.uncertainty_seconds < 0:
            raise ValueError("uncertainty must be finite and nonnegative")
        return self

    @property
    def lower_bound(self) -> Decimal:
        return self.coordinate_seconds - self.uncertainty_seconds

    @property
    def upper_bound(self) -> Decimal:
        return self.coordinate_seconds + self.uncertainty_seconds


class DurationBounds(BaseModel):
    """A nonnegative duration interval derived from two readings of one clock."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    clock_id: str
    minimum_seconds: Decimal = Field(ge=0)
    maximum_seconds: Decimal = Field(ge=0)


class TemporalEvent(BaseModel):
    """An identified occurrence located relative to a declared clock."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str = Field(min_length=1, max_length=120)
    observed_at: TemporalPoint
    description: str = Field(default="", max_length=500)


class StateTransition(BaseModel):
    """A recorded change between two content-addressed system states."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str = Field(min_length=1, max_length=120)
    source_state_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_state_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def require_actual_change(self):
        if self.source_state_sha256 == self.target_state_sha256:
            raise ValueError("a state transition must change the represented state")
        return self


class CausalLink(BaseModel):
    """A directed causal/dependency claim, not a timestamp comparison."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    source_event_id: str = Field(min_length=1, max_length=120)
    target_event_id: str = Field(min_length=1, max_length=120)
    relation: str = Field(min_length=1, max_length=40)

    @model_validator(mode="after")
    def validate_endpoints(self):
        if self.source_event_id == self.target_event_id:
            raise ValueError("a causal link cannot point from an event to itself")
        return self


def compare_temporal_points(left: TemporalPoint, right: TemporalPoint) -> TemporalOrder:
    """Compare uncertainty intervals, refusing cross-clock assumptions."""
    if left.clock_id != right.clock_id:
        raise ValueError("temporal points from different clocks are not directly comparable")
    if left.upper_bound < right.lower_bound:
        return TemporalOrder.BEFORE
    if left.lower_bound > right.upper_bound:
        return TemporalOrder.AFTER
    if (
        left.uncertainty_seconds == 0
        and right.uncertainty_seconds == 0
        and left.coordinate_seconds == right.coordinate_seconds
    ):
        return TemporalOrder.SAME_COORDINATE
    return TemporalOrder.INDETERMINATE


def duration_bounds(start: TemporalPoint, end: TemporalPoint) -> DurationBounds:
    """Bound elapsed clock-time without pretending uncertain readings are exact."""
    if start.clock_id != end.clock_id:
        raise ValueError("duration requires readings from the same clock")
    minimum = max(
        Decimal("0"),
        end.lower_bound - start.upper_bound,
        start.lower_bound - end.upper_bound,
    )
    maximum = max(
        abs(end.lower_bound - start.upper_bound),
        abs(end.upper_bound - start.lower_bound),
    )
    return DurationBounds(
        clock_id=start.clock_id,
        minimum_seconds=minimum,
        maximum_seconds=maximum,
    )
