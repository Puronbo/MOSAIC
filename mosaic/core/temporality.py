"""Explicit temporal relations for state-changing systems.

A timestamp is a coordinate supplied by a clock, not a definition of time.
This module compares coordinates only within the same declared clock and
keeps causal dependency separate from temporal ordering.
"""
from __future__ import annotations

from decimal import Decimal
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator




class ClockKind(StrEnum):
    """Semantic role of a clock; kinds are not interchangeable."""
    MONOTONIC = "MONOTONIC"
    CIVIL = "CIVIL"
    PROPER = "PROPER"
    COORDINATE = "COORDINATE"


class ClockDefinition(BaseModel):
    """Declared semantics for a clock that supplies TemporalPoint readings.

    Metadata describes the measurement context; it does not certify clock
    calibration, synchronization, or a physical reference frame.
    """
    model_config = ConfigDict(extra="forbid", frozen=True)

    clock_id: str = Field(min_length=1, max_length=120)
    kind: ClockKind
    unit: str = Field(default="seconds", pattern=r"^seconds$")
    reference_frame: str | None = Field(default=None, min_length=1, max_length=120)
    worldline_id: str | None = Field(default=None, min_length=1, max_length=120)
    timezone: str | None = Field(default=None, min_length=1, max_length=80)

    @model_validator(mode="after")
    def validate_clock_semantics(self):
        if self.kind == ClockKind.COORDINATE and self.reference_frame is None:
            raise ValueError("coordinate time requires an explicit reference_frame")
        if self.kind == ClockKind.PROPER and self.worldline_id is None:
            raise ValueError("proper time requires an explicit worldline_id")
        if self.kind != ClockKind.COORDINATE and self.reference_frame is not None:
            raise ValueError("reference_frame is only valid for coordinate time")
        if self.kind != ClockKind.PROPER and self.worldline_id is not None:
            raise ValueError("worldline_id is only valid for proper time")
        if self.kind == ClockKind.CIVIL and self.timezone is None:
            raise ValueError("civil time requires an explicit timezone")
        if self.kind != ClockKind.CIVIL and self.timezone is not None:
            raise ValueError("timezone is only valid for civil time")
        return self


def validate_clock_point(point: TemporalPoint, clock: ClockDefinition) -> None:
    """Check that a reading names the clock whose semantics are declared."""
    if point.clock_id != clock.clock_id:
        raise ValueError("temporal point clock_id does not match clock definition")


class ClockCalibration(BaseModel):
    """An explicit affine mapping between two clock scales.

    This is declared calibration data, not proof that the clocks were correctly
    calibrated. The mapping is valid only over its stated source-coordinate range.
    """
    model_config = ConfigDict(extra="forbid", frozen=True)

    source_clock_id: str = Field(min_length=1, max_length=120)
    target_clock_id: str = Field(min_length=1, max_length=120)
    offset_seconds: Decimal
    rate: Decimal = Field(gt=0)
    calibration_uncertainty_seconds: Decimal = Field(default=Decimal("0"), ge=0)
    valid_source_min_seconds: Decimal
    valid_source_max_seconds: Decimal

    @model_validator(mode="after")
    def validate_calibration(self):
        values = (
            self.offset_seconds,
            self.rate,
            self.calibration_uncertainty_seconds,
            self.valid_source_min_seconds,
            self.valid_source_max_seconds,
        )
        if not all(value.is_finite() for value in values):
            raise ValueError("calibration values must be finite")
        if self.source_clock_id == self.target_clock_id:
            raise ValueError("calibration must connect distinct clock IDs")
        if self.valid_source_min_seconds > self.valid_source_max_seconds:
            raise ValueError("calibration validity range is reversed")
        return self


def transform_clock_point(
    point: TemporalPoint, calibration: ClockCalibration
) -> TemporalPoint:
    """Map a reading using declared calibration and propagate bounded uncertainty."""
    if point.clock_id != calibration.source_clock_id:
        raise ValueError("temporal point does not match calibration source clock")
    if (
        point.lower_bound < calibration.valid_source_min_seconds
        or point.upper_bound > calibration.valid_source_max_seconds
    ):
        raise ValueError("temporal point uncertainty extends outside calibration range")
    return TemporalPoint(
        clock_id=calibration.target_clock_id,
        coordinate_seconds=(
            calibration.offset_seconds + calibration.rate * point.coordinate_seconds
        ),
        uncertainty_seconds=(
            calibration.rate * point.uncertainty_seconds
            + calibration.calibration_uncertainty_seconds
        ),
    )


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


class IntervalRelation(StrEnum):
    BEFORE = "BEFORE"
    MEETS = "MEETS"
    OVERLAPS = "OVERLAPS"
    STARTS = "STARTS"
    DURING = "DURING"
    FINISHES = "FINISHES"
    EQUALS = "EQUALS"
    FINISHED_BY = "FINISHED_BY"
    CONTAINS = "CONTAINS"
    STARTED_BY = "STARTED_BY"
    OVERLAPPED_BY = "OVERLAPPED_BY"
    MET_BY = "MET_BY"
    AFTER = "AFTER"
    INDETERMINATE = "INDETERMINATE"


class TemporalInterval(BaseModel):
    """A closed interval on one clock, with uncertainty at each endpoint."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    start: TemporalPoint
    end: TemporalPoint

    @model_validator(mode="after")
    def validate_interval(self):
        if self.start.clock_id != self.end.clock_id:
            raise ValueError("interval endpoints must use the same clock")
        if self.start.coordinate_seconds > self.end.coordinate_seconds:
            raise ValueError("interval start cannot follow its end")
        return self


def compare_temporal_intervals(
    left: TemporalInterval, right: TemporalInterval
) -> IntervalRelation:
    """Apply Allen-style interval relations when justified by clock readings.

    Strictly separated uncertainty bounds prove BEFORE/AFTER. For relations
    involving endpoint coincidence or overlap, all four endpoints must be
    exact; otherwise the result is conservatively INDETERMINATE.
    """
    if left.start.clock_id != right.start.clock_id:
        raise ValueError("intervals from different clocks are not directly comparable")

    if left.end.upper_bound < right.start.lower_bound:
        return IntervalRelation.BEFORE
    if right.end.upper_bound < left.start.lower_bound:
        return IntervalRelation.AFTER

    points = (left.start, left.end, right.start, right.end)
    if any(point.uncertainty_seconds != 0 for point in points):
        return IntervalRelation.INDETERMINATE

    a, b = left.start.coordinate_seconds, left.end.coordinate_seconds
    c, d = right.start.coordinate_seconds, right.end.coordinate_seconds

    if a == c and b == d:
        return IntervalRelation.EQUALS
    if b == c:
        return IntervalRelation.MEETS
    if d == a:
        return IntervalRelation.MET_BY
    if a == c and b < d:
        return IntervalRelation.STARTS
    if a == c and b > d:
        return IntervalRelation.STARTED_BY
    if a > c and b < d:
        return IntervalRelation.DURING
    if a < c and b > d:
        return IntervalRelation.CONTAINS
    if b == d and a > c:
        return IntervalRelation.FINISHES
    if b == d and a < c:
        return IntervalRelation.FINISHED_BY
    if a < c < b < d:
        return IntervalRelation.OVERLAPS
    if c < a < d < b:
        return IntervalRelation.OVERLAPPED_BY
    if b < c:
        return IntervalRelation.BEFORE
    if d < a:
        return IntervalRelation.AFTER
    return IntervalRelation.INDETERMINATE


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


class PartialOrderRelation(StrEnum):
    BEFORE = "BEFORE"
    AFTER = "AFTER"
    SAME_EVENT = "SAME_EVENT"
    INCOMPARABLE = "INCOMPARABLE"


class EventOrderGraph(BaseModel):
    """A finite partial order over events, independent of clock coordinates.

    An edge (A, B) asserts A precedes B. Transitive consequences are inferred;
    missing paths mean incomparable, not simultaneous.
    """
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_ids: tuple[str, ...] = Field(min_length=1, max_length=500)
    precedes: tuple[tuple[str, str], ...] = Field(default=(), max_length=2000)

    @model_validator(mode="after")
    def validate_partial_order(self):
        nodes = set(self.event_ids)
        if len(nodes) != len(self.event_ids):
            raise ValueError("event_ids must be unique")
        adjacency = {node: set() for node in nodes}
        for source, target in self.precedes:
            if source not in nodes or target not in nodes:
                raise ValueError("precedence edge references an unknown event")
            if source == target:
                raise ValueError("an event cannot precede itself")
            adjacency[source].add(target)

        temporary = set()
        permanent = set()

        def visit(node):
            if node in permanent:
                return
            if node in temporary:
                raise ValueError("precedence graph contains a cycle")
            temporary.add(node)
            for target in adjacency[node]:
                visit(target)
            temporary.remove(node)
            permanent.add(node)

        for node in nodes:
            visit(node)
        return self


def compare_event_order(
    graph: EventOrderGraph, left_event_id: str, right_event_id: str
) -> PartialOrderRelation:
    """Return the relation implied by graph reachability, not timestamps."""
    nodes = set(graph.event_ids)
    if left_event_id not in nodes or right_event_id not in nodes:
        raise ValueError("both event IDs must belong to the order graph")
    if left_event_id == right_event_id:
        return PartialOrderRelation.SAME_EVENT

    adjacency = {node: set() for node in nodes}
    for source, target in graph.precedes:
        adjacency[source].add(target)

    def reachable(source, target):
        pending = [source]
        visited = set()
        while pending:
            current = pending.pop()
            if current == target:
                return True
            if current in visited:
                continue
            visited.add(current)
            pending.extend(adjacency[current] - visited)
        return False

    if reachable(left_event_id, right_event_id):
        return PartialOrderRelation.BEFORE
    if reachable(right_event_id, left_event_id):
        return PartialOrderRelation.AFTER
    return PartialOrderRelation.INCOMPARABLE


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



class EventOccurrence(BaseModel):
    """A claim about when an event happened, independent of its observation."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str = Field(min_length=1, max_length=120)
    occurred_during: TemporalInterval
    description: str = Field(default="", max_length=500)


class EventObservation(BaseModel):
    """An observer's measurement and subsequent recording of an event.

    measurement_at is when the observer/instrument registered evidence;
    recorded_at is when that evidence entered the record. Neither is silently
    substituted for the event's occurrence interval.
    """
    model_config = ConfigDict(extra="forbid", frozen=True)

    observation_id: str = Field(min_length=1, max_length=120)
    event_id: str = Field(min_length=1, max_length=120)
    observer_id: str = Field(min_length=1, max_length=120)
    measurement_at: TemporalPoint
    recorded_at: TemporalPoint
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class EventKnowledge(BaseModel):
    """A record that a recipient learned of an event at a particular clock point.

    Learning time is an epistemic timestamp. It is not an occurrence time and
    need not share a clock with the event or its measurement.
    """
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str = Field(min_length=1, max_length=120)
    recipient_id: str = Field(min_length=1, max_length=120)
    learned_at: TemporalPoint
    source_observation_id: str = Field(min_length=1, max_length=120)


class CausalEvidencePolarity(StrEnum):
    SUPPORTS = "SUPPORTS"
    CHALLENGES = "CHALLENGES"


class CausalEvidenceMethod(StrEnum):
    OBSERVATIONAL = "OBSERVATIONAL"
    INTERVENTIONAL = "INTERVENTIONAL"
    COUNTERFACTUAL = "COUNTERFACTUAL"
    MECHANISTIC = "MECHANISTIC"
    OTHER = "OTHER"


class CausalEvidence(BaseModel):
    """A provenance-bound item bearing on a causal hypothesis.

    Polarity records how the submitter interprets the evidence; it is not a
    machine-verified conclusion. A digest protects identity, not truth.
    """
    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_id: str = Field(min_length=1, max_length=120)
    polarity: CausalEvidencePolarity
    method: CausalEvidenceMethod
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    description: str = Field(min_length=1, max_length=1000)
    assumptions: tuple[str, ...] = Field(default=(), max_length=20)


class CausalHypothesis(BaseModel):
    """A falsifiable causal proposal kept distinct from temporal precedence.

    Evidence may support or challenge the proposal. The model deliberately
    does not calculate a truth value or promote a hypothesis to a proof.
    """
    model_config = ConfigDict(extra="forbid", frozen=True)

    hypothesis_id: str = Field(min_length=1, max_length=120)
    cause_event_id: str = Field(min_length=1, max_length=120)
    effect_event_id: str = Field(min_length=1, max_length=120)
    relation: str = Field(min_length=1, max_length=80)
    evidence: tuple[CausalEvidence, ...] = Field(default=(), max_length=100)
    alternative_explanations: tuple[str, ...] = Field(default=(), max_length=20)
    proposed_counterfactual: str | None = Field(default=None, max_length=1000)

    @model_validator(mode="after")
    def validate_hypothesis(self):
        if self.cause_event_id == self.effect_event_id:
            raise ValueError("a causal hypothesis must connect distinct events")
        evidence_ids = [item.evidence_id for item in self.evidence]
        if len(set(evidence_ids)) != len(evidence_ids):
            raise ValueError("causal evidence IDs must be unique")
        if any(not item.strip() for item in self.alternative_explanations):
            raise ValueError("alternative explanations cannot be blank")
        return self
