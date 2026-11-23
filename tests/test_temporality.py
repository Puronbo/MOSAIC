from decimal import Decimal

import pytest
from pydantic import ValidationError

from mosaic.core.temporality import (
    CausalLink,
    EventOrderGraph,
    PartialOrderRelation,
    compare_event_order,
    StateTransition,
    TemporalEvent,
    TemporalOrder,
    TemporalPoint,
    compare_temporal_points,
    duration_bounds,
)


def point(value, uncertainty="0", clock="monotonic-A"):
    return TemporalPoint(
        clock_id=clock,
        coordinate_seconds=Decimal(value),
        uncertainty_seconds=Decimal(uncertainty),
    )


def test_temporal_order_is_clock_relative():
    assert compare_temporal_points(point("1"), point("2")) == TemporalOrder.BEFORE
    assert compare_temporal_points(point("2"), point("1")) == TemporalOrder.AFTER
    assert compare_temporal_points(point("2"), point("2")) == TemporalOrder.SAME_COORDINATE


def test_uncertainty_can_make_order_indeterminate():
    assert compare_temporal_points(
        point("10", "1"), point("11", "1")
    ) == TemporalOrder.INDETERMINATE
    assert compare_temporal_points(
        point("10", "0.1"), point("11", "0.1")
    ) == TemporalOrder.BEFORE


def test_cross_clock_comparison_is_rejected():
    with pytest.raises(ValueError, match="different clocks"):
        compare_temporal_points(point("1", clock="A"), point("2", clock="B"))


def test_duration_bounds_include_measurement_uncertainty():
    bounds = duration_bounds(point("10", "1"), point("15", "2"))
    assert bounds.minimum_seconds == Decimal("2")
    assert bounds.maximum_seconds == Decimal("8")
    assert bounds.clock_id == "monotonic-A"


def test_duration_bounds_can_include_zero_for_overlapping_readings():
    bounds = duration_bounds(point("10", "2"), point("11", "2"))
    assert bounds.minimum_seconds == Decimal("0")
    assert bounds.maximum_seconds == Decimal("5")


def test_temporal_uncertainty_must_be_finite_and_nonnegative():
    with pytest.raises(ValidationError):
        point("1", "-0.1")
    with pytest.raises(ValidationError):
        point("1", "NaN")


def test_causal_links_are_separate_directed_claims():
    link = CausalLink(
        source_event_id="event-A",
        target_event_id="event-B",
        relation="enables",
    )
    assert link.source_event_id == "event-A"
    with pytest.raises(ValidationError):
        CausalLink(
            source_event_id="event-A",
            target_event_id="event-A",
            relation="causes",
        )



def test_events_are_clock_located_and_transitions_record_state_change():
    event = TemporalEvent(
        event_id="event-1",
        observed_at=point("42.5"),
        description="system state updated",
    )
    transition = StateTransition(
        event_id=event.event_id,
        source_state_sha256="a" * 64,
        target_state_sha256="b" * 64,
    )
    assert transition.event_id == event.event_id
    with pytest.raises(ValidationError):
        StateTransition(
            event_id="event-1",
            source_state_sha256="a" * 64,
            target_state_sha256="a" * 64,
        )



def test_partial_order_infers_transitive_precedence_and_incomparability():
    graph = EventOrderGraph(
        event_ids=("A", "B", "C", "D"),
        precedes=(("A", "B"), ("B", "C")),
    )
    assert compare_event_order(graph, "A", "C") == PartialOrderRelation.BEFORE
    assert compare_event_order(graph, "C", "A") == PartialOrderRelation.AFTER
    assert compare_event_order(graph, "A", "D") == PartialOrderRelation.INCOMPARABLE
    assert compare_event_order(graph, "B", "B") == PartialOrderRelation.SAME_EVENT


def test_partial_order_does_not_treat_incomparability_as_simultaneity():
    graph = EventOrderGraph(
        event_ids=("independent-A", "independent-B"),
        precedes=(),
    )
    assert compare_event_order(
        graph, "independent-A", "independent-B"
    ) == PartialOrderRelation.INCOMPARABLE


def test_partial_order_rejects_cycles_unknown_nodes_and_duplicate_nodes():
    with pytest.raises(ValidationError, match="cycle"):
        EventOrderGraph(
            event_ids=("A", "B", "C"),
            precedes=(("A", "B"), ("B", "C"), ("C", "A")),
        )
    with pytest.raises(ValidationError, match="unknown event"):
        EventOrderGraph(event_ids=("A",), precedes=(("A", "B"),))
    with pytest.raises(ValidationError, match="unique"):
        EventOrderGraph(event_ids=("A", "A"))


def test_partial_order_comparison_rejects_unregistered_event():
    graph = EventOrderGraph(event_ids=("A", "B"))
    with pytest.raises(ValueError, match="belong"):
        compare_event_order(graph, "A", "C")




def interval(start, end, clock="monotonic-A"):
    from mosaic.core.temporality import TemporalInterval

    return TemporalInterval(start=point(str(start), clock=clock), end=point(str(end), clock=clock))


@pytest.mark.parametrize(
    "left,right,expected",
    [
        ((1, 2), (3, 4), "BEFORE"),
        ((1, 3), (3, 5), "MEETS"),
        ((1, 4), (3, 6), "OVERLAPS"),
        ((1, 3), (1, 5), "STARTS"),
        ((2, 3), (1, 5), "DURING"),
        ((2, 5), (1, 5), "FINISHES"),
        ((1, 5), (1, 5), "EQUALS"),
        ((1, 5), (2, 5), "FINISHED_BY"),
        ((1, 6), (2, 5), "CONTAINS"),
        ((1, 5), (1, 3), "STARTED_BY"),
        ((3, 6), (1, 4), "OVERLAPPED_BY"),
        ((3, 5), (1, 3), "MET_BY"),
        ((4, 5), (1, 3), "AFTER"),
    ],
)
def test_exact_temporal_intervals_use_allen_relations(left, right, expected):
    from mosaic.core.temporality import IntervalRelation, compare_temporal_intervals

    assert compare_temporal_intervals(
        interval(*left), interval(*right)
    ) == IntervalRelation(expected)


def test_uncertain_interval_order_is_only_asserted_when_bounds_separate():
    from mosaic.core.temporality import (
        IntervalRelation,
        TemporalInterval,
        compare_temporal_intervals,
    )

    definitely_before = TemporalInterval(
        start=point("1", "0.1"),
        end=point("2", "0.1"),
    )
    later = TemporalInterval(
        start=point("3", "0.1"),
        end=point("4", "0.1"),
    )
    uncertain_overlap = TemporalInterval(
        start=point("1", "0.2"),
        end=point("3", "0.2"),
    )
    overlapping = TemporalInterval(
        start=point("2.9", "0.2"),
        end=point("4", "0.2"),
    )
    assert compare_temporal_intervals(
        definitely_before, later
    ) == IntervalRelation.BEFORE
    assert compare_temporal_intervals(
        uncertain_overlap, overlapping
    ) == IntervalRelation.INDETERMINATE


def test_temporal_intervals_reject_cross_clock_endpoints_and_comparisons():
    from mosaic.core.temporality import TemporalInterval, compare_temporal_intervals

    with pytest.raises(ValidationError, match="same clock"):
        TemporalInterval(start=point("1"), end=point("2", clock="other"))
    with pytest.raises(ValueError, match="different clocks"):
        compare_temporal_intervals(interval(1, 2), interval(3, 4, clock="other"))


def test_temporal_interval_rejects_reversed_endpoints():
    from mosaic.core.temporality import TemporalInterval

    with pytest.raises(ValidationError, match="cannot follow"):
        TemporalInterval(start=point("3"), end=point("2"))

def test_clock_calibration_transforms_coordinates_and_propagates_uncertainty():
    from mosaic.core.temporality import ClockCalibration, transform_clock_point

    calibration = ClockCalibration(
        source_clock_id="device-A",
        target_clock_id="reference-B",
        offset_seconds=Decimal("100"),
        rate=Decimal("2"),
        calibration_uncertainty_seconds=Decimal("0.05"),
        valid_source_min_seconds=Decimal("0"),
        valid_source_max_seconds=Decimal("10"),
    )
    transformed = transform_clock_point(
        point("5", "0.1", clock="device-A"), calibration
    )
    assert transformed.clock_id == "reference-B"
    assert transformed.coordinate_seconds == Decimal("110")
    assert transformed.uncertainty_seconds == Decimal("0.25")


def test_clock_calibration_rejects_wrong_source_and_out_of_range_readings():
    from mosaic.core.temporality import ClockCalibration, transform_clock_point

    calibration = ClockCalibration(
        source_clock_id="device-A",
        target_clock_id="reference-B",
        offset_seconds=Decimal("0"),
        rate=Decimal("1"),
        valid_source_min_seconds=Decimal("0"),
        valid_source_max_seconds=Decimal("10"),
    )
    with pytest.raises(ValueError, match="source clock"):
        transform_clock_point(point("5", clock="other"), calibration)
    with pytest.raises(ValueError, match="outside calibration range"):
        transform_clock_point(point("10", "0.1", clock="device-A"), calibration)


def test_clock_calibration_requires_finite_values_and_valid_range():
    from mosaic.core.temporality import ClockCalibration

    with pytest.raises(ValidationError):
        ClockCalibration(
            source_clock_id="A",
            target_clock_id="B",
            offset_seconds=Decimal("NaN"),
            rate=Decimal("1"),
            valid_source_min_seconds=Decimal("0"),
            valid_source_max_seconds=Decimal("1"),
        )
    with pytest.raises(ValidationError, match="reversed"):
        ClockCalibration(
            source_clock_id="A",
            target_clock_id="B",
            offset_seconds=Decimal("0"),
            rate=Decimal("1"),
            valid_source_min_seconds=Decimal("2"),
            valid_source_max_seconds=Decimal("1"),
        )

def test_clock_definitions_make_time_semantics_explicit():
    from mosaic.core.temporality import ClockDefinition, ClockKind, validate_clock_point

    monotonic = ClockDefinition(clock_id="process-1", kind=ClockKind.MONOTONIC)
    civil = ClockDefinition(
        clock_id="wall-1", kind=ClockKind.CIVIL, timezone="Asia/Manila"
    )
    proper = ClockDefinition(
        clock_id="traveler-1", kind=ClockKind.PROPER, worldline_id="worldline-A"
    )
    coordinate = ClockDefinition(
        clock_id="frame-1", kind=ClockKind.COORDINATE, reference_frame="frame-A"
    )
    assert monotonic.kind == ClockKind.MONOTONIC
    assert civil.timezone == "Asia/Manila"
    assert proper.worldline_id == "worldline-A"
    assert coordinate.reference_frame == "frame-A"
    validate_clock_point(point("12", clock="process-1"), monotonic)
    with pytest.raises(ValueError, match="does not match"):
        validate_clock_point(point("12", clock="other"), monotonic)


def test_clock_definitions_reject_missing_or_misapplied_context():
    from mosaic.core.temporality import ClockDefinition, ClockKind

    with pytest.raises(ValidationError, match="reference_frame"):
        ClockDefinition(clock_id="frame", kind=ClockKind.COORDINATE)
    with pytest.raises(ValidationError, match="worldline_id"):
        ClockDefinition(clock_id="traveler", kind=ClockKind.PROPER)
    with pytest.raises(ValidationError, match="timezone"):
        ClockDefinition(clock_id="wall", kind=ClockKind.CIVIL)
    with pytest.raises(ValidationError, match="only valid"):
        ClockDefinition(clock_id="mono", kind=ClockKind.MONOTONIC, timezone="UTC")



def test_occurrence_measurement_recording_and_learning_are_distinct_times():
    from mosaic.core.temporality import (
        EventKnowledge,
        EventObservation,
        EventOccurrence,
    )

    occurrence = EventOccurrence(
        event_id="power-loss",
        occurred_during=interval(10, 11, clock="plant-clock"),
    )
    observation = EventObservation(
        observation_id="sensor-report-1",
        event_id="power-loss",
        observer_id="sensor-7",
        measurement_at=point("25", clock="sensor-clock"),
        recorded_at=point("40", clock="database-clock"),
        evidence_sha256="a" * 64,
    )
    knowledge = EventKnowledge(
        event_id="power-loss",
        recipient_id="operator-2",
        learned_at=point("55", clock="operator-log"),
        source_observation_id=observation.observation_id,
    )

    assert occurrence.occurred_during.start.clock_id == "plant-clock"
    assert observation.measurement_at.clock_id == "sensor-clock"
    assert observation.recorded_at.clock_id == "database-clock"
    assert knowledge.learned_at.clock_id == "operator-log"
    assert knowledge.event_id == occurrence.event_id == observation.event_id


def test_observation_provenance_rejects_invalid_evidence_hash():
    from mosaic.core.temporality import EventObservation

    with pytest.raises(ValidationError):
        EventObservation(
            observation_id="report-1",
            event_id="event-1",
            observer_id="sensor-1",
            measurement_at=point("2", clock="sensor"),
            recorded_at=point("5", clock="database"),
            evidence_sha256="not-a-sha256",
        )


def test_event_knowledge_does_not_rewrite_occurrence_or_causality():
    from mosaic.core.temporality import EventKnowledge, EventOccurrence, CausalLink

    occurrence = EventOccurrence(
        event_id="change",
        occurred_during=interval(1, 2, clock="physical-clock"),
    )
    learned = EventKnowledge(
        event_id="change",
        recipient_id="agent-A",
        learned_at=point("100", clock="agent-clock"),
        source_observation_id="observation-1",
    )
    assert learned.event_id == occurrence.event_id
    assert learned.learned_at.clock_id != occurrence.occurred_during.end.clock_id
    # Knowledge arriving later does not itself establish a causal edge.
    assert CausalLink(
        source_event_id="change",
        target_event_id="another-event",
        relation="enables",
    ).relation == "enables"
