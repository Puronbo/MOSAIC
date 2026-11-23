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
