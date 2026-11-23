# MOSAIC temporal model (initial contract)

## Working interpretation

MOSAIC does not assume that a timestamp *is* time. It separates four ideas:

1. **Change:** a system occupies states and may undergo transitions.
2. **Temporal order:** events may be earlier, later, coincident at a clock coordinate, or not orderable from the available measurements.
3. **Duration:** a measured interval between readings of a specified clock.
4. **Causality:** a directed dependency or influence claim between events.

These concepts interact, but none should be silently substituted for another. In particular, a causal dependency is not established merely by sorting timestamps, and temporal precedence alone does not prove causation.

## Clock-relative measurements

`TemporalPoint` records a clock identifier, a coordinate in seconds on that clock's scale, and a nonnegative measurement uncertainty. Two points are comparable only when they name the same clock. This is deliberate: clock synchronization, calibration, relativistic frame transformations, and clock drift require explicit models rather than implicit assumptions.

For a coordinate (t) and uncertainty (u), the represented interval is ([t-u,t+u]).

- `BEFORE` / `AFTER`: the uncertainty intervals are strictly separated.
- `SAME_COORDINATE`: both readings are exact and have equal coordinates.
- `INDETERMINATE`: intervals overlap or touch without proving exact coordinate equality.

The initial `duration_bounds` function returns a nonnegative interval for the absolute separation of two readings from the same clock. It preserves uncertainty instead of silently selecting a point estimate.

## Event order as a partial order

A single global timeline is not always justified by the available information. MOSAIC now represents event precedence as a directed acyclic graph. An edge (A \to B) means the model asserts that A precedes B. Reachability gives transitive consequences: if A precedes B and B precedes C, then A precedes C.

If neither event is reachable from the other, the relation is **incomparable**. This does not mean that they happened simultaneously; it means the declared ordering information does not establish either direction. Simultaneity is a stronger claim and requires an appropriate measurement or physical model.

The graph is validated as acyclic, bounded to 500 events and 2,000 edges, and rejects unknown endpoints and duplicate event identifiers. This partial-order structure is independent of clock readings. A later physical model may add constraints that relate event order to measured coordinates, but that coupling must be explicit.

## What this does—and does not—claim about reality

This is an operational and epistemic contract for software: it says what MOSAIC can infer from specified clock readings and declared event relations. It is not a proof that time is fundamentally a dimension, a flow, an illusion, an emergent phenomenon, or identical to change.

A useful research hypothesis is that **time in a model has at least two layers**:

- an ordering layer represented as a partial order, describing which events can precede others and which are incomparable;
- a metric layer assigning durations using a clock or physical process.

A third, separate causal layer describes dependencies. Physics may constrain how these layers fit together, but the current code does not choose a complete theory of time.

## Trust boundary and next work

The temporal models are descriptive data, not formal physical certificates. A caller-supplied clock identifier is a declared measurement context, not proof that the clock is calibrated or synchronized. The initial API does not infer universal simultaneity, causal direction, or physical laws.

Future extensions should add explicit clock calibration and synchronization records, monotonic versus civil-time semantics, event/state transition records, interval relations (including overlap), and domain-specific physical models. Each extension should state its assumptions and verification method. Relativistic comparisons must include reference frames and transformation rules; they must not be approximated by comparing unrelated timestamps.

Tests cover strict ordering, overlapping uncertainty intervals, cross-clock rejection, duration bounds, and the separation of causal links from temporal comparisons.
