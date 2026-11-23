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


## Clock kinds and what a timestamp means

A clock ID identifies a measurement scale; a ClockDefinition declares its intended semantics:

- **MONOTONIC:** an elapsed-time counter that should not move backward. Useful for durations in software; it is not a universal physical clock.
- **CIVIL:** a calendar/administrative time scale interpreted with an explicit timezone. It can jump or repeat because of daylight-saving rules and clock corrections, so raw civil timestamps are not reliable elapsed-time measurements.
- **PROPER:** time accumulated along a specified physical worldline. The definition therefore requires a worldline_id; comparing different worldlines requires a physical model, not just matching numeric coordinates.
- **COORDINATE:** a time coordinate within a specified reference frame. The definition therefore requires a reference_frame; another frame's coordinate time is not directly interchangeable.

All coordinates in this initial contract are stored in seconds, but this common unit does not make distinct clocks comparable. validate_clock_point checks that a reading is associated with its declared clock. It does not prove calibration, synchronization, correct timezone data, a valid worldline, or a physical frame transformation. Proper-time and coordinate-time conversion is intentionally not implemented until an explicit relativistic model and assumptions are supplied.

This gives MOSAIC a practical answer to “what time is” at the software boundary: a timestamp is a value produced by a particular clock under declared semantics. Physical time itself is not reduced to that value. The model records change, ordering, duration, and causal claims separately, then asks what a specified clock or physical theory licenses us to infer.


## Explicit clock calibration

`ClockCalibration` represents a declared affine mapping from one clock scale to another:

`target = offset + rate × source`

The mapping names both clock IDs, requires a positive rate, records a finite validity interval on the source scale, and includes a bounded calibration uncertainty. Transforming a `TemporalPoint` is allowed only when its clock ID matches the source and its entire uncertainty interval lies inside the calibration range.

Uncertainty is propagated conservatively as `rate × source_uncertainty + calibration_uncertainty`. This is a bounded-error contract for the stated affine model; it is not a calibration procedure, proof of synchronization, or evidence that the assumed rate and offset remain physically valid. Nonlinear drift, changing rates, discontinuities, and relativistic frame transformations require richer domain-specific models. A calibration must never be extrapolated outside its declared range.


## Interval relations

`TemporalInterval` stores start and end readings on the same clock. For exact endpoints, `compare_temporal_intervals` implements the 13 qualitative relations of Allen-style interval algebra: before, meets, overlaps, starts, during, finishes, equals, and their converse relations. This describes how two intervals relate; it does not assert why either interval occurred.

For uncertain endpoints, MOSAIC makes only conservative claims in this initial implementation. `BEFORE` or `AFTER` is returned only when the endpoint uncertainty bounds are strictly separated. Other relations require exact endpoints; otherwise the answer is `INDETERMINATE`. In particular, overlapping uncertainty bounds do not prove simultaneity, equality, or causal connection. Intervals on different clocks cannot be compared without an explicit calibration or physical transformation.

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


## Occurrence, observation, recording, and knowledge

An event can happen before anyone detects it, and detection can precede the arrival of a report in a database or an agent's awareness. MOSAIC therefore gives these stages distinct records:

- **Occurrence:** `EventOccurrence.occurred_during` locates the event itself as an interval on a declared clock. An interval is useful when the exact instant is unknown or the event unfolds over time.
- **Measurement/observation:** `EventObservation.measurement_at` records when an observer or instrument registered evidence. It identifies the observer and binds the record to an evidence SHA-256 digest.
- **Recording:** `EventObservation.recorded_at` records when the observation entered the information system. It may use a different clock from the measurement.
- **Knowledge:** `EventKnowledge.learned_at` records when a named recipient learned of the event, with a reference to the observation that informed them.

These timestamps are deliberately not compared just because they are numeric values. Different clock IDs require an explicit calibration or a domain-specific transformation before coordinate comparison. Even when clocks are comparable, the model does not assume that observation occurred at the event's onset, that recording was immediate, or that a recipient learned of the event when the database stored it.

For example, a machine failure may occur during an interval on a plant clock, a sensor may detect it later on its own clock, a report may be persisted on a database clock, and an operator may learn of it through a separate notification system. These records describe different facts. They do not by themselves establish the cause of the failure or prove that the sensor's evidence is accurate.

The evidence digest supports integrity checking and provenance; it does not prove the evidence is truthful. The observer and recipient identifiers identify whose observation or knowledge is represented; they do not certify that person's reliability. A causal or enabling relationship must still be represented explicitly, and requires its own evidence or verification.

This separation is a key epistemic rule for MOSAIC: **the time an event occurs, the time it is measured, the time it is recorded, and the time someone knows about it are not interchangeable.** The model captures the distinctions without claiming to settle the metaphysics of time.


## Causal hypotheses and evidence

A precedence edge and a causal hypothesis answer different questions. “A happened before B” is an ordering statement. “A caused B” proposes a dependency that needs evidence and may have competing explanations. MOSAIC now represents the latter with `CausalHypothesis`, without deriving it from timestamps or from an existing `CausalLink`.

A hypothesis identifies a proposed cause event, effect event, and relation (for example, `causes` or `enables`). It can retain multiple `CausalEvidence` records, each with:

- a unique evidence identifier and SHA-256 digest;
- a method category: observational, interventional, counterfactual, mechanistic, or other;
- a submitter-assigned polarity: supports or challenges;
- a description and explicitly listed assumptions.

A hypothesis may also list alternative explanations and a proposed counterfactual question. Both supporting and challenging evidence can coexist. This is intentional: evidence is not collapsed into a majority vote or a single confidence score. The schema permits an unassessed hypothesis with no evidence, and does not automatically mark any hypothesis true, false, proved, or refuted.

### What these evidence categories mean

- **Observational:** records covariation or sequence in observed data. Confounding and selection effects may remain.
- **Interventional:** describes evidence from changing a candidate cause under a stated procedure. The intervention design, compliance, and unintended effects still matter.
- **Counterfactual:** asks what would have happened under an alternative condition. A proposed question is not itself a computed or identified counterfactual.
- **Mechanistic:** records a proposed process connecting cause and effect. A plausible mechanism is not proof that it operated in this instance.

An evidence digest establishes which bytes a record refers to, not whether the record is accurate. The polarity is the evidence submitter's interpretation, not an independently verified assessment. The current schema is a provenance and reasoning scaffold, not a causal-discovery algorithm.

### Counterfactual discipline

A useful causal investigation asks a question such as: “Would the shutdown still have occurred if overheating had been prevented while relevant background conditions were held fixed?” This is stronger than noting that overheating preceded shutdown. It also exposes the assumptions that must be justified: what counts as an intervention, which background conditions are held fixed, whether the alternative is physically possible, and whether other causes remain.

MOSAIC should not answer such a question merely by deleting an event from a log or replaying a model's narrative. A future counterfactual engine needs a declared structural or physical model, intervention semantics, variable domains, and independently checkable assumptions. Until then, the counterfactual field stores a question, not its answer.

The intended research rule is therefore: **temporal precedence can constrain a causal explanation, but it cannot establish one; causal evidence must remain traceable, challengeable, and explicit about assumptions.**
