# Vacuum stability and transition evidence

MOSAIC represents a vacuum as a state **within a declared physical model**.
The stability vocabulary is deliberately model-relative:

- `STABLE_WITHIN_MODEL`: the supplied assessment classifies the state as stable
  under its stated model and regime.
- `METASTABLE_WITHIN_MODEL`: the supplied assessment classifies it as
  metastable under that model and regime.
- `UNASSESSED`: no stability conclusion is being asserted.

A label does not establish that the model is true, that the regime describes
our universe, or that the state has been experimentally observed. Each
assessment records its method, evidence kind, regime, and assumptions.

## Evidence is not one undifferentiated status

`EvidenceKind` distinguishes theoretical analysis, simulation, observation,
and experiment. These labels identify the kind of support being recorded;
they do not rank reliability automatically. A simulation is not an
observation, and an observation is not automatically a causal explanation.
A hash can preserve evidence integrity but cannot establish its truth.

## Vacuum-to-vacuum transitions

A `VacuumTransitionAssessment` wraps a model-bound `PhysicalTransition`
whose source and target must both be typed as vacuum states. It records the
evidence kind, method, and regime. The transition record itself is a
description of a candidate change; its existence in the database is not
evidence that the change occurred.

A claim of spontaneous transition must still state the system boundary and
what counts as external driving. "No external input" within a chosen boundary
does not mean "from absolute nothing": internal dynamics and the initial
state remain part of the model.

A quantitative vacuum-decay calculation would additionally require a
specified field theory or other physical model, potential/action, boundary
conditions, parameter regime, and a validated method for calculating a rate.
These data models do not calculate such a rate.

## Trust boundary

MOSAIC validates record structure and consistency. It does not infer
stability from a label, prove a physical theory, or convert theoretical or
simulated evidence into experimental confirmation. Physical conclusions
remain conditional on the model, assumptions, and evidence supplied.
