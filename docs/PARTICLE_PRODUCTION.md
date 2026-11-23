# Particle production relative to a vacuum

A particle-like excitation is represented relative to a reference state in a
physical model. `ParticleProductionRecord` connects three things:

1. a `PhysicalTransition` whose source is typed as `VACUUM`;
2. a target state typed as `EXCITED`;
3. one or more `ParticleExcitation` records that refer to that exact source
   vacuum and the same model.

The validator rejects mismatched model identifiers and mismatched reference
vacua. This prevents a particle label from floating free of the state and
model that give it meaning.

## What this does—and does not—say

The phrase "particle production from a vacuum" is shorthand for a transition
from a model-defined vacuum state to an excited state. It is not production
from absolute nothingness. The vacuum state, field degrees of freedom,
dynamics, and boundary conditions are part of the physical description.

The record can distinguish theoretical, simulated, observational, and
experimental evidence. It does not calculate particle-production rates,
derive a quantum field theory, or verify that an experiment occurred. The
evidence kind is provenance metadata, not an automatic truth ranking.

Energy accounting can be attached to the underlying transition through
`PhysicalTransition`. A balanced ledger is a consistency check on declared
values and a declared system boundary; it is not a substitute for a physical
derivation or measurement.
