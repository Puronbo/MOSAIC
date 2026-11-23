# Physical state transitions and energy accounting

MOSAIC records a proposed transition between two physical states only relative
to a declared model. A vacuum-to-excited-state transition is therefore a
model-relative state change, not a claim that an entity emerged from absolute
nothingness.

## Transition records

`PhysicalTransition` binds source and target `PhysicalStateReference` records
to one model identifier. It records a mechanism description, system boundary,
assumptions, and optional evidence digest. It rejects state references from
different models and mismatched energy-ledger boundaries.

The transition is a structured proposal. Its presence does not prove that the
transition occurred, that the mechanism is correct, or that the named model
describes nature.

## Energy accounting

`EnergyAccounting` uses one declared unit and the sign convention:

```
initial energy + energy supplied - energy transferred out = final energy
```

`check_energy_balance` evaluates the residual with exact Decimal arithmetic
and compares its absolute value with an explicit nonnegative tolerance.
A balanced result means only that the supplied ledger satisfies this equation
within tolerance. It does not validate the system boundary, calibration,
measurement uncertainty, completeness of the energy terms, or physical model.

For an isolated system, supplied and transferred-out energy are zero in this
ledger. For an open system, energy crossing the declared boundary must be
accounted for. The model does not silently assume that an apparent energy
increase violates conservation; omitted interactions or boundary flows may
explain it, and must be represented rather than guessed.

## What this does not establish

The current implementation is bookkeeping, not a quantum-field solver. It
does not derive particle production, calculate transition amplitudes, model
vacuum decay, or prove energy conservation in a physical experiment. Such
claims require theory-specific dynamics, state definitions, observables,
uncertainty models, and independently checkable predictions.

A useful guiding distinction remains: a state is not necessarily an object,
a transition is not creation from absolute nonbeing, and an internally
balanced ledger is not evidence that the proposed process happened.
