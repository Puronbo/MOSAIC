# Discrete Scalar-Field Relaxation

MOSAIC provides a bounded one-step gradient-descent operation for a declared
finite one-dimensional scalar-field energy functional.

## Scope

The update is an algorithmic relaxation step,

\[
\phi_i^{(n+1)} = \phi_i^{(n)} - \eta\,\frac{\partial E_h}{\partial\phi_i}.
\]

Here \(n\) is an iteration index, not physical time. The implementation is
not a real-time field equation solver, a continuum limit, a quantum-field
theory calculation, or a claim that a physical field follows this update.

## Discrete derivative

The derivative is taken from the same lattice functional evaluated by
`assess_discrete_field_energy`. For an open lattice, endpoint potential
terms receive half trapezoidal weight; interior samples receive full weight.
For a periodic lattice, every sample receives full rectangular weight and
the gradient includes the wraparound edge.

## Backtracking and result

The caller supplies a positive Decimal initial step size, kinetic coefficient,
unit labels, output configuration ID, and optional iteration index. If a
candidate leaves the declared potential domain or increases the evaluated
energy, the step size is halved. The operation accepts the first candidate
whose energy does not exceed the input energy, or raises an error when the
bounded backtracking budget is exhausted.

The result preserves input/output IDs, model and potential IDs, before/after
energy, field samples, accepted step size, mobility unit, and backtracking
count. Unit strings are declarations only; MOSAIC does not infer dimensional
compatibility. The caller must supply consistent units and interpret the
mobility/step-size convention.

An unchanged-energy step is reported as `UNCHANGED`; a strict decrease is
reported as `ENERGY_DECREASED`. Acceptance is a numerical property of this
declared discrete functional, not a proof of physical stability or truth.
