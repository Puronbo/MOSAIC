# Auditable Finite-Lattice Field Trajectories

`evolve_field_trajectory` applies the existing semi-implicit-Euler update a
fixed number of times and retains every `FieldDynamicsResult`. The returned
aggregate includes the initial/final configuration IDs, step count, fixed
time step, elapsed time, initial/final total energy, absolute energy drift,
relative energy drift (when initial total energy is nonzero), and observed
minimum/maximum total energy.

## Reproducibility

Each output configuration ID is formed from the caller-supplied prefix and
one-based step index. The complete ordered step records preserve each
intermediate field, velocity, and energy diagnostic. The same initial
configuration, velocities, coefficients, and step settings therefore define
the complete numerical run, subject to the active Decimal arithmetic context.

## Timestep refinement

A useful numerical experiment is to compare runs over the same elapsed time
using successively smaller steps, for example:

- 100 steps of size 0.01;
- 200 steps of size 0.005;
- 400 steps of size 0.0025.

Compare final field and velocity values and the energy-drift histories. This
is empirical convergence evidence for the tested initial-value problem, not
a universal convergence proof. Keep the model, domain, boundary conditions,
initial data, and elapsed time fixed while refining the step.

## Interpretation and limits

The reported energy drift is a diagnostic, not a conserved quantity or an
acceptance criterion. Semi-implicit Euler generally has nonzero energy error.
The trajectory routine does not adapt its step size, silently enforce the
stability assessment, or claim physical validity. Call
`assess_field_time_step` separately when its sufficient convex-domain
stability screen is appropriate. The step-count limit is 10,000 to bound
accidental resource use.

This remains a finite-dimensional, caller-parameterized mechanical model.
Unit strings are declarations rather than dimensional analysis. A numerical
trajectory is not, by itself, a continuum field-theory, relativistic, or
quantum-field result.
