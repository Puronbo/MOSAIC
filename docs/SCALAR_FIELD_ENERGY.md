# Discrete scalar-field energy on a 1D lattice

MOSAIC provides `assess_discrete_field_energy` for a finite
`FieldConfiguration1D` bound to a `ScalarPotential`.

The declared functional is

```
E = integral [ K/2 * (d(phi)/dx)^2 + V(phi) ] dx
```

where `K` is an explicit nonnegative Decimal kinetic coefficient. The
implementation approximates the gradient contribution by summing
`K * (delta_phi)^2 / (2 * dx)` over lattice edges.

- `OPEN`: adjacent edges only; potential density uses trapezoidal quadrature.
- `PERIODIC`: includes the last-to-first edge; potential density uses a
  periodic rectangular sum over all samples.

The result reports gradient, potential, and total contributions separately,
along with the configuration/model/potential IDs, declared energy unit,
kinetic-coefficient unit string, and quadrature convention.

## Dimensional and physical limits

The unit strings are declarations, not a dimensional-analysis engine. The
caller must ensure that `K * (field_unit / coordinate_unit)^2` has the same
density units as the potential, and that integration over the coordinate
produces the intended energy unit. The current API records the coefficient's
unit declaration but cannot prove dimensional compatibility. It does not
silently infer or convert units.

This is a finite-grid functional, not a continuum field theory, equation-of-
motion solver, time evolution, or quantum-field calculation. It does not
select a physical value for `K`, establish that the potential is physically
correct, estimate discretization error, or prove stability. Numerical output
is conditional on the declared model, boundary convention, quadrature, and
unit assumptions.
