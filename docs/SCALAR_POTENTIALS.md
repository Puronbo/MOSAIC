# Scalar polynomial potentials

MOSAIC now supports bounded, univariate polynomial potentials with explicit
field and energy units, a declared model identifier, and a finite field
domain. Coefficients are finite `Decimal` values and powers are bounded
nonnegative integers.

For a potential

`V(φ) = Σ cₙ φⁿ`

the implementation evaluates `V`, `dV/dφ`, and `d²V/dφ²` using decimal
arithmetic. It can assess a point as stationary within a caller-supplied
tolerance and classify the sign of its second derivative using a separate
curvature tolerance.

## Interpretation limits

- Positive curvature is a local diagnostic at a stationary point; it is not
  by itself a proof of a global minimum.
- Near-zero curvature is inconclusive; higher-order terms and the domain
  matter.
- This is a potential-energy function of one scalar variable, not a complete
  field theory. It does not include spacetime dependence, kinetic terms,
  gradients, interactions with other fields, quantum corrections, or
  boundary-condition solvers.
- It does not calculate tunnelling or vacuum-decay rates.
- Decimal arithmetic makes the implemented polynomial evaluation explicit;
  it does not remove uncertainty or validate the physical model.

The API intentionally reports curvature rather than declaring a vacuum
"stable". A later model can add kinetic and spacetime structure without
silently upgrading this local mathematical diagnostic into a physical claim.
