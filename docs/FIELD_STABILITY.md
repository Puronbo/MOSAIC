# Finite-Lattice Field Timestep Stability Assessment

MOSAIC provides a conservative sufficient timestep screen for its
semi-implicit-Euler inertial update. It is intentionally separate from the
time-stepper: callers can inspect the assessment and decide whether to run.

## Bound

Let the lattice spacing be \(h\), the positive gradient coefficient be
\(K\), the positive inertia coefficient be \(M\), and let \(w_{\min}\)
be the smallest quadrature weight (1 for periodic lattices and 1/2 for open
trapezoidal lattices). For the discrete energy Hessian and matching diagonal
mass matrix, MOSAIC uses the conservative upper bound

\[
\omega_{\max}^2 \le
\frac{4K}{M h^2 w_{\min}} +
\frac{\sup_{\phi\in D}|V''(\phi)|}{M}.
\]

The factor 4 bounds the largest eigenvalue of the one-dimensional path or
cycle graph Laplacian. The potential term uses a coefficient-magnitude bound
over the full declared polynomial domain \(D\), not merely at the current
field samples.

For a convex potential throughout that domain, the semi-implicit-Euler
oscillator condition is

\[
0 < \Delta t < \frac{2}{\sqrt{\omega_{\max}^2}}.
\]

The reported decimal upper bound is rounded downward. The assessment reports
one of three outcomes:

- `CERTIFIED_WITHIN_BOUND`: the conservative convexity condition holds and
  the supplied step is strictly below the reported bound.
- `TIME_STEP_EXCEEDS_BOUND`: convexity is bounded but the supplied step is
  not strictly below the sufficient bound.
- `NOT_CERTIFIED_NONCONVEX_DOMAIN`: the conservative lower bound on
  \(V''\) is negative, so this method does not certify the step.

## Conservative polynomial bounds

The lower and upper curvature bounds are formed term-by-term from the
polynomial coefficients and the maximum absolute domain endpoint. This is
simple and safe but can be loose, especially for positive higher-order terms.
A negative lower bound means *not certified*, not necessarily that the
potential is actually nonconvex.

## Limitations

This is a sufficient linear-stability screen for the declared finite lattice
and update scheme. It does not prove nonlinear global stability, estimate
truncation error, certify physical units, guarantee energy conservation, or
establish a continuum/relativistic/quantum-field result. The caller remains
responsible for dimensional consistency, model validity, and convergence
studies. The time-stepper does not silently change or reject a step based on
this separate assessment; applications should explicitly call
`assess_field_time_step` before evolution when this screen is required.
