# Explicit Inertial Scalar-Field Evolution

MOSAIC now includes one explicit finite-lattice update with supplied initial
field values and initial velocities. The scheme is semi-implicit Euler:

\[
v_i^{n+1}=v_i^n-\Delta t\,\frac{1}{M}\frac{\partial E_h}{\partial\phi_i},
\qquad
\phi_i^{n+1}=\phi_i^n+\Delta t\,v_i^{n+1}.
\]

The field-energy gradient is derived from the same boundary-aware discrete
functional used by the energy assessment. Open lattices use trapezoidal
endpoint weights; periodic lattices include the wraparound gradient edge and
rectangular potential weights.

## Explicit inputs

The caller must supply:
- a field configuration, including model/potential binding and boundary type;
- one finite initial velocity per lattice sample;
- a positive time step and its declared unit;
- a positive inertia coefficient and its declared unit;
- the kinetic coefficient and its unit used by the field-energy functional;
- a velocity unit and output configuration ID.

The update uses the same trapezoidal/periodic quadrature weights in its
inertial mass matrix as in the reported kinetic-energy diagnostic. It rejects
non-finite results and any new field sample outside the potential's declared
domain. It returns the updated configuration, updated
velocities, and a record containing initial/final field samples, velocities,
field energy, kinetic diagnostic, total mechanical-energy diagnostic, and
parameter declarations.

## Interpretation and limitations

This is a finite-dimensional mechanical model defined by the supplied
functional and update rule. It is not automatically a continuum field
equation, relativistic dynamics, a quantum-field model, or a description of
observed physical reality. Unit labels are caller declarations; dimensional
compatibility is not inferred by MOSAIC.

The integrator is not energy-conserving in general. The reported before/after
total energy is diagnostic only; no conservation law is asserted. The separate
[stability assessment](FIELD_STABILITY.md) computes a conservative sufficient
time-step bound when the potential is convex over its complete declared
domain. It deliberately declines certification when its conservative
curvature lower bound is negative. This bound is a linear stability screen,
not an accuracy estimate, nonlinear error bound, or substitute for convergence
studies. There is no adaptive time-step controller.
