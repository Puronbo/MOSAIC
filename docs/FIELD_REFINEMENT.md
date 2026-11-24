# Fixed-Horizon Timestep Refinement Experiments

`assess_field_timestep_refinement` runs the same initial-value problem at
geometrically decreasing time steps. The base run uses 100 steps; each
successive level divides the step by the requested integer refinement ratio
and multiplies the step count by that ratio. All levels therefore cover the
same elapsed time. The implementation requires this horizon to be exactly
representable under the active Decimal arithmetic context and rejects a
combination that would introduce a rounded horizon mismatch.

## Reported comparisons

For each level except the finest, MOSAIC reports the maximum absolute
difference in final field samples and final velocities relative to the next
finer run. For levels with two successive positive, decreasing endpoint
errors, it also reports the descriptive observed order

\[
p = \frac{\log(e_{coarse}/e_{fine})}{\log(r)},
\]

where \(r\) is the refinement ratio. An order is omitted when errors are
zero, fail to decrease, or are otherwise unsuitable for this calculation.
The finest level has no finer reference and therefore no endpoint error.

Every level embeds its complete `FieldTrajectoryResult`, including all
intermediate states and energy diagnostics.

## Limits and interpretation

This is an empirical comparison, not a proof of convergence or an estimate
of the exact solution's error. Pairwise differences can be misleading when
the runs are outside the asymptotic convergence regime, when roundoff
dominates, or when the chosen model is unstable. The experiment does not
automatically call or enforce the separate timestep stability assessment.

The function currently uses 100 base steps, accepts 2 through 6 levels, and
caps each trajectory at 10,000 steps. Refinement ratio must be an integer of
at least 2. Unit labels remain caller declarations. This remains a
finite-dimensional numerical model, not a continuum or quantum-field solver.
