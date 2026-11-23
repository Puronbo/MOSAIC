# Finite one-dimensional scalar-field configurations

MOSAIC represents a sampled scalar field on a finite, uniformly spaced
one-dimensional lattice with `FieldConfiguration1D`. Each configuration binds
to an explicit model ID and scalar-potential ID and declares coordinate and
field units.

## Discrete gradient functional

For samples `phi_i` separated by spacing `dx`, the implementation computes

```
G = 1/2 * sum_i ((phi[i+1] - phi[i])^2 / dx)
```

An `OPEN` lattice sums adjacent sample pairs. A `PERIODIC` lattice also
includes the last-to-first pair, treating the ring length as the number of
samples times the spacing. Coordinates must be strictly increasing and
uniformly spaced.

The result has units `field_unit^2 / coordinate_unit`. It is deliberately
called a gradient functional, not physical energy: a physical kinetic term
requires a separately specified coefficient with compatible dimensions and
a declared normalization convention. The current implementation does not
silently invent that coefficient or combine incompatible units.

## Scope and limitations

This is a finite-grid data model and a discrete diagnostic. It is not a
continuum limit, a solution of the Euler-Lagrange equations, a quantum field
theory, a time evolution, or a vacuum-decay calculation. It does not yet
implement fixed-value/Neumann boundary data, multidimensional grids,
interactions between multiple fields, or a discretization-error estimate.

Before calculating the gradient functional, callers should use
`validate_against(potential)` to enforce model identity, potential identity,
field-unit agreement, and the potential's declared domain. These checks
establish structural consistency only; they do not establish that the model
describes nature.
