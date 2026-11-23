# Lean polynomial backend

## Status

The first bounded Mathlib-backed polynomial checker is implemented and
integrated with request-bound identity and transformation verification. The
pinned real-kernel CI workflow has passed the positive, negative, unsupported,
and request-bound checks.

The Python/API adapter is deliberately narrower than a general computer
algebra system. It proves only universally quantified polynomial identities
over `Int`.

## Reproducible proof environment

- Lean toolchain: `leanprover/lean4:v4.36.0`
- Mathlib release: `v4.36.0`
- Mathlib commit: `fc4f59e577feb1a4956671bc04ac18aaaf8cd842`
- Lake project: `formal/polynomial/`
- Import: `Mathlib.Tactic.Ring`
- CI: `.github/workflows/lean-polynomial.yml`

The project includes fixed regression theorems and a Python adapter that
generates a theorem for each supported equality. The adapter runs
`lake env lean` inside the pinned project. The generated theorem is accepted
only when Lean exits successfully; Python polynomial expansion is used only
to enforce input/resource bounds, never to award formal status.

## Supported expression language

- Variables: `x`, `y`, and `z` (at most three distinct variables).
- Integer literals bounded by 1,000,000 in absolute value.
- Unary plus and minus.
- Addition, subtraction, and multiplication.
- Nonnegative integer powers up to exponent 8.
- Input length at most 512 characters and AST size at most 64 nodes.
- Polynomial total degree at most 12.
- At most 128 monomials.
- Intermediate integer coefficients limited to 256 bits.

Both `^` (mathematical notation) and `**` (Python notation) are accepted as
power syntax. Division, modulo, function calls, unknown identifiers, negative
powers, assumptions, and arbitrary Lean source are rejected as unsupported.

## Integration surfaces

- `POST /v1/verify/lean/polynomial-int-identity` checks a bounded raw equality.
- `POST /v1/verify/lean/request-identity` derives an identity from a
  `verify_identity` MathRequest. The route tries the closed-Nat checker,
  affine-Int checker, and then this polynomial checker.
- `POST /v1/verify/lean/transformation` binds a proposed simplify/expand/factor
  result to the exact request and uses the affine or polynomial checker.

Results expose the checker ID, request/candidate hashes where applicable,
generated proof-source hash, variables, Lean version, and pinned Mathlib
revision. If the Lake project or executable is unavailable, the checker
returns `KERNEL_UNAVAILABLE`; timeouts or execution failures return
`KERNEL_ERROR`. Neither status is upgraded using symbolic computation.

## Trust boundary and limitations

A successful `ring` proof is checked by Lean's kernel and establishes equality
for every assignment of the bound integer variables. It does not establish
rational-function equivalence, denominator nonzeroness, domain preservation,
inequalities, or canonical-form properties. No user-supplied imports, binders,
tactics, macros, or Lean source are accepted.

The subprocess timeout and parser limits reduce accidental resource use, but
they are not a complete operating-system sandbox. Public deployments should
run Lake/Lean with process, memory, filesystem, and network restrictions.

## Real-kernel acceptance tests

CI checks the following with the pinned Lean/Mathlib environment:

- `(x + 1)^2 = x^2 + 2*x + 1` is accepted.
- `(x + y)*(x - y) = x^2 - y^2` is accepted.
- `x^2 + 1 = x^2 + 2` is rejected.
- Division and other non-polynomial syntax are unsupported.
- A request-bound nonlinear identity is formally verified by the polynomial
  checker and records its obligation/checker metadata.
- A false identity is not marked formally verified.

The standalone Python suite additionally covers expression bounds, unsafe
syntax, source generation, unavailable-kernel fingerprints, timeouts, and
API input validation.
