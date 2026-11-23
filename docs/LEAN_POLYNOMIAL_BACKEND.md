# Lean polynomial backend: dependency decision

## Status

Design decision recorded; implementation is not yet enabled. The existing Lean
4.36.0 integration remains the trusted baseline. Nonlinear polynomial
identities remain unsupported by the formal adapter.

## Finding

Lean's core arithmetic tactic `omega` is suitable for the existing affine
integer checker, but it is not a polynomial-ring decision procedure.
The commonly used `ring` tactic is supplied by Mathlib, not by core Lean.
Consequently, adding `ring` to the current generated source while continuing
to invoke the standalone `lean` executable would create a false assumption
about the installed environment.

References:

- [Mathlib introduction and tactic requirements](https://lean4.dev/tactics/mathlib/intro)
- [Mathlib ring tactic documentation](https://academy.lean4.dev/tactics/mathlib/ring)
- [Mathlib Ring tactic reference](https://leanprover-community.github.io/mathlib4_docs/tactics.html)

## Chosen boundary

A future polynomial checker will be a separate optional backend, not an
expansion of the affine checker. It will:

1. Accept only a bounded AST grammar: integer literals, declared variables,
   unary signs, addition, subtraction, multiplication, and nonnegative
   integer powers under explicit size and degree limits.
2. Compile AST nodes to Lean syntax itself. Caller-provided Lean source,
   imports, binders, tactics, macros, and assumptions will never be accepted.
3. Generate universally quantified identities over `Int` (or a separately
   specified semiring), with variables sorted deterministically.
4. Use a pinned Mathlib revision and the `Mathlib.Tactic.Ring` import in an
   isolated Lake project. The Mathlib version must match the Lean toolchain.
5. Run `lake env lean` in that project and record the Lean version, Mathlib
   revision, generated source hash, request hash, candidate hash, and checker
   identifier in the result.
6. Return `KERNEL_UNAVAILABLE` or `KERNEL_ERROR` if the pinned project is
   unavailable or fails to build. It must never silently fall back to a
   Python coefficient comparison and report formal verification.
7. Treat a successful `ring` proof as a kernel-checked equality of
   polynomials over the selected type. It does not prove rational-function
   equivalence, denominator nonzeroness, inequalities, or domain preservation.

## Resource limits

The parser must bound input length, AST node count, integer literal size,
maximum exponent, polynomial total degree, number of monomials, and
intermediate coefficient bit length. The Lake process needs wall-clock and
memory limits at the deployment boundary. A subprocess timeout alone is not
a complete sandbox.

## Acceptance tests

Before this backend can be enabled, CI must use the pinned toolchain and
Mathlib revision to verify all of the following with the real kernel:

- `(x + 1)^2 = x^2 + 2*x + 1` is accepted.
- `(x + 1)^2 = x^2 + 1` is rejected.
- `(x + y)*(x - y) = x^2 - y^2` is accepted.
- Non-polynomial syntax, negative exponents, division, unknown variables,
  excessive degree, and oversized expressions are unsupported.
- No request field can inject Lean source or select a tactic.
- The exact generated source hash is returned even when the kernel is
  unavailable.

Until these checks exist, MOSAIC must continue to describe nonlinear
polynomial proof as unsupported rather than infer formal status from
symbolic simplification.
