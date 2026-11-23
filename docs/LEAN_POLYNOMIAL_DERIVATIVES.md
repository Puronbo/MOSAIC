# Lean polynomial derivative checker

## Status

MOSAIC has an initial real-kernel derivative checker for bounded univariate
polynomials over `ℝ`. It is separate from the integer polynomial identity
checker: differentiation is defined over the real numbers, and a successful
result means Lean accepted a `HasDerivAt` theorem for the generated derivative
at an arbitrary real point.

## Supported syntax

- One variable: `x`.
- Integer literals with absolute value at most 1,000,000.
- Unary plus and minus.
- Addition, subtraction, and multiplication.
- Nonnegative integer powers up to 8.
- Input length at most 512 characters and AST size at most 64 nodes.
- Total polynomial degree at most 12.

Division, modulo, function calls, other variables, negative powers, and
arbitrary Lean source are unsupported.

## Proof construction and trust boundary

The adapter generates a theorem of the form
`HasDerivAt (fun t : ℝ => p(t)) p'(x) x`. Its proof is assembled from
Mathlib's derivative rules for constants, the identity, negation, addition,
subtraction, multiplication, and natural powers. The generated theorem is
submitted to the pinned Mathlib project and receives
`FORMALLY_VERIFIED` only when Lean exits successfully after kernel checking.

The checker can also accept a proposed derivative string from the model. It
parses that candidate with the same bounded grammar, compares exact polynomial
coefficients against its independently computed derivative, and makes the
candidate—not a substituted expected value—the conclusion of the generated
Lean theorem. Lean reconciles equivalent polynomial forms with a generated
ring equality proof. The expression, submitted derivative, and generated proof
source each receive a SHA-256 fingerprint. The Mathlib revision is pinned to
`fc4f59e577feb1a4956671bc04ac18aaaf8cd842`. A missing Lean environment,
timeout, unsupported syntax, or rejected theorem is never reported as a
formal proof.

The model gateway binds the exact original request and candidate result before
calling this checker. Only variable `x` is currently connected to this formal
path; `y` and `z`, rational functions, domain restrictions, and
multivariate/partial derivatives remain unsupported for formal differentiation.
