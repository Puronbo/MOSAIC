# Derivation-to-obligation graph compilation

MOSAIC compiles a validated recursive derivation tree into a dependency-aware
obligation graph. Terminal derivation requests become checker obligations;
internal nodes preserve decomposition structure and dependency semantics.

For the registered integer-power chain rule, the final composition identity
depends on all terminal obligations in the outer- and inner-derivative
branches. Nested applications preserve this dependency closure.

## Rule preconditions and conservative checking

Every registered rule may declare request-bound side conditions. The chain
rule declares inner differentiability, domain definedness, and
domain/branch preservation. Each contract is attached to the exact request
that generated it and revalidated against the statically registered rule.

A narrow checker, \`calculus.real_polynomial_domain.v1\`, now recognizes a
nonnegative integer power of a polynomial. In this case the expression and
its derivatives are polynomials, so the three declared real-domain
preconditions can be marked \`EXPERIMENTAL\`. This is a conservative,
restricted recognition rule: it does not claim to handle negative powers,
rational functions, logarithms, roots, trigonometric expressions, or general
branch-sensitive functions. Those remain \`UNSUPPORTED\`.

The checker result is separate from the immutable side-condition contract.
It cannot be altered by supplying a candidate string. Graph validation
recomputes the contract; graph evaluation invokes the built-in checker.
Algebraic leaf checks still run for diagnostics.

## Status and trust boundary

- \`EXPERIMENTAL\` means all algebraic obligations and all applicable
  preconditions passed current experimental checkers.
- \`UNSUPPORTED\` means at least one required precondition has no registered
  checker for the supplied expression.
- \`INCOMPLETE\` means required algebraic candidates or dependencies are
  missing or unsatisfied.
- \`INVALID_CERTIFICATE\` means a candidate failed certificate/schema checks.

No status here is a formal proof. The polynomial checker relies on the
restricted parser and symbolic polynomial classification; future checkers
must declare their supported domains and limitations explicitly.
