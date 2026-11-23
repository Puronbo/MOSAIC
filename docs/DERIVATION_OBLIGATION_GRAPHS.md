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

The checker `calculus.rational_domain_constraints.v1` recognizes a
nonnegative integer power of a rational expression. It preserves original
denominator restrictions even when algebraic cancellation would hide them.
For example, `((x**2 - 1)/(x - 1))**2` retains the condition
`x - 1 != 0`.

Restrictions are emitted as typed `DomainRestriction` records containing a
stable request-bound identifier, a nonzero predicate, the normalized
expression, the source construct, and its syntax location. This makes domain
information consumable by later checkers and model adapters without requiring
them to parse explanatory prose. The compatibility `domain_constraints`
string view remains available.

These restrictions are conditions, not solved excluded-point sets and not
proofs that the conditions hold. The checker does not enumerate roots or
remove restrictions after cancellation. Supported rational expressions and
their derivatives remain conditional on the recorded restrictions and are
marked `EXPERIMENTAL`. Negative outer powers, logarithms, roots,
trigonometric expressions, and branch-sensitive functions remain unsupported. Negative
integer powers *inside* the rational expression are supported and contribute
a typed `negative_power_base` restriction (for example, `x**-1` records
`x != 0`). Negative outer powers remain unsupported.

The checker result is separate from the immutable side-condition contract.
It cannot be altered by supplying a candidate string. Graph validation
recomputes the contract; graph evaluation invokes the built-in checker.
Algebraic leaf checks still run for diagnostics. Direct chain-rule execution uses
this same registered checker path, so it cannot bypass precondition evaluation.

## Status and trust boundary

- \`EXPERIMENTAL\` means all algebraic obligations and all applicable
  preconditions passed current experimental checkers.
- \`UNSUPPORTED\` means at least one required precondition has no registered
  checker for the supplied expression.
- \`INCOMPLETE\` means required algebraic candidates or dependencies are
  missing or unsatisfied.
- \`INVALID_CERTIFICATE\` means a candidate failed certificate/schema checks.

No status here is a formal proof. The rational-domain checker relies on the
restricted parser and symbolic rational-function classification; future checkers
must declare their supported domains and limitations explicitly.


## Comparing domains across proposed transformations

`check_domain_preservation(request, candidate_expression)` compares the
original expression's polynomial nonzero exclusions with those syntactically
required by a proposed rational candidate. It factors polynomial predicates
and ignores nonzero multiplicity, so `x - 1 != 0` and
`(x - 1)**2 != 0` have the same signature. It reports whether a candidate
expands, narrows, changes, or preserves the represented domain.

This is intentionally conservative: it supports only the restricted rational
expression grammar and polynomial exclusion factors. A `PRESERVED` result
means the extracted exclusion signatures match; it is not a proof of the
transformation's algebraic correctness or a formal proof of domain equality.
