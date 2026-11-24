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


## Integrity-bound derivation bundles

The `mosaic.verification.derivation_bundle` module can package a validated recursive derivation tree, its compiled obligation graph, bounded candidate payloads, and the deterministic graph result into one request-bound bundle. The canonical SHA-256 digest detects content changes. Validation rebuilds the graph from registered decomposition rules and re-evaluates the exact stored candidates; a stored result is not accepted merely because it was serialized.

Bundles are bounded by candidate count, candidate payload size, and total serialized size. Unknown obligation IDs are rejected. A bundle tied to a different request is stale. The bundle is a replayable computation record, **not** a formal proof of the root claim: current graph outcomes remain `EXPERIMENTAL`, and unresolved rule side conditions continue to cap the result.


## Lean root-derivative bridge (bounded polynomial subset)

`mosaic.verification.lean_derivation.verify_derivation_root_derivative_with_lean` adds a request-bound formal-checking entry point for differentiation requests over the variable `x` whose root expression and candidate derivative fit the bounded univariate real-polynomial grammar supported by the pinned Mathlib backend.

The adapter requires a complete registered derivation tree for the exact request, hashes that tree, and binds the receipt to both the request fingerprint and tree digest. The Lean calculus checker independently parses the original expression, computes its polynomial derivative, rejects a mismatching candidate, and asks the Lean kernel to check a `HasDerivAt` theorem over `ℝ`. A successful receipt therefore establishes the root derivative theorem for the exact expression and candidate, subject to the pinned Lean/Mathlib environment.

**Important scope boundary:** the current proof is generated directly for the root expression. The tree digest preserves provenance and prevents a receipt from being casually transferred to a different derivation, but the tree's individual chain-rule edges are not themselves the proof term and are not yet formally composed. `validate_lean_derivation_receipt` re-runs the restricted Lean checker and requires exact receipt equality; the receipt's hashes alone are not an authenticity mechanism. This is a real root-level formal result, not yet a formal proof of the recursive decomposition procedure. Non-polynomial expressions, variables other than `x`, unsupported domain conditions, and general chain-rule composition remain outside this bridge. A kernel-unavailable or rejected result is preserved as such; it is never upgraded to formal verification.


## Formally checked exponent increments

The pinned Lean project now contains the `MosaicExponentShift` theorem family. For natural `n` and `k`, it embeds the value `value n k = (n : ℝ) ^ (n + k)` into the reals and proves:

- `value n (k + 1) = (n : ℝ) * value n k`;
- `value n (k + 1) - value n k = ((n : ℝ) - 1) * value n k`;
- strict increase for `2 ≤ n`;
- the fixed point at base one;
- zero-valued terms for base zero after the initial exponent-zero boundary.

The natural-number base is intentional. It avoids silently treating negative bases as arbitrary real exponentiation, and the strict-growth theorem has the explicit hypothesis `2 ≤ n`. The initial zero-base term is not assigned a special value by this theorem family: `0^0` remains a boundary case. These are kernel-checked Lean statements when the pinned polynomial-kernel workflow passes. They establish the recurrence and its stated domain-specific properties, not a universal monotonicity claim over all real or complex bases.


### Higher-order finite differences

The exponent-shift formalization now defines `forwardDifference` and recursively defined `iteratedDifference`. Its target theorem is `iterated_difference`: for natural base `n`, shift `k`, and order `r`, the r-th forward difference of `(n : ℝ)^(n+k)` equals `((n : ℝ)-1)^r` times the original value. A positivity corollary is restricted to `2 ≤ n`. This is a finite-difference theorem over a natural-indexed sequence embedded in the reals; it does not assert arbitrary real/complex base semantics or continuous differentiation.


The arbitrary-step extension defines `arbitrary_shift`, `forwardDifferenceBy`, and `iteratedDifferenceBy`. Its target identity is

\[
F_{k+m}(n)=n^mF_k(n),\qquad
\Delta_m^rF_k(n)=(n^m-1)^rF_k(n).
\]

Here `m` is a natural-number step and `r` is the iteration order. The formal statement includes `m = 0` (the zero-step difference is zero at positive iteration orders); no positivity claim for arbitrary-step differences is included unless separately proved with the required positive-step assumptions.


### Shift-operator algebra

The exponent-shift module now exposes `shiftOperator`, with kernel-checked laws for the identity shift, composition (`T_a(T_b f) = T_(a+b) f`), its action on the exponent-increment sequence, and commutation with the unit forward-difference operator. These are natural-indexed forward shifts. There is no inverse shift in this API: a natural sequence has no generally defined values at negative indices, so an inverse law would require a separately specified domain (for example, a bi-infinite integer-indexed sequence).
