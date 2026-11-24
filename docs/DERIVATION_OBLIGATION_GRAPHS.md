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


The arbitrary-step API also includes a named first-difference corollary and a zero-step boundary theorem: every positive iteration of a zero-sized step is zero. This explicitly covers the degenerate `m = 0` case rather than relying on the intuitive interpretation of a step as positive.


### Bi-infinite integer shifts

`MosaicIntegerShift` extends translation from natural-indexed sequences to
sequences indexed by `ℤ`. For an arbitrary real-valued sequence, the
translation `T_m f(k) = f(k + m)` is proved to satisfy the identity and
composition laws, and translation by `-m` is both a left and right
inverse of translation by `m`. The unit forward difference commutes
with every integer translation.

This is a genuine group action on bi-infinite sequences, unlike the monoid of
forward-only natural shifts. It is deliberately a generic sequence theorem:
it does not yet identify the sequence with `x^(x+k)` for positive real
`x`, nor does it establish a real-exponent addition theorem or a
continuous derivative. Those require a separate positive-real-power bridge
and are not inferred from the generic shift laws.


### Continuous positive-real exponent family

The previous attempted integer-offset specialization to positive real powers
did not compile against the pinned Mathlib revision and was removed rather than
left as an unverified theorem. The generic integer translation group above
remains valid and independent of exponentiation.

The current `MosaicRealExponentShift` namespace instead defines the
noncomputable real-parameter family

\\[
F_x(t)=x^{t+x},\\qquad x>0,
\\]

and proves with Mathlib's constant-base real-power chain rule that

\\[
F'_x(t)=F_x(t)\\log x.
\\]

The Lean statement is `MosaicRealExponentShift.derivative`. Its
`HasDerivAt` conclusion is the formal derivative notion; Mathlib connects
this to the usual difference-quotient limit. The sign corollary records
positive, zero, and negative derivative according as `log x` is positive,
zero, or negative.

This derivative bridge concerns a fixed positive base and a real exponent
parameter. It does not yet prove a limit theorem connecting the discrete
natural-index finite differences to this derivative, nor does it prove
higher continuous derivatives or variable-base partial derivatives. Those
remain separate formalization targets. The statements are kernel-checked
only when the pinned polynomial-kernel workflow passes.

### Secant-to-tangent limit

The continuous exponent family now exposes
`MosaicRealExponentShift.secantSlope x t h`, the normalized finite-step
change

\[
S_x(t,h)=h^{-1}\big(F_x(t+h)-F_x(t)\big).
\]

The theorems `secant_slope_limit`,
`secant_slope_limit_right`, and `secant_slope_limit_left` prove that
this slope tends to

\[
F_x(t)\log x
\]

as the nonzero step tends to zero, through a punctured neighborhood and
separately from the right and left. This is the precise geometric statement:
the secant slopes converge to the tangent slope. It does **not** say that
the finite difference itself has a nonzero limit. The step and the change
both shrink; their ratio converges.

These limit theorems are derived from the already kernel-checked
`HasDerivAt` theorem through Mathlib's derivative-to-slope equivalence.
They make the limit characterization explicit, rather than independently
proving the exponential limit from first principles. The claims are
kernel-checked only when the pinned polynomial-kernel workflow passes.

### Higher continuous derivatives

The namespace also defines `iteratedDerivative x r t` recursively and states
`iterated_derivative`, proving that each successive derivative exists for
every fixed positive base. The closed-form theorem
`iterated_derivative_formula` gives

\[
F_x^{(r)}(t)=(\log x)^rF_x(t).
\]

This is a fixed-base result for all natural derivative orders. The proof
repeatedly applies the constant-multiple derivative rule to the preceding
order. It does not yet cover variable-base derivatives or complex branches.



### Variable-base and exponent partial derivatives

The positive-base family is also exposed as `MosaicRealExponentShift.jointValue x t = x ^ (x + t)`. The kernel-checked theorem `base_derivative` differentiates with respect to the base while holding `t` fixed:

\\[
\\frac{\\partial}{\\partial x}x^{x+t}
=(x+t)x^{x+t-1}+x^{x+t}\\log x,
\\qquad x>0.
\\]

The theorem `exponent_partial_derivative` differentiates with respect to `t` while holding the base fixed:

\\[
\\frac{\\partial}{\\partial t}x^{x+t}
=x^{x+t}\\log x.
\\]

These are one-variable `HasDerivAt` statements for the two coordinate slices, not yet a single Fréchet-derivative theorem for the joint map `(x,t) ↦ x^(x+t)`. The positive-base hypothesis is essential to the real-power derivative rule used here. Higher mixed partials and a full two-variable smoothness result remain separate targets.


The theorem `along_base_path_derivative` goes one step further: for any differentiable path `u(t)` that remains positive at the evaluation point, it differentiates `u(t)^(u(t)+t)`. Its formula is

\\[
\\frac{d}{dt}u(t)^{u(t)+t}
=u'(t)(u(t)+t)u(t)^{u(t)+t-1}
+(u'(t)+1)u(t)^{u(t)+t}\\log u(t).
\\]

This combines the changing-base and changing-exponent contributions via the real-power chain rule. The hypothesis is local at the point where the derivative is evaluated; it does not assert that the path stays positive globally.


The generalized theorem `along_joint_path_derivative` accepts two independently
differentiable coordinate paths `u(s)` and `v(s)`, and differentiates
`u(s)^(u(s)+v(s))` at a point where the base is positive. If their
derivatives are `u'` and `v'`, the result is

\[
u'(u+v)u^{u+v-1}+(u'+v')u^{u+v}\log u.
\]

This gives the derivative along every differentiable curve in the positive-base
domain, including affine directional paths. It is stronger than the special
path `u(s)^(u(s)+s)`, but it is still a pathwise chain-rule theorem rather
than a bundled Fréchet derivative of the two-variable map. The pinned Lean
integration workflow is the acceptance gate for the new theorem.


The joint exponent family now also has a full Fréchet chain-rule theorem,
`MosaicRealExponentShift.joint_map_fderiv`. For differentiable maps
\(f,g:E\to\mathbb R\) on a real normed space, with \(f(z)>0\), it
differentiates
\[
z\longmapsto f(z)^{f(z)+g(z)}.
\]
The derivative is the continuous linear map
\[
(f(z)+g(z))f(z)^{f(z)+g(z)-1}f'
+f(z)^{f(z)+g(z)}\log(f(z))(f'+g').
\]
Here \(f'\) and \(g'\) are the Fréchet derivatives at the selected point;
scalar multiplication and addition are operations on continuous linear maps.
This formulation works on arbitrary real normed domains, not only on a
one-dimensional path. The pinned Lean kernel workflow remains the acceptance
gate; the theorem is not described as verified until that workflow succeeds.


### Differential geometry of the joint exponent surface

For the positive-base map `G(x,t) = x^(x+t)`, put
`L(x,t) = (x+t)/x + log(x)`. Its first differential is

\[
dG = G L\,dx + G\log(x)\,dt.
\]

The second partial derivatives are

\[
G_{xx}=G\left(L^2+\frac{x-t}{x^2}\right),\qquad
G_{xt}=G_{tx}=G\left(L\log(x)+\frac1x\right),\qquad
G_{tt}=G(\log x)^2.
\]

The mixed-partial identity follows by differentiating either first partial
in the other coordinate; it is also the expected symmetry of the Hessian
for this smooth map on the open half-plane x > 0.

The only stationary point is (x,t) = (1,-1): since G is positive,
G_t = 0 forces log(x) = 0 and hence x = 1; then G_x = 0 forces t = -1.
At that point G = 1 and the Hessian is

\[
\begin{pmatrix}2&1\\1&0\end{pmatrix},
\]

whose determinant is -1. Thus the stationary point is a nondegenerate
saddle, not a local maximum or minimum.

These formulas are analytic consequences of the real-variable derivative
rules. They are documented as mathematical targets here; they must not be
described as Lean-kernel verified until corresponding formal theorems and
successful pinned proof-source replay exist.
