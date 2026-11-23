# Derivation-to-obligation graph compilation

MOSAIC compiles a validated recursive derivation tree into a dependency-aware
obligation graph. Terminal derivation requests become checker obligations;
internal nodes preserve decomposition structure and dependency semantics.

For the registered integer-power chain rule, the final composition identity
depends on all terminal obligations in the outer- and inner-derivative
branches. Nested applications preserve this dependency closure.

## Rule preconditions are part of graph evaluation

Every registered rule may declare request-bound side conditions. The chain
rule currently declares inner differentiability, domain definedness, and
domain/branch preservation. Each is explicitly `UNSUPPORTED` because no
domain-aware checker is registered.

The compiler now attaches each condition to the exact request that generated
it as a `RuleSideConditionNode`. Graph validation recomputes the expected
condition from the statically registered rule and rejects altered, stale, or
unknown contracts. This is integrity validation, not proof that the condition
holds.

The evaluator still runs the algebraic leaf checks so users retain diagnostic
results. However, any unresolved side condition makes the aggregate graph
status `UNSUPPORTED`, even when every algebraic candidate passes its
experimental checker. Side conditions are separately reported in
`side_condition_results`; they are never silently treated as satisfied and
cannot be discharged by supplying an arbitrary candidate string.

## Status and trust boundary

- `EXPERIMENTAL` means all algebraic obligations passed current experimental
  checkers, with no unresolved rule preconditions.
- `UNSUPPORTED` means at least one required rule precondition has no checker.
- `INCOMPLETE` means required algebraic candidates or dependencies are
  missing or unsatisfied.
- `INVALID_CERTIFICATE` means a candidate failed certificate/schema checks.

No status here is a formal proof. The registered rules remain allow-listed
repository code, and future domain-aware checkers must explicitly discharge
their own contracts before a derivation can be reported as fully evaluated.
