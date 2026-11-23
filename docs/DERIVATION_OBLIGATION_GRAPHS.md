# Derivation-to-obligation graph compilation

MOSAIC can compile a validated recursive derivation tree into the existing
dependency-aware obligation graph.

`compile_derivation_obligation_graph(request, tree)` first revalidates the
entire tree against the statically registered decomposition rules. It then
creates checker obligations for terminal requests only. Internal nodes are
decomposition structure, not independently checked mathematical claims.

For the registered integer-power chain rule, the three child branches have a
fixed meaning: outer derivative, inner derivative, and final composition
identity. The final identity is gated on every terminal obligation in the
first two branches. This preserves prerequisite dependencies when the inner
derivative itself has been recursively decomposed.

The compiler rejects invalid trees and rules without an explicit obligation
compiler. The resulting graph is a structural dependency contract; it does
not prove that the rule registry is mathematically complete or that the
current experimental symbolic checker is sound. A fully satisfied graph
therefore retains the checkers' conservative status and cannot be promoted to
`PROVED` or `FORMALLY_VERIFIED`.

## Current scope

- Terminal requests use the existing `obligations_for_request` factory.
- The integer-power chain rule is the only registered composition compiler.
- The generic graph evaluator continues to own candidate checking and status
  aggregation.
- Future rule compilers must explicitly define prerequisite branches and
  dependency semantics before they can participate.


## Rule-owned derivation expansion

Each statically registered decomposition rule now supplies its own ordered
child-request expander. The recursive tree builder and validator resolve that
expander through the registry rather than branching on a particular rule ID.
This makes adding a new built-in rule less invasive while preserving the
allow-list: rule code is still trusted repository code, not model-supplied
executable content. Child order remains significant because dependency policies
refer to child indices.
