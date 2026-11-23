# Dependency-aware verification graphs

MOSAIC can compose request-bound obligations into a directed acyclic graph
(DAG) using `mosaic.verification.graph`.

- `ObligationNode` binds one `MathRequest` to its generated
  `VerificationObligation` and names prerequisite obligation IDs.
- `ObligationGraph` is the immutable graph container.
- `validate_obligation_graph` rejects duplicate IDs, duplicate dependencies,
  unknown dependencies, self-dependencies, and cycles. It returns a stable
  topological execution order.
- `evaluate_obligation_graph` evaluates candidates in dependency order.
  A dependent node runs only when every prerequisite has status
  `EXPERIMENTAL` and `equal=True`. Failed prerequisites block descendants,
  not independent branches.

Candidate strings are supplied in a mapping keyed by obligation ID. Missing
candidates remain `INCOMPLETE`. Invalid certificates and unsupported
obligations remain explicit. The aggregate is `EXPERIMENTAL` only when every
node has an experimental, equal result; it never upgrades experimental checks
to proof.

## Current scope

Each node currently binds to one request-generated primary obligation.
Distinct sub-requests can be composed, but automatic decomposition of one
complex expression into mathematically justified subgoals is not implemented.
That requires operation-specific decomposition rules and explicit assumptions.
The graph is a dependency scheduler, not a theorem prover or a trusted proof
kernel. Checker identifiers are validated against registered contracts; they
are never dynamically imported or executed from model-supplied text.
