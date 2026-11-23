# MOSAIC architecture (prototype)

## Design boundary

MOSAIC separates an untrusted proposal/execution layer from trusted verification. AI models and symbolic engines may suggest transformations or produce candidate results. A result becomes formally verified only when a designated trusted proof checker validates a proof object under a documented kernel and assumptions. Model agreement, a successful computation, and a content hash are not substitutes for proof checking.

## Research cycle

- **Encode:** validate a typed request and normalize its mathematical objects.
- **Detect:** identify structure, domains, invariants, and applicable operations.
- **Decompose:** produce subgoals and explicit dependency edges.
- **Realize:** ask bounded engines or agents to produce candidate transformations.
- **Verify:** check obligations independently and preserve provenance.

## Prototype layers

- core: operation vocabulary, versioned request/response models, and agent orchestration contracts;
- engines: restricted parsing and SymPy-backed exact symbolic operations;
- verification: structured and task-bound candidate checking, typed request-bound obligations, dependency-aware DAG evaluation, independent exact-arithmetic cross-checking, and an optional restricted Lean-kernel adapter;
- adapters: FastAPI endpoint; Python and MCP adapters are planned;
- tests: regression tests for supported operations, rejected syntax, and orchestration invariants.

## Trust and status policy

The general identity and transformation routines remain EXPERIMENTAL even when symbolic recomputation succeeds. The Lean endpoints can return FORMALLY_VERIFIED only when the configured Lean kernel accepts MOSAIC-generated proof source. Closed-Nat and affine-Int checkers use the core Lean toolchain; the separate polynomial-Int checker uses a pinned Mathlib Lake project. The request-bound identity route derives an assumption-free obligation from the exact MathRequest and tries these checkers in sequence. The transformation route binds both the request and candidate hashes and supports the affine or bounded polynomial grammars. Rational-domain preservation, arbitrary Lean source, and user-supplied tactics remain unsupported. If a proof environment is unavailable, the result says so and never falls back to experimental evidence.

Agent outputs are untrusted proposals. Agreement between agents is not verification; disagreement triggers review rather than an automatic verdict. See [AGENT_ORCHESTRATION.md](AGENT_ORCHESTRATION.md).

## Next milestones

1. Harden parser and bound CPU, memory, recursion, and expression growth.
2. Add domain-aware semantics and explicit assumptions.
3. Define canonical certificate schemas and independent checkers.
4. Add Python SDK and MCP adapter over the same operation contract.
5. Expand the restricted Lean bridge into request-bound proof obligations with explicit assumptions and a reproducible Lean toolchain.
6. Add provider adapters, sandboxed execution, provenance logging, retries, and budget-aware scheduling.

Nonlinear polynomial verification is implemented in a separate, optional Mathlib-backed Lake project. Its pinned dependency, supported grammar, resource bounds, API routes, and real-kernel acceptance tests are documented in [LEAN_POLYNOMIAL_BACKEND.md](LEAN_POLYNOMIAL_BACKEND.md). Lean core's `omega` checker remains separate from Mathlib's `ring` tactic.

The request-bound Lean bridge now supports a second, distinct checker for
universally quantified affine identities over `Int`. A restricted AST
compiler permits only `x`, `y`, and `z`, bounded integer constants,
addition, subtraction, and multiplication by a constant. It emits explicit
`Int` binders and uses Lean's `omega` tactic; generated proof source is
fingerprinted. Nonlinear expressions, division, domain assumptions, and arbitrary source
remain outside the affine checker. The theorem proves equality for every
integer assignment and must not be interpreted as a rational-domain proof.

A further route, POST /v1/verify/lean/transformation, binds a proposed result
to a specific simplify/expand/factor request and checks affine or bounded polynomial equivalence over Int. The
obligation binds both request and candidate hashes. It does not establish
rational-domain preservation or canonical-form properties.
