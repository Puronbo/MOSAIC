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
- verification: conservative candidate checking; no Lean integration yet;
- adapters: FastAPI endpoint; Python and MCP adapters are planned;
- tests: regression tests for supported operations, rejected syntax, and orchestration invariants.

## Trust and status policy

The current identity routine reports EXPERIMENTAL even when SymPy simplifies a difference to zero. The attached object is a symbolic-zero candidate, not an independently checked proof certificate. The prototype does not emit FORMALLY_VERIFIED. A failed simplification is INCOMPLETE unless a separate sound procedure establishes a counterexample or refutation.

Agent outputs are untrusted proposals. Agreement between agents is not verification; disagreement triggers review rather than an automatic verdict. See [AGENT_ORCHESTRATION.md](AGENT_ORCHESTRATION.md).

## Next milestones

1. Harden parser and bound CPU, memory, recursion, and expression growth.
2. Add domain-aware semantics and explicit assumptions.
3. Define canonical certificate schemas and independent checkers.
4. Add Python SDK and MCP adapter over the same operation contract.
5. Integrate a trusted proof assistant kernel for formal proof claims.
6. Add provider adapters, sandboxed execution, provenance logging, retries, and budget-aware scheduling.
