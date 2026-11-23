# MOSAIC

**Mathematical Object, Structure, and Inference Calculus**

MOSAIC is a model-independent framework for representing mathematical reasoning as typed transformations with explicit, independently checkable obligations.

Its research cycle is:

1. **Encode** a mathematical task in a typed, structured representation.
2. **Detect** relevant structure, constraints, invariants, and applicable methods.
3. **Decompose** the task into smaller obligations with explicit dependencies.
4. **Realize** candidate transformations using symbolic engines, numerical methods, theorem provers, or AI-assisted search.
5. **Verify** results with trusted checkers and preserve provenance.

## Trust model

MOSAIC distinguishes computation, independently checked certificates, and formal proof. A computed answer is not automatically a certificate; a certificate is not automatically a formal proof. A hash establishes integrity, not mathematical truth. AI models may propose strategies, transformations, and proof candidates, but they are not trusted verifiers. Majority agreement between models is not proof. Formal proof claims require checking by the relevant trusted kernel (for example, Lean's kernel).

## Result statuses

Use explicit statuses where applicable: `DEFINITION`, `ASSUMPTION`, `CONJECTURE`, `EXPERIMENTAL`, `CONDITIONAL`, `PROVED`, `FORMALLY_VERIFIED`, `REFUTED`, `INCOMPLETE`, `STALE`, `INVALID_CERTIFICATE`, and `UNSUPPORTED`.

## Initial implementation direction

The first prototype is a deliberately restricted mathematical service with:

- a versioned JSON request/response contract;
- a safe expression parser with resource limits;
- exact symbolic algebra and calculus operations;
- independent checking for supported identities and certificates;
- an HTTP interface, Python client, and MCP adapter;
- tests for correctness, rejection behavior, and certificate validation.

The initial operation registry is expected to cover `simplify`, `expand`, `factor`, `differentiate`, `integrate`, `verify_identity`, `solve`, `verify_certificate`, `search`, `counterexample`, and `analyze`. Unsupported operations must return an explicit status rather than silently guessing.

## Repository status

This repository is the starting point for the MOSAIC prototype. Architecture notes and interfaces are specifications until implemented and tested; do not interpret a design document or example as evidence that a component is complete.

## Development

The project targets Python 3.11+ and uses exact arithmetic wherever practical. See [ARCHITECTURE.md](docs/ARCHITECTURE.md), [SECURITY.md](SECURITY.md), and [CONTRIBUTING.md](CONTRIBUTING.md) as the implementation grows.

## License

License selection is pending. Until a license is added, standard copyright restrictions apply; no open-source license is granted by this repository.
