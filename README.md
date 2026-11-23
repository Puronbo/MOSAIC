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

## Implemented prototype

The current Python prototype includes:

- a versioned Pydantic request/response contract and FastAPI endpoints;
- an allow-listed expression parser for a restricted symbolic algebra grammar;
- SymPy-backed simplify, expand, factor, differentiate, and integrate operations;
- an experimental identity candidate checker (not a proof checker);
- a Python HTTP client;
- typed agent task/proposal contracts with dependency graph validation;
- a provider-neutral asynchronous model adapter protocol, explicit provider registry, timeout and payload bounds, and prompt/output hashes;
- a deterministic agent graph runner with explicit provider assignments, dependency-output handoff, failure isolation, and execution provenance;
- an opt-in OpenAI-compatible HTTP chat provider with HTTPS/loopback policy, redirect rejection, sanitized errors, and injectable test transport;
- a structured identity-claim boundary, task-bound candidate verification, and first-class verification obligations that bind explicit checker contracts to request fingerprints;
- regression tests for supported operations, rejected syntax, orchestration invariants, and adapter boundaries.

Run `python -m pytest` to execute the suite. GitHub Actions runs the tests on pushes and pull requests.

## Planned work

Lean-kernel integration, independently checked canonical certificates, additional task-bound operation coverage, additional vendor-specific provider implementations, parallel scheduling, retries, durable execution storage, MCP adapter, stronger resource isolation, domain-aware semantics, and formal proof workflows are not implemented yet. The operation registry also includes planned operations such as `solve`, `verify_certificate`, `search`, `counterexample`, and `analyze`; unsupported operations return an explicit status.

## Repository status

MOSAIC is an early research prototype. Symbolic computation and model responses are candidates, not trusted proofs. The current provider adapter defines an integration contract but does not call any external model. See the architecture and security documents for the trust boundaries and remaining work.

## Development

The project targets Python 3.11+ and uses exact arithmetic wherever practical. See [ARCHITECTURE.md](docs/ARCHITECTURE.md), [SECURITY.md](SECURITY.md), and [CONTRIBUTING.md](CONTRIBUTING.md) as the implementation grows.

## License

License selection is pending. Until a license is added, standard copyright restrictions apply; no open-source license is granted by this repository.


## Run the prototype

Create a virtual environment, install the package and development dependencies, then start the API:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
uvicorn mosaic.api:app --reload
```

On Windows PowerShell, activate with `.venv\\Scripts\\Activate.ps1`.

The health endpoint is `GET /health`. Mathematical requests use `POST /v1/math`. For example:

```json
{
  "schema_version": "1.0",
  "operation": "expand",
  "expression": "(x+1)**2"
}
```

Run the test suite with `python -m pytest`. The Python client is available as `mosaic.client.MosaicClient`.

The current implementation is intentionally small. The HTTP service is a prototype and should not be exposed to untrusted public traffic without the additional isolation and resource controls described in [SECURITY.md](SECURITY.md).
