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
- a structured identity-claim boundary, task-bound candidate verification, and first-class verification obligations and dependency-aware DAG execution;
- a deterministic, allow-listed decomposition-rule registry;
- bounded recursive derivation trees that validate complete expansion relative to registered rules;
- compilation of validated derivation trees into dependency-aware obligation DAGs;
- regression tests for supported operations, rejected syntax, orchestration invariants, and adapter boundaries.

Run `python -m pytest` to execute the suite. GitHub Actions runs the tests on pushes and pull requests.

See [recursive derivation trees](docs/RECURSIVE_DERIVATION_TREES.md) and [derivation-to-obligation graph compilation](docs/DERIVATION_OBLIGATION_GRAPHS.md) for the current decomposition contracts and trust limitations.

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

## Task-bound verification API

External AI systems can submit a proposed result to
`POST /v1/verify/task-bound`. The request carries the mathematical task
separately from the untrusted candidate payload. MOSAIC binds the candidate to
the exact task, recomputes supported operations, and returns a versioned
machine-readable check with hashes and (where applicable) a domain-preservation
certificate. See [the API contract](docs/TASK_BOUND_API.md).

Python callers can use `MosaicClient.verify_candidate(request, candidate)`.
All symbolic outcomes remain experimental rather than formal proofs.

## Persistent verification sessions

MOSAIC can retain an immutable mathematical request and an append-only history
of candidate revisions using its SQLite session API. Each revision includes a
conservative progress classification and a stopping recommendation, with a
default cap of 20 revisions per session. Create a session with
`POST /v1/verification-sessions`, append candidates at
`POST /v1/verification-sessions/{session_id}/revisions`, and retrieve the
history with `GET /v1/verification-sessions/{session_id}`. See
[the session contract](docs/TASK_BOUND_API.md#persistent-verification-sessions).
Configure storage with `MOSAIC_SESSION_DB`; add authentication and deployment
hardening before exposing it beyond a trusted environment.

## Evidence provenance

Task-bound checks now return provenance-labelled evidence findings alongside
the result. For simplify/expand/factor, a bounded exact rational-polynomial
checker using Python AST parsing and Fraction arithmetic independently checks
equivalence without SymPy. Checker identities and independence groups are
registered in code; related checks using the same symbolic runtime count as
one source. Model opinions are not checker evidence. This cross-check remains
experimental and is not a formal proof. See
[the evidence and independence contract](docs/TASK_BOUND_API.md#evidence-provenance-and-independence).


## Optional Lean kernel check

When a Lean 4 executable is installed and available on PATH, MOSAIC exposes
`POST /v1/verify/lean/closed-nat-equality`. It accepts only bounded, closed
natural-number arithmetic expressions; MOSAIC generates the Lean theorem
rather than accepting source code or tactics from the caller. A successful
kernel check is reported as `FORMALLY_VERIFIED` for that exact equality only.
If Lean is unavailable, the response explicitly reports
`KERNEL_UNAVAILABLE`. This narrow bridge does not yet prove general symbolic
identities or transformations. See [the architecture](docs/ARCHITECTURE.md)
and [security limitations](SECURITY.md).


### Request-bound Lean identity checks

MOSAIC also exposes `POST /v1/verify/lean/request-identity`. Unlike the
low-level closed-equality endpoint, this route accepts a normal mathematical
request and derives the proposition from its exact `expression` and `rhs`.
It currently supports only `verify_identity` requests whose expressions fit
the closed-natural-number grammar. The response includes a request fingerprint
and an explicit assumption-free obligation. It does not yet formally verify
general symbolic transformations.


### Symbolic affine identity checks

The request-bound Lean identity route now has a second, narrowly scoped path
for affine identities over integers. It accepts only variables `x`, `y`,
and `z`; integer literals; addition and subtraction; and multiplication
where at least one factor is constant. MOSAIC derives universally quantified
`Int` binders and asks Lean's `omega` tactic to construct the proof. The
generated theorem is still checked by Lean's kernel, and its source hash and
variable list are returned. Nonlinear products, division, powers, assumptions,
and other variables remain unsupported. This proves an identity over all
integer assignments, not a statement about rational-function domains.
