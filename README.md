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
- a model-facing candidate gateway that combines strict task binding with optional request-bound Lean verification;
- a bounded provider-neutral proposal → independent verification → structured feedback → revision loop (maximum three attempts);
- a deterministic agent graph runner with explicit provider assignments, dependency-output handoff, failure isolation, and execution provenance;
- an opt-in OpenAI-compatible HTTP chat provider with HTTPS/loopback policy, redirect rejection, sanitized errors, and injectable test transport;
- a structured identity-claim boundary, task-bound candidate verification, and first-class verification obligations and dependency-aware DAG execution;
- a deterministic, allow-listed decomposition-rule registry;
- bounded recursive derivation trees that validate complete expansion relative to registered rules;
- compilation of validated derivation trees into dependency-aware obligation DAGs;
- typed scoped absence claims, model-relative vacuum states, and particle-like excitation records;
- model-bound physical state transitions and exact Decimal energy-ledger checks;
- model-relative vacuum stability assessments and evidence-typed vacuum transition records;
- vacuum-referenced particle-production records that enforce model and reference-state consistency;
- bounded scalar polynomial potentials with explicit Decimal derivative and curvature assessments;
- finite one-dimensional scalar-field configurations with explicit lattice boundaries and a discrete gradient functional;
- discrete scalar-field energy assessments with explicit kinetic coefficients, boundary-aware quadrature, and unit declarations;
- bounded discrete gradient-flow relaxation steps with analytic lattice-energy gradients and backtracking descent;
- explicit inertial scalar-field steps with caller-supplied initial velocities, time steps, and quadrature-consistent mechanical-energy diagnostics;
- conservative timestep screening for convex finite-lattice potentials, with explicit non-certification for potentially nonconvex domains;
- auditable multi-step field trajectories retaining every intermediate state and energy diagnostic;
- fixed-horizon timestep-refinement experiments comparing final fields, velocities, energy drift, and descriptive observed orders;
- portable refinement assessment records with recomputed acceptance criteria and canonical SHA-256 integrity digests;
- provenance envelopes that distinguish computation, independent checker findings, reported formal-kernel checks, and artifact integrity;\n- an in-process adapter that invokes the request-bound Lean transformation verifier and creates kernel evidence events only for completed pass/rejection outcomes with proof-source and version metadata;\n- optional HMAC-authenticated Lean runner receipts and Ed25519-signed attestations for deployments that separate proof execution from evidence-envelope consumption;
- regression tests for supported operations, rejected syntax, orchestration invariants, and adapter boundaries.

Run `python -m pytest` to execute the suite. GitHub Actions runs the tests on pushes and pull requests.

See [the temporal model](docs/TEMPORAL_MODEL.md) for event partial orders, uncertainty-aware clock measurements, explicit monotonic/civil/proper/coordinate clock semantics, bounded clock-calibration transforms, Allen-style temporal interval relations, duration bounds, state transitions, separate event-occurrence, observation, recording, and knowledge timestamps, and provenance-bound causal hypotheses that retain supporting and challenging evidence. See [absence and vacuum modeling](docs/ABSENCE_AND_VACUUM.md) for scoped absence claims, model-relative vacuum states, and particle-like excitations. See [physical state transitions](docs/PHYSICAL_STATE_TRANSITIONS.md) for model-bound state changes and explicit energy accounting, and [vacuum stability and transition evidence](docs/VACUUM_STABILITY.md) for model-relative stability labels and evidence provenance, and [particle production](docs/PARTICLE_PRODUCTION.md) for vacuum-referenced excitation records, and [scalar potentials](docs/SCALAR_POTENTIALS.md) for bounded polynomial field-potential evaluation, and [finite 1D field configurations](docs/FIELD_CONFIGURATIONS_1D.md) for sampled lattice fields and discrete gradient diagnostics, and [discrete scalar-field energy](docs/SCALAR_FIELD_ENERGY.md) for boundary-aware lattice energy functionals, and [field relaxation](docs/FIELD_RELAXATION.md) for algorithmic energy-descent steps, and [field dynamics](docs/FIELD_DYNAMICS.md) for an explicit inertial finite-lattice update, and [field stability](docs/FIELD_STABILITY.md) for a conservative sufficient timestep bound, plus [field trajectories](docs/FIELD_TRAJECTORY.md) for reproducible multi-step runs and [field refinement](docs/FIELD_REFINEMENT.md) for fixed-horizon numerical comparisons, with [portable refinement certificates](docs/FIELD_REFINEMENT_CERTIFICATES.md) for explicit acceptance decisions. See [evidence envelopes](docs/EVIDENCE_ENVELOPES.md) for the separate meanings of computation, independent checking, integrity digests, and formal-kernel records, including the request-bound Lean-to-envelope adapter, authenticated runner receipts, Ed25519 public-key verification, and their trust/key-management limitations.

See [recursive derivation trees](docs/RECURSIVE_DERIVATION_TREES.md) and [derivation-to-obligation graph compilation](docs/DERIVATION_OBLIGATION_GRAPHS.md) for the current decomposition contracts and trust limitations.

## Planned work

Independently checked canonical certificates, broader task-bound operation coverage, additional vendor-specific provider implementations, parallel scheduling, durable execution storage, an MCP adapter, stronger resource isolation, richer domain-aware semantics, and broader formal proof workflows remain future work. Lean-kernel integration and the initial provider-neutral AI candidate gateway are implemented for the bounded operations documented below. The operation registry also includes planned operations such as `solve`, `verify_certificate`, `search`, `counterexample`, and `analyze`; unsupported operations return an explicit status.

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

## AI model integration

Existing AI systems can register the portable function tool from `GET /v1/ai/tool-schema` and submit proposals to `POST /v1/ai/candidate`. MOSAIC
validates the candidate against the unchanged mathematical request, checks
supported semantic conditions, and invokes a request-bound Lean checker where
available. The response distinguishes formal verification from rejected,
incomplete, unsupported, kernel-unavailable, and experimental outcomes.
Provider identity is provenance only; models cannot supply Lean source or
upgrade their own claims. Python callers can use
`MosaicClient.verify_model_candidate(...)`. See the
[AI integration contract](docs/MODEL_INTEGRATION.md).

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


## Optional Lean kernel verification

MOSAIC includes Lean-backed checkers for closed natural-number equalities,
affine integer identities, bounded polynomial identities, request-bound
transformations, and bounded real-polynomial derivatives.

- Closed natural-number equalities, using the pinned core Lean toolchain.
- Universally quantified affine integer identities, using Lean's `omega`
  tactic.
- Bounded polynomial integer identities, using a separate pinned Mathlib
  Lake project and `Mathlib.Tactic.Ring`.

The polynomial checker accepts variables `x`, `y`, and `z`; bounded integer
literals; unary signs; addition, subtraction, multiplication; and
nonnegative integer powers. Both `^` and `**` are accepted for powers.
Division, negative powers, function calls, unknown variables, oversized
expressions, and caller-supplied Lean source are unsupported.

The derivative checker supports univariate polynomials in `x` over `ℝ`. In
the model gateway, it binds the proposed derivative to the original request,
compares exact polynomial coefficients, and asks Lean to prove the submitted
result is the derivative. It does not cover rational functions or partial
derivatives. See [the derivative backend contract](docs/LEAN_POLYNOMIAL_DERIVATIVES.md).

Available endpoints:

- `POST /v1/verify/lean/closed-nat-equality`
- `POST /v1/verify/lean/polynomial-int-identity`
- `POST /v1/verify/lean/request-identity`
- `POST /v1/verify/lean/transformation`
- `POST /v1/verify/lean/polynomial-real-derivative` (optional `candidate_derivative`)

Request-bound identity and transformation checks retain request/candidate
hashes, checker identifiers, and generated proof-source fingerprints. A
`FORMALLY_VERIFIED` result is returned only when the configured Lean kernel
accepts MOSAIC-generated source. If the proof environment is unavailable, the
response says so; experimental symbolic computation is never substituted for
a formal proof.

The polynomial project pins Lean 4.36.0 and Mathlib commit
`fc4f59e577feb1a4956671bc04ac18aaaf8cd842`. Its real-kernel CI workflow
tests accepted identities, a rejected identity, unsupported syntax, and a
request-bound proof. See [the polynomial backend contract](docs/LEAN_POLYNOMIAL_BACKEND.md),
[the architecture](docs/ARCHITECTURE.md), and [security limitations](SECURITY.md).

A polynomial proof over `Int` does not establish rational-function domain
preservation, denominator nonzeroness, inequalities, or canonical form. The
Lean subprocess also requires deployment-level resource isolation; a timeout
alone is not a complete sandbox.
