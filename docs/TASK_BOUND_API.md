# Task-bound verification API

The HTTP API exposes the existing task-bound candidate checker at
`POST /v1/verify/task-bound`. It accepts a mathematical request and an
untrusted candidate as separate fields:

```json
{
  "request": {
    "schema_version": "1.0",
    "operation": "simplify",
    "expression": "(x**2 - 1)/(x - 1)",
    "variable": "x"
  },
  "candidate": "{\"operation\":\"simplify\",\"expression\":\"(x**2 - 1)/(x - 1)\",\"variable\":\"x\",\"result\":\"x + 1\"}"
}
```

The candidate cannot select or redefine its task. The checker binds its
operation, expression, and variable to the supplied request, recomputes the
expected result, and performs the existing rational-domain comparison for
simplify/expand/factor candidates.

## Response and revision loop

Response schema version `1.1` contains `checker_id`, the complete structured
`check`, and a `feedback` array. Feedback entries have stable machine-facing
codes, severity, a human-readable message, a suggested next action, and a
`retryable` flag. Current codes include:

- `DOMAIN_RESTRICTION_LOST`: preserve the original excluded values; missing
  factors are included when the checker can identify them.
- `ALGEBRAIC_MISMATCH`: recompute the operation from the unchanged request.
- `INVALID_CANDIDATE`: correct the claim schema or exact task binding.
- `UNSUPPORTED_CHECK`: do not treat the candidate as accepted.
- `REVIEW_RESULT`: available experimental checks passed, but proof is not
  established.

An agent loop should retain the original request unchanged, revise only its
candidate, and resubmit it. It should stop or escalate when feedback is not
retryable. Feedback is guidance, not evidence; the checker result and its
limitations remain authoritative. No provider identity or model-generated
confidence can upgrade a result.

The check includes request and candidate hashes, status, equality result, and
(where applicable) a candidate-bound domain-preservation certificate.
Consumers should retain the complete response and may rerun the identified
checker against the original inputs.

A response with `EXPERIMENTAL` is not a proof. Hashes bind the report to the
inputs; they do not establish mathematical truth. `INCOMPLETE`,
`INVALID_CERTIFICATE`, and `UNSUPPORTED` are distinct outcomes. Candidate
payloads are limited to 10,000 characters, and the enclosing request models
reject unknown fields.

This endpoint reuses the same checker as the Python verification layer. It
does not call an AI provider, accept provider assertions as trusted evidence,
or upgrade symbolic computation to formal proof.

# Persistent verification sessions

MOSAIC exposes an append-only SQLite-backed session API:

- `POST /v1/verification-sessions` creates a session with one immutable
  `MathRequest`.
- `POST /v1/verification-sessions/{session_id}/revisions` checks and appends
  a candidate against that stored request.
- `GET /v1/verification-sessions/{session_id}` returns the original request,
  its SHA-256 fingerprint, and the ordered revision history.

Revision numbers are assigned transactionally by SQLite. Each revision stores
the raw candidate, the complete task-bound checker result, structured feedback,
and a UTC timestamp. The request and existing revision rows are protected by
database triggers against updates. Revisions are append-only through this API;
this is an integrity-oriented local ledger, not a tamper-proof audit system
against an administrator who can replace the database file.

The database path is configured by `MOSAIC_SESSION_DB`; the default is
`mosaic_sessions.sqlite3` in the service working directory. SQLite creates
the database and parent directory as needed. Use a persistent volume for
deployment if sessions must survive process or container replacement.

A session ID is an unguessable UUID, but the prototype does not implement user
authentication, tenant isolation, retention policies, encryption at rest, or
multi-host storage. Do not expose this API publicly or store sensitive data
without adding those controls. Back up the database and restrict filesystem
permissions appropriately.

Every revision is verified against the stored original request. Clients cannot
supply a replacement request when appending. The stored hash is the canonical
request fingerprint used by the task-bound checker. A passing experimental
result is still not a formal proof.

## Revision progress and stopping policy

Each appended revision includes an `assessment` computed from checker outputs,
not model confidence or textual similarity:

- `FIRST_ATTEMPT`: no earlier candidate exists.
- `IMPROVED`: a candidate that did not pass the available checks now does.
- `REGRESSED`: a previously passing experimental candidate no longer passes.
- `UNCHANGED`: the candidate is repeated or its checker outcome is unchanged.
- `CHANGED_UNRESOLVED`: the checker outcome changed but did not establish an improvement.

The accompanying recommendation is one of:

- `CONTINUE`: retryable checker feedback remains.
- `STOP_REVIEW`: available experimental checks passed; stop automated retries
  and route the result for review. This does not mean proved.
- `STOP_NO_PROGRESS`: an identical candidate was already submitted.
- `STOP_NONRETRYABLE`: the latest feedback does not offer a retryable correction.
- `STOP_REVISION_LIMIT`: the configured session limit was reached.

The default maximum is 20 revisions per session. A further append returns HTTP
409. The limit is configurable when constructing `SessionStore`. The assessment
is deliberately conservative: it compares discrete checker outcomes, not
semantic quality, elegance, or the magnitude of mathematical progress. It is
an orchestration hint, not evidence and not a proof status.

## Evidence provenance and independence

Every task-bound verification response and stored session revision now includes
an `evidence` bundle. Each item identifies the mathematical claim it concerns,
the registered checker, the exact request and candidate hashes, its finding
(`supports`, `refutes`, or `unresolved`), and an implementation
`independence_group`.

Evidence sources are allow-listed in MOSAIC code. A caller or candidate cannot
declare a new checker ID or independence group and have it counted. Findings
must refer to the same request and candidate hashes before they can be
aggregated. Conflicting findings are detected only when independent groups
disagree about the same claim; support for domain preservation and refutation
of algebraic equivalence are different claims, not a false conflict.

**Current implementation:** the task-bound algebraic check and rational-domain
comparison both rely on the same SymPy-backed symbolic runtime. For
simplify/expand/factor, MOSAIC also runs a bounded exact rational-polynomial
equivalence checker implemented with Python AST parsing and Fraction arithmetic,
without SymPy. These map to separate implementation groups. This permits
experimental multi-source corroboration for supported expressions, but does not
establish domain equality or constitute a formal proof.

Model outputs are not `EvidenceItem` records and do not contribute to the
independent checker count. Model identity, agreement, confidence, and majority
vote cannot upgrade the result. The optional Lean endpoint is a separate
formal-checking path and is not silently mixed into experimental evidence.
Even multiple independent experimental checkers do not automatically establish
a formal proof.


## Optional Lean closed-natural-number equality endpoint

`POST /v1/verify/lean/closed-nat-equality` accepts a strict JSON object with
`lhs` and `rhs` strings (each at most 512 characters). The expressions must
be closed natural-number arithmetic in a bounded grammar: non-negative integer
literals, addition, multiplication, and bounded integer powers. MOSAIC
generates the Lean theorem and proof script itself; caller-supplied Lean source,
imports, macros, tactics, variables, and assumptions are not accepted.

Possible statuses:

- `FORMALLY_VERIFIED`: the configured Lean executable accepted the generated
  theorem for this exact closed equality.
- `REJECTED`: Lean rejected the equality theorem.
- `KERNEL_UNAVAILABLE`: Lean is not installed or not on PATH.
- `UNSUPPORTED`: an expression is outside the supported grammar.
- `KERNEL_ERROR`: execution failed or exceeded the wall-clock limit.

This is a narrow proof bridge, not general symbolic proof support. It does not
prove identities with variables, rational-domain preservation, or arbitrary
transformation obligations. The configured Lean executable is part of the
trusted computing base; see [SECURITY.md](../SECURITY.md) for deployment
limitations.


## Request-bound Lean identity obligation

`POST /v1/verify/lean/request-identity` accepts the standard
`{ "request": MathRequest }` envelope. It does not accept proposition text
or a caller-selected obligation. MOSAIC derives both sides directly from the
request and creates a request-fingerprinted
`lean.kernel.closed_nat_equality.v1` obligation. Only
`verify_identity` requests with an explicit right-hand side are eligible.
The generated Lean proposition has no additional assumptions.

A formal result therefore applies to the exact identity encoded in that
request, not to a nearby candidate or an independently supplied equation. The
Lean check includes a SHA-256 fingerprint of the exact generated theorem
source, alongside the hashes of the original left- and right-hand expressions,
so the checked artifact can be identified in downstream records.
The current Lean grammar still supports only closed natural-number arithmetic;
identities containing variables or rational-domain conditions remain
unsupported. This endpoint does not upgrade the general task-bound result or
the evidence bundle.


### Symbolic affine identities

For symbolic linear identities, the request-bound endpoint can derive an
assumption-free universally quantified proposition over `Int`, using only
the allow-listed variables `x`, `y`, and `z`. The affine compiler accepts
addition, subtraction, and multiplication by constants; it rejects products
of variables, division, and powers. The response identifies the linear
checker, quantified variables, request fingerprint, and generated theorem
source hash. A kernel-accepted affine identity is not a proof of rational
domain preservation and does not discharge calculus side conditions.


### Request-bound transformation endpoint

`POST /v1/verify/lean/transformation` accepts a `MathRequest` and a
proposed `result`. It currently supports only `simplify`, `expand`, and
`factor` requests where both expressions fit the affine-integer grammar.
MOSAIC creates a candidate-bound obligation and checks universal equivalence
over `Int` with Lean. A formal result means the proposed expression equals
the original for every integer assignment; it does not prove that the result
is canonical, preserve a rational-function domain, or satisfy any unmodeled
side conditions. Division and nonlinear products are rejected as unsupported.
