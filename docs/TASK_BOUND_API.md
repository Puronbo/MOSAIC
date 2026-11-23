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

**Current limitation:** the task-bound algebraic check and rational-domain
comparison both rely on the same SymPy-backed symbolic runtime. Their findings
are separately recorded, but both map to
`sympy_symbolic_runtime`, so the bundle counts at most one independent source
today. `MULTI_SOURCE_SUPPORT` is reserved for future separately registered
implementations with distinct independence groups; it is not produced by
duplicating model calls.

Model outputs are not `EvidenceItem` records and do not contribute to the
independent checker count. Model identity, agreement, confidence, and majority
vote cannot upgrade the result. Formal-kernel evidence will require a separate
registered integration and its own explicit trust contract. Even multiple
independent experimental checkers do not automatically establish a formal
proof.
