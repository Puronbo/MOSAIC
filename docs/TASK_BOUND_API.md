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
