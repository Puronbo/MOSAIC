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

The response envelope contains `schema_version`, `checker_id`, and a
structured `check`. The check includes request and candidate hashes, status,
equality result, and (when applicable) a candidate-bound domain-preservation
certificate. Consumers should retain the complete response and may rerun the
identified checker against the original inputs.

A response with `EXPERIMENTAL` is not a proof. Hashes bind the report to the
inputs; they do not establish mathematical truth. `INCOMPLETE`,
`INVALID_CERTIFICATE`, and `UNSUPPORTED` are distinct outcomes. Candidate
payloads are limited to 10,000 characters, and the enclosing request models
reject unknown fields.

This endpoint reuses the same checker as the Python verification layer. It
does not call an AI provider, accept provider assertions as trusted evidence,
or upgrade symbolic computation to formal proof.
