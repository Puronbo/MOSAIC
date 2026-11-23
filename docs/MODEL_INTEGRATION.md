# AI model integration contract

MOSAIC exposes a provider-neutral candidate boundary at
`POST /v1/ai/candidate`. An existing model, agent framework, or orchestration
system can call this endpoint after generating a mathematical candidate. The
endpoint does not call a model; it is the independent verification side of the
integration.

## Registering the tool with an AI agent

Fetch `GET /v1/ai/tool-schema` to obtain a portable function-tool declaration
named `mosaic_verify_candidate`. Register that declaration with an agent
framework that supports function tools. When the model requests the tool, your
application forwards its arguments to `POST /v1/ai/candidate` and returns the
JSON response to the model as tool output.

This separates three responsibilities: the model proposes a candidate, the
agent runtime transports tool calls, and MOSAIC independently evaluates the
candidate. MOSAIC does not invoke the model or assume that a tool call itself
is trustworthy. The returned status and checker details—not the model's
description of the tool result—are authoritative.

## Request

The request carries the original mathematical task separately from the
candidate text. Provider and model identifiers are optional provenance labels,
not trust signals.

```json
{
  "request": {
    "schema_version": "1.0",
    "operation": "verify_identity",
    "expression": "(x + 1)**2",
    "variable": "x",
    "rhs": "x**2 + 2*x + 1"
  },
  "candidate": "{\"operation\":\"verify_identity\",\"expression\":\"(x + 1)**2\",\"rhs\":\"x**2 + 2*x + 1\"}",
  "provider_id": "my-provider",
  "model_id": "my-model"
}
```

For simplify/expand/factor tasks, the candidate JSON must use the existing
task-bound transformation shape and include `operation`, the exact original
`expression`, the exact `variable`, and a proposed `result`. The model
cannot replace the request with a self-selected proposition.

## Verification sequence

1. MOSAIC parses the candidate using strict, bounded claim schemas.
2. The task-bound checker confirms that the claim matches the original request
   and independently recomputes the requested operation.
3. Transformations must also pass the available rational-domain preservation
   check before they can advance to formal checking.
4. For eligible identity, simplify/expand/factor, and bounded univariate
   differentiation tasks, MOSAIC generates its own Lean obligation and invokes
   the configured Lean checker. Differentiation currently supports real
   polynomials in `x` only; the submitted derivative is checked against an
   independently computed polynomial and is the conclusion of the Lean theorem.
5. The response binds the original request and exact candidate to SHA-256
   fingerprints and reports each checker result separately.

A model cannot submit Lean source, choose a tactic, replace the proposition,
or set a mathematical status. Unknown fields are rejected. Provider/model
labels are retained only to help trace which proposal was evaluated.

Every evaluation also includes a `feedback` array. Each item has a stable
code, severity, suggested action, and `retryable` flag. For example, an
algebraic mismatch asks the agent to recompute from the unchanged request;
lost domain restrictions ask it to preserve the original excluded values;
unsupported checks and experimental-only results are explicitly non-retryable
as proof claims. A formal-kernel outage is retryable operationally, but never
counts as a successful proof. Feedback is guidance derived from checker
outputs, not mathematical evidence.

## Status policy

- `FORMALLY_VERIFIED`: task-bound checks passed and the request-bound
  proposition was accepted by the configured Lean kernel.
- `REJECTED`: the task-bound checker found a mismatch.
- `INVALID_CANDIDATE`: the model output does not match a supported claim
  schema or the exact request.
- `INCOMPLETE`: an additional semantic condition, such as domain
  preservation, did not pass.
- `UNSUPPORTED`: the claim is outside the supported grammar or semantics.
- `KERNEL_UNAVAILABLE` / `KERNEL_ERROR`: formal verification could not
  complete; this is not a successful proof.
- `EXPERIMENTAL`: task-bound checks passed but no formal checker is available
  for that operation (including differentiation in variables other than `x`
  or outside the bounded polynomial grammar).

The API never upgrades a model's own assertion, confidence, or agreement with
other models into evidence. A hash establishes input/report identity, not
truth. `FORMALLY_VERIFIED` is limited to the precise proposition and semantics
of the selected Lean checker; for example, polynomial equivalence over
integers does not establish rational-function domain preservation.

## Python client

```python
from mosaic.client import MosaicClient
from mosaic.core.requests import MathRequest

client = MosaicClient("http://127.0.0.1:8000")
tool = client.ai_tool_schema()  # register this with your agent runtime
request = MathRequest(
    operation="verify_identity",
    expression="(x + 1)**2",
    rhs="x**2 + 2*x + 1",
)
result = client.verify_model_candidate(
    request,
    '{"operation":"verify_identity","expression":"(x + 1)**2",'
    '"rhs":"x**2 + 2*x + 1"}',
    provider_id="my-provider",
    model_id="my-model",
)
print(result["status"])
```

Any model provider can be used: the caller invokes its own model, serializes
the candidate into MOSAIC's bounded claim format, and submits it. This keeps
provider credentials and provider-specific APIs outside the mathematical
verification service. The existing asynchronous provider adapters can be used
for model orchestration, while this endpoint remains the trust boundary.

## Operational limits

This is an early integration contract, not a hosted multi-tenant service.
Deployments must add authentication, authorization, rate limiting, request
logging policy, and resource isolation before accepting untrusted public
traffic. The Lean subprocess timeout is not a complete sandbox. Do not send
secrets in mathematical requests or candidate text.
