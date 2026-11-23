# Verified Agent Loop

MOSAIC exposes a provider-neutral, bounded proposal/revision loop through
`mosaic.core.verified_agent.run_verified_agent`.

```python
import asyncio
from mosaic.core.openai_compatible import OpenAICompatibleProvider
from mosaic.core.requests import MathRequest
from mosaic.core.verified_agent import run_verified_agent

async def main():
    provider = OpenAICompatibleProvider(
        base_url="https://your-compatible-endpoint/v1",
        api_key="YOUR_KEY",
        model_id="your-model",
    )
    try:
        result = await run_verified_agent(
            MathRequest(
                operation="verify_identity",
                expression="x + 1",
                rhs="1 + x",
            ),
            provider,
            max_attempts=3,
        )
        print(result.model_dump(mode="json"))
    finally:
        await provider.aclose()

asyncio.run(main())
```

## Wrap an existing model SDK

You do not need to replace your current model client or adopt a specific
agent framework. Adapt its call with `CallableModelProvider` and keep
credentials in your application's existing SDK configuration:

```python
from mosaic.core.adapters import (
    CallableModelProvider,
    ModelCapability,
    ModelRequest,
)
from mosaic.core.orchestration import AgentRole

# Existing SDK client is created and authenticated by your application.
async def call_existing_model(request: ModelRequest) -> str:
    response = await existing_sdk.generate(
        system=request.system_instruction,
        prompt=request.prompt,
        max_tokens=request.max_output_tokens,
    )
    return response.text

provider = CallableModelProvider(
    ModelCapability(
        provider_id="my-application",
        model_id="my-current-model",
        supported_roles=(AgentRole.SOLVER,),
    ),
    call_existing_model,
)
```

The callback receives a bounded `ModelRequest` and returns raw text. A normal
synchronous callback is also supported and is executed in a worker thread;
async callbacks remain asynchronous. The adapter does not interpret model
output, add credentials to prompts, or assign mathematical status. Pass this
provider to `run_verified_agent` as in the example above. Provider IDs are
provenance labels, not trust signals.
The loop asks the provider for a strict JSON candidate, submits the exact
unchanged request and raw candidate to MOSAIC's independent gateway, and feeds
structured checker feedback into a bounded revision attempt when the candidate
is malformed or mathematically rejected. It stops after at most three attempts.

Important boundaries:

- Provider output, confidence, and self-reported status are never trusted.
- The provider cannot supply Lean source or tactics.
- A retry does not change the original mathematical request.
- Kernel outages and unsupported semantics stop immediately; a new model
  answer cannot repair a missing verifier.
- Only `FORMALLY_VERIFIED` means task-bound checks passed and the configured
  Lean kernel accepted the request-bound proposition.
- Other statuses remain distinct; a Python-side algebraic match is not silently
  promoted to formal proof. Differentiation currently has task-bound experimental
  comparison but no dedicated Lean derivative checker, so it cannot return
  `FORMALLY_VERIFIED` through this gateway. Integration is not currently
  supported by task-bound candidate checking.
- The returned trace records provider/model labels, prompt/output hashes, and
  the complete checker evaluation for each attempt.

This helper is an orchestration primitive, not a hosted model service. API keys
remain in the provider adapter's configuration and must be supplied securely
by the application.
