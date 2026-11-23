# OpenAI-compatible provider

MOSAIC includes an optional HTTP adapter for services implementing the common
OpenAI chat-completions request/response shape. It can target a hosted service
or a self-hosted endpoint without coupling the mathematical core to a vendor SDK.

## Example

```python
import os

from mosaic.core.adapters import ProviderRegistry
from mosaic.core.openai_compatible import OpenAICompatibleProvider
from mosaic.core.orchestration import AgentRole

provider = OpenAICompatibleProvider(
    base_url=os.environ["MOSAIC_MODEL_BASE_URL"],
    api_key=os.environ["MOSAIC_MODEL_API_KEY"],
    model_id=os.environ["MOSAIC_MODEL_ID"],
    provider_id="primary-model",
    supported_roles=(AgentRole.SOLVER, AgentRole.CRITIC),
)
registry = ProviderRegistry()
registry.register(provider)
```

Then assign `"primary-model"` to task IDs passed to
`execute_task_graph(...)`. Use environment variables or a secret manager for
credentials; never commit API keys or put them in task prompts.

## Endpoint and safety behavior

- Uses `/v1/chat/completions` (or `/chat/completions` when the base URL already
  ends in `/v1`).
- Requires HTTPS, except for localhost/loopback development endpoints.
- Rejects URL credentials, query strings, fragments, and HTTP redirects.
- Does not log request bodies, response bodies, or credentials.
- Converts HTTP and response-shape failures into sanitized provider errors.
- Accepts an injected `httpx.AsyncClient` for custom transports and tests.
- Closes only clients it created itself, via `await provider.aclose()`.

This is a compatibility adapter, not a guarantee that every vendor's API
supports identical request fields. Some services may require a small provider-
specific extension. The provider returns raw text only; the common adapter
applies timeouts, character bounds, and provenance hashes.

## Trust boundary

Responses remain untrusted proposals with `EXPERIMENTAL` mathematical status.
A successful HTTP response, model self-report, or agreement between models does
not establish mathematical correctness. Route candidate claims to independent
checkers or a trusted proof kernel.
