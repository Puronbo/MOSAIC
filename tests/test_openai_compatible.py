import asyncio
import json

import httpx
import pytest

from mosaic.core.adapters import ModelRequest, ProviderError, invoke_provider
from mosaic.core.openai_compatible import OpenAICompatibleProvider
from mosaic.core.orchestration import AgentRole


def make_request():
    return ModelRequest(
        role=AgentRole.SOLVER,
        system_instruction="Propose a candidate only.",
        prompt="Factor x^2 + x",
        max_output_tokens=128,
    )


def test_openai_compatible_provider_sends_chat_payload_and_auth():
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        seen["auth"] = request.headers["Authorization"]
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={
            "choices": [{"message": {"content": "x*(x+1)"}}]
        })

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = OpenAICompatibleProvider(
        base_url="https://models.example/v1",
        api_key="test-secret",
        model_id="math-model",
        client=client,
    )
    result = asyncio.run(invoke_provider(provider, make_request()))

    assert result.output == "x*(x+1)"
    assert result.mathematical_status == "EXPERIMENTAL"
    assert seen["url"] == "https://models.example/v1/chat/completions"
    assert seen["auth"] == "Bearer test-secret"
    assert seen["body"]["model"] == "math-model"
    assert seen["body"]["max_tokens"] == 128
    asyncio.run(client.aclose())


def test_provider_appends_v1_for_root_base_url():
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(200, json={
            "choices": [{"message": {"content": "candidate"}}]
        })

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = OpenAICompatibleProvider(
        base_url="https://models.example",
        api_key="key",
        model_id="m",
        client=client,
    )
    asyncio.run(provider.generate(make_request()))
    assert seen == ["https://models.example/v1/chat/completions"]
    asyncio.run(client.aclose())


@pytest.mark.parametrize("base_url", [
    "http://models.example",
    "https://user:pass@models.example",
    "https://models.example?token=secret",
    "not-a-url",
])
def test_unsafe_or_invalid_base_urls_are_rejected(base_url):
    with pytest.raises(ValueError):
        OpenAICompatibleProvider(
            base_url=base_url, api_key="key", model_id="m"
        )


def test_localhost_http_is_allowed_for_development():
    provider = OpenAICompatibleProvider(
        base_url="http://localhost:8080/v1",
        api_key="local",
        model_id="local-model",
    )
    assert provider.capability.provider_id == "openai-compatible"
    asyncio.run(provider.aclose())


def test_http_error_is_sanitized():
    def handler(request):
        return httpx.Response(429, json={"error": {"message": "sensitive detail"}})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = OpenAICompatibleProvider(
        base_url="https://models.example",
        api_key="key",
        model_id="m",
        client=client,
    )
    with pytest.raises(ProviderError, match="HTTP 429") as exc:
        asyncio.run(provider.generate(make_request()))
    assert "sensitive detail" not in str(exc.value)
    asyncio.run(client.aclose())


def test_redirect_is_rejected():
    def handler(request):
        return httpx.Response(302, headers={"Location": "https://other.example/"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = OpenAICompatibleProvider(
        base_url="https://models.example",
        api_key="key",
        model_id="m",
        client=client,
    )
    with pytest.raises(ProviderError, match="redirects"):
        asyncio.run(provider.generate(make_request()))
    asyncio.run(client.aclose())


def test_malformed_response_is_rejected():
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json={"choices": []}))
    )
    provider = OpenAICompatibleProvider(
        base_url="https://models.example",
        api_key="key",
        model_id="m",
        client=client,
    )
    with pytest.raises(ProviderError, match="invalid chat-completions"):
        asyncio.run(provider.generate(make_request()))
    asyncio.run(client.aclose())
