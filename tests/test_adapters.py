import asyncio
import pytest

from mosaic.core.adapters import (
    ModelCapability, ModelRequest, ProviderError, ProviderRegistry, invoke_provider,
)
from mosaic.core.orchestration import AgentRole


class FakeProvider:
    def __init__(self, output="candidate result", delay=0):
        self._capability = ModelCapability(
            provider_id="fake",
            model_id="fake-model-v1",
            supported_roles=(AgentRole.SOLVER,),
            max_input_chars=100,
            max_output_chars=100,
        )
        self.output = output
        self.delay = delay

    @property
    def capability(self):
        return self._capability

    async def generate(self, request):
        await asyncio.sleep(self.delay)
        return self.output


def request(**kwargs):
    values = {
        "role": AgentRole.SOLVER,
        "system_instruction": "Propose, do not claim proof.",
        "prompt": "Factor x^2+x",
    }
    values.update(kwargs)
    return ModelRequest(**values)


def test_provider_registry_is_explicit_and_rejects_duplicates():
    registry = ProviderRegistry()
    provider = FakeProvider()
    registry.register(provider)
    assert registry.provider_ids() == ("fake",)
    assert registry.get("fake") is provider
    with pytest.raises(ValueError, match="already registered"):
        registry.register(provider)
    with pytest.raises(ProviderError, match="not allow-listed"):
        registry.get("unknown")


def test_adapter_returns_hashes_and_experimental_status():
    response = asyncio.run(invoke_provider(FakeProvider(), request()))
    assert response.provider_id == "fake"
    assert len(response.prompt_sha256) == 64
    assert len(response.output_sha256) == 64
    assert response.mathematical_status == "EXPERIMENTAL"


def test_unsupported_role_is_rejected_before_call():
    bad = ModelRequest(
        role=AgentRole.CRITIC,
        system_instruction="Review",
        prompt="Check this",
    )
    with pytest.raises(ProviderError, match="does not support role"):
        asyncio.run(invoke_provider(FakeProvider(), bad))


class TimeoutProvider(FakeProvider):
    async def generate(self, request):
        raise asyncio.TimeoutError()


def test_timeout_is_bounded():
    with pytest.raises(ProviderError, match="timed out"):
        asyncio.run(invoke_provider(TimeoutProvider(), request()))


def test_output_limit_is_enforced():
    with pytest.raises(ProviderError, match="output exceeds"):
        asyncio.run(invoke_provider(FakeProvider(output="x" * 101), request()))


def test_input_limit_is_enforced():
    with pytest.raises(ProviderError, match="input limit"):
        asyncio.run(invoke_provider(FakeProvider(), request(prompt="x" * 101)))


def test_empty_output_is_rejected():
    with pytest.raises(ProviderError, match="empty"):
        asyncio.run(invoke_provider(FakeProvider(output="  "), request()))
