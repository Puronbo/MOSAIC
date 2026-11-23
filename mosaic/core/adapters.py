"""Provider-neutral model adapter contracts.

Providers are untrusted proposal generators. This module does not verify math.
"""
import asyncio
import hashlib
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from mosaic.core.orchestration import AgentRole


class ModelCapability(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    provider_id: str = Field(min_length=1, max_length=80)
    model_id: str = Field(min_length=1, max_length=160)
    supported_roles: tuple[AgentRole, ...]
    max_input_chars: int = Field(default=16000, ge=1, le=200000)
    max_output_chars: int = Field(default=8000, ge=1, le=50000)


class ModelRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    role: AgentRole
    system_instruction: str = Field(min_length=1, max_length=4000)
    prompt: str = Field(min_length=1, max_length=16000)
    max_output_tokens: int = Field(default=2000, ge=1, le=20000)
    timeout_seconds: int = Field(default=30, ge=1, le=300)


class ModelResponse(BaseModel):
    """Auditable provider response; output remains an untrusted proposal."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    provider_id: str
    model_id: str
    output: str = Field(min_length=1, max_length=50000)
    prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    output_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    elapsed_ms: int = Field(ge=0)
    mathematical_status: str = "EXPERIMENTAL"


class ProviderError(RuntimeError):
    """Provider is unavailable, incompatible, or returned invalid output."""


@runtime_checkable
class ModelProvider(Protocol):
    @property
    def capability(self) -> ModelCapability: ...

    async def generate(self, request: ModelRequest) -> str:
        """Return raw model text. Implementations must not claim verification."""
        ...


class ProviderRegistry:
    """Explicit allow-list of provider implementations."""

    def __init__(self) -> None:
        self._providers: dict[str, ModelProvider] = {}

    def register(self, provider: ModelProvider) -> None:
        provider_id = provider.capability.provider_id
        if provider_id in self._providers:
            raise ValueError(f"provider already registered: {provider_id}")
        self._providers[provider_id] = provider

    def get(self, provider_id: str) -> ModelProvider:
        try:
            return self._providers[provider_id]
        except KeyError as exc:
            raise ProviderError(f"provider is not allow-listed: {provider_id}") from exc

    def provider_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._providers))


async def invoke_provider(
    provider: ModelProvider,
    request: ModelRequest,
) -> ModelResponse:
    """Invoke one provider under strict timeout and payload bounds."""
    capability = provider.capability
    if request.role not in capability.supported_roles:
        raise ProviderError(f"provider does not support role: {request.role.value}")
    input_size = len(request.system_instruction) + len(request.prompt)
    if input_size > capability.max_input_chars:
        raise ProviderError("request exceeds provider input limit")

    prompt_hash = hashlib.sha256(
        (request.system_instruction + "\\0" + request.prompt).encode("utf-8")
    ).hexdigest()
    loop = asyncio.get_running_loop()
    started = loop.time()
    try:
        raw = await asyncio.wait_for(
            provider.generate(request),
            timeout=request.timeout_seconds,
        )
    except asyncio.TimeoutError as exc:
        raise ProviderError("provider request timed out") from exc
    except ProviderError:
        raise
    except Exception as exc:
        raise ProviderError("provider request failed") from exc

    if not isinstance(raw, str) or not raw.strip():
        raise ProviderError("provider returned empty or non-text output")
    if len(raw) > capability.max_output_chars:
        raise ProviderError("provider output exceeds configured limit")
    return ModelResponse(
        provider_id=capability.provider_id,
        model_id=capability.model_id,
        output=raw,
        prompt_sha256=prompt_hash,
        output_sha256=hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        elapsed_ms=max(0, int((loop.time() - started) * 1000)),
        mathematical_status="EXPERIMENTAL",
    )
