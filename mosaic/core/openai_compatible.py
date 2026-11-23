"""OpenAI-compatible chat-completions provider.

This adapter is optional and keeps credentials outside MOSAIC task data.
"""
from urllib.parse import urlsplit

import httpx

from mosaic.core.adapters import ModelCapability, ModelRequest, ProviderError
from mosaic.core.orchestration import AgentRole


class OpenAICompatibleProvider:
    """Call an OpenAI-compatible /chat/completions endpoint.

    HTTPS is required except for loopback development endpoints. Redirects are
    rejected so bearer credentials cannot be forwarded to another origin.
    Pass an httpx.AsyncClient to support custom transports and deterministic tests.
    """

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        model_id: str,
        provider_id: str = "openai-compatible",
        supported_roles: tuple[AgentRole, ...] = tuple(AgentRole),
        max_input_chars: int = 16000,
        max_output_chars: int = 8000,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        parsed = urlsplit(base_url)
        if (
            parsed.scheme not in {"https", "http"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("base_url must be an absolute HTTP(S) URL without credentials, query, or fragment")
        loopback_hosts = {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme != "https" and parsed.hostname.lower() not in loopback_hosts:
            raise ValueError("HTTPS is required except for localhost development endpoints")
        if not api_key.strip():
            raise ValueError("api_key must not be empty")
        if not base_url.strip():
            raise ValueError("base_url must not be empty")

        root = base_url.rstrip("/")
        self._endpoint = (
            root + "/chat/completions"
            if parsed.path.rstrip("/").endswith("/v1")
            else root + "/v1/chat/completions"
        )
        self._api_key = api_key
        self._client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(30.0),
            follow_redirects=False,
        )
        self._owns_client = client is None
        self._capability = ModelCapability(
            provider_id=provider_id,
            model_id=model_id,
            supported_roles=supported_roles,
            max_input_chars=max_input_chars,
            max_output_chars=max_output_chars,
        )

    @property
    def capability(self) -> ModelCapability:
        return self._capability

    async def generate(self, request: ModelRequest) -> str:
        payload = {
            "model": self.capability.model_id,
            "messages": [
                {"role": "system", "content": request.system_instruction},
                {"role": "user", "content": request.prompt},
            ],
            "max_tokens": request.max_output_tokens,
        }
        try:
            response = await self._client.post(
                self._endpoint,
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
            )
        except httpx.HTTPError as exc:
            raise ProviderError("OpenAI-compatible endpoint request failed") from exc

        if 300 <= response.status_code < 400:
            raise ProviderError("provider redirects are not permitted")
        if response.status_code < 200 or response.status_code >= 300:
            raise ProviderError(f"provider returned HTTP {response.status_code}")

        try:
            data = response.json()
            content = data["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise ProviderError("provider returned an invalid chat-completions response") from exc
        if not isinstance(content, str) or not content.strip():
            raise ProviderError("provider returned empty or non-text message content")
        return content

    async def aclose(self) -> None:
        """Close only the HTTP client created and owned by this provider."""
        if self._owns_client:
            await self._client.aclose()
