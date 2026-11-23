# Provider adapter contract (v11.5)

## Goal

Allow MOSAIC to connect to different model vendors or self-hosted models without making provider-specific concepts part of the mathematical core.

## Interface

A provider exposes immutable capability metadata and one asynchronous `generate` method. Capability metadata declares provider/model IDs, supported agent roles, and input/output character limits. Requests contain only the role, bounded instructions and prompt, output-token budget, and timeout. Credentials and endpoint configuration belong inside the provider implementation, never in a mathematical task or user request.

## Runtime guarantees

The shared invocation boundary:
- checks the requested role against declared capabilities;
- rejects oversized inputs before dispatch;
- applies a wall-clock timeout;
- rejects empty, non-text, or oversized output;
- records provider/model IDs, elapsed time, and SHA-256 hashes of prompt and output.

The registry is an explicit allow-list and rejects duplicate provider IDs. The adapter does not implement retries, concurrency scheduling, provider discovery, secret storage, or network transport. Concrete providers must use secure transport, keep credentials out of logs, and apply their own vendor-specific token limits.

## Trust policy

Every response is untrusted model text. Hashes establish content integrity, not truth. Provider identity, model identity, latency, or agreement with other providers does not establish correctness. The adapter always labels the mathematical status `EXPERIMENTAL`; independent symbolic checking or a trusted proof kernel remains a separate step.

## Adding a provider

Implement `ModelProvider`, expose a `ModelCapability`, and implement asynchronous `generate(ModelRequest) -> str`. Register the provider explicitly at application startup. Keep provider-specific SDK imports and credential handling inside that adapter. Test timeout, malformed output, output bounds, and supported roles.

## Current implementation boundary

`mosaic.core.adapters` contains the protocol, request/response contracts, allow-list registry, and bounded invocation wrapper. An opt-in OpenAI-compatible HTTP implementation is provided in `mosaic.core.openai_compatible`. It is not enabled automatically; applications must configure and register it explicitly. No external model is called by the core package on its own.

See [OPENAI_COMPATIBLE_PROVIDER.md](OPENAI_COMPATIBLE_PROVIDER.md) for configuration, endpoint policy, and usage.
