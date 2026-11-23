# Security model

MOSAIC treats expressions, tool outputs, and model-generated suggestions as untrusted input.

## Current prototype safeguards

- Parses expressions with Python's AST and converts an allow-listed grammar; it never evaluates raw user input.
- Rejects attribute access, subscripting, comprehensions, lambdas, imports, keyword arguments, and unknown function names.
- Applies input-length and AST-node-count limits.
- Restricts supported symbols and mathematical functions.
- Distinguishes symbolic computation from formal verification.

## Known limitations

This is an early prototype, not a hardened multi-tenant service. Symbolic operations can still consume substantial CPU or memory. Production deployment requires process isolation, wall-clock and memory limits, request quotas, dependency auditing, observability, and explicit tool permissions. Do not expose an unrestricted worker to untrusted public traffic.

A symbolic simplification result is not automatically a formal proof. Formal proof status must be backed by a trusted proof checker and retained provenance.
