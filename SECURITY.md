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


## Optional Lean kernel bridge

The optional closed-natural-number equality endpoint does not accept Lean
source from callers. MOSAIC parses a small arithmetic expression grammar and
generates one fixed theorem using only Nat literals, addition,
multiplication, bounded powers, and the built-in decision procedure. This
prevents candidate text from injecting imports, macros, tactics, or arbitrary
elaborator code into the generated file.

The endpoint invokes a locally configured Lean executable with a wall-clock
timeout and a temporary working directory. A successful result is limited to
the exact closed Nat equality submitted and generated; it does not verify
symbolic expressions with variables, real/rational domains, assumptions, or
general transformation requests. The Lean executable and its installation
remain part of the trusted computing base. The current subprocess boundary is
not a complete OS sandbox and does not impose a memory limit. Do not expose
this endpoint to hostile public traffic without process/container isolation,
resource quotas, and a pinned, audited Lean toolchain.
