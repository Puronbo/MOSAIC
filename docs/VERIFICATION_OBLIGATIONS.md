# First-class verification obligations

A `VerificationObligation` is a typed statement of what MOSAIC must check,
which request it belongs to, and which checker identifier is authorized.
Create the initial obligation set with
`mosaic.verification.obligations.obligations_for_request(request)`.

Each obligation carries:

- a stable identifier derived from the request fingerprint;
- a kind (`identity`, `transformation`, or `unsupported`);
- the SHA-256 fingerprint of the complete versioned request;
- the requested operation and a human-readable statement;
- an explicit checker identifier, or `none` when no checker is registered;
- an assumptions tuple, empty by default.

The initial factory emits one primary obligation per request. It names the
existing symbolic identity checker or the deterministic recomputation checker
for simplify, expand, factor, and differentiate. Other operations are marked
unsupported rather than assigned a speculative checker.

Obligations are contracts, not evidence that a result is true. Their hashes
bind the obligation to a request representation but do not authenticate the
caller or establish mathematical truth. A later proof workflow can extend
this model with sub-obligations, domain conditions, proof-object formats, and
kernel identities without treating model output as trusted.
