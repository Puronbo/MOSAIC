# Evidence Envelopes and Trust Boundaries

MOSAIC has two related evidence mechanisms:

- `mosaic.verification.evidence` aggregates registered checker findings for
  task-bound mathematical candidates. It tracks claim-level support,
  refutation, unresolved findings, and checker independence groups.
- `mosaic.verification.evidence_envelope` packages provenance events against
  one exact result artifact and adds a canonical SHA-256 integrity digest.

`evidence_bundle_to_envelope` connects the two. It preserves each registered
checker finding as a separate event and binds the envelope to the candidate
hash already present in the checker evidence.

## Evidence kinds

| Kind | What it records | What it does not establish |
|---|---|---|
| `COMPUTATION` | A tool produced a result artifact | Independent correctness |
| `INDEPENDENT_CHECK` | A checker passed, failed, or could not resolve a result | Formal proof unless the checker itself is a trusted proof kernel |
| `FORMAL_KERNEL_CHECK` | A reported proof-kernel execution, with kernel identity/version and proof-artifact digest | Authenticity of the report or correctness of an untrusted kernel binary |

These categories are independent provenance facts, not a single ranked trust
score. A computation can also be independently checked; a record can also
have a valid integrity digest. The profile reports each fact separately.

## Integrity and verification

The envelope digest is SHA-256 over canonical JSON (sorted keys, compact
separators, UTF-8), excluding only the digest field itself. Events must all
refer to the same artifact digest. Verification recomputes the envelope
digest and checks this binding.

This detects changes relative to a trusted expected digest. It does not
authenticate the creator: anyone able to rewrite the envelope can recompute
its digest. Use a digital signature and a trusted key-distribution process
when authenticated provenance is required.

## Formal proof boundary

A `FORMAL_KERNEL_CHECK` event is a structured record that a named kernel
reported a pass for a particular proof artifact. The envelope code does not
run Lean, inspect a proof term, or independently validate a kernel receipt.
Consequently, `kernel_pass_recorded` means exactly that the record contains
such a pass event; it must not be interpreted as a newly established
`FORMALLY_VERIFIED` result.

The existing verified-agent and proof-checking paths remain responsible for
actual Lean invocation and kernel acceptance. A formal verification claim
must be grounded in that trusted execution path, not in a user-authored
evidence envelope or a hash.

## Status discipline

- A computed result remains a computation.
- A checker pass remains a checker pass, scoped to its implementation and
  supported semantics.
- A valid hash establishes integrity relative to the expected digest, not
  truth.
- Formal proof requires the relevant trusted kernel to accept the proof
  artifact. Model agreement, repeated computation, and envelope metadata do
  not substitute for that acceptance.
