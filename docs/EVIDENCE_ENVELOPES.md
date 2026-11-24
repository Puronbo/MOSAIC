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

The request-bound transformation path now has an in-process adapter:
`verify_transformation_with_evidence` calls
`verify_request_transformation_with_lean` itself and creates an envelope
only when that call returns a completed `FORMALLY_VERIFIED` or `REJECTED`
result with a proof-source digest and Lean version. The candidate hash is
recomputed from the exact submitted result and checked against the generated
obligation. Kernel-unavailable, unsupported, timeout, and execution-error
outcomes produce no kernel event.

This adapter reduces accidental hand-assembly of kernel records, but it is
not a cryptographic attestation boundary. Python callers can construct model
objects, and the adapter trusts the MOSAIC process, imported verifier code,
configured Lean/Lake executable, and runtime environment. Deployments needing
remote or tamper-resistant attestations still need a separately authenticated
runner receipt (for example, a signed CI/build attestation) and trusted key
management. The envelope digest alone cannot supply that guarantee.

## Status discipline

- A computed result remains a computation.
- A checker pass remains a checker pass, scoped to its implementation and
  supported semantics.
- A valid hash establishes integrity relative to the expected digest, not
  truth.
- Formal proof requires the relevant trusted kernel to accept the proof
  artifact. Model agreement, repeated computation, and envelope metadata do
  not substitute for that acceptance.

## Authenticated Lean runner receipts

For deployments that separate the proof runner from the envelope consumer,
`mosaic.verification.lean_runner_receipt` adds an authenticated receipt
format. A trusted runner can call
`receipt_from_transformation_result` immediately after the actual
request-bound Lean invocation. The receipt binds the request fingerprint,
candidate bytes, generated proof-source digest, checker identity, Lean
version (and pinned Mathlib revision where applicable), runner identity,
and completed pass/rejection outcome.

Receipts use HMAC-SHA256 with a shared secret of at least 32 bytes.
`LeanRunnerReceipt.to_evidence_event` verifies the MAC before converting
the receipt into a formal-kernel evidence event. The event retains the runner
identity, receipt ID, request fingerprint, and MAC, so
`verify_evidence_event_receipt` can authenticate the event again after it
has been placed in an evidence envelope. Altered event fields, altered
receipts, and receipts presented with the wrong key are rejected.

**Key boundary:** HMAC is symmetric authentication, not a public-key
signature. Every verifier holding the shared secret can also mint receipts.
The secret must remain inside a trusted runner/signing service and must never
be available to untrusted API clients, models, or general envelope consumers.
For independent third-party verification, use an asymmetric signing system
or a platform-native signed build attestation with public-key verification.
The current module does not implement key distribution, rotation, revocation,
or remote attestation.

Receipt tests exercise MAC generation, tamper detection, wrong-key rejection,
and event conversion. These tests use a fixture key and mocked runner inputs;
they do not claim that CI executed the Lean kernel.

## Ed25519 runner attestations

For consumers that must not hold a signing secret, the optional
`mosaic.verification.lean_runner_signature` module provides Ed25519-signed
attestations. The isolated runner calls `run_and_sign_transformation`, which invokes the
request-bound Lean verifier and signs only its completed result using the
runner's private key. Consumers receive only the signed attestation and a
trusted public-key registry; they can convert it to an evidence event and
verify it with `verify_evidence_event_signature`. The lower-level
`sign_transformation_result` is also available when the trusted runner
already holds a completed verification result.

The signed payload includes the request fingerprint, exact candidate digest,
proof-source digest, checker ID, Lean/Mathlib version, runner ID, receipt ID,
and key ID. Signature metadata is retained in the event and therefore in the
envelope's canonical integrity digest. A changed payload or unknown key ID
fails verification.

Ed25519 support uses the `cryptography` package. Private keys are raw
32-byte values at the API boundary; use a secrets manager or hardware-backed
key store in production rather than committing or embedding them. Public
keys can be distributed to envelope consumers. Key ID selection must be
controlled by a trusted registry, with explicit rotation and revocation
policies. The library's `generate_ed25519_keypair` helper is for key
provisioning/testing; it does not persist or protect keys.

This is an asymmetric signature protocol, not remote attestation of the
runner's machine. It proves that the holder of the configured private key
signed the bound statement. It does not independently prove that the machine
was uncompromised or that the claimed Lean executable was genuine. The
deployment must isolate the runner, protect the private key, and control
which runner software is authorized to sign.

