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
proof-source digest and source bytes, checker ID, Lean/Mathlib version, runner
ID, receipt ID, and key ID. When environment provenance is supplied, it also
binds the exact environment-manifest SHA-256, source commit, workflow run ID,
pinned Lean toolchain, and Mathlib revision as one all-or-none field group.
Those fields are retained in the evidence event and included in signature
verification and the envelope's canonical integrity digest. A changed payload,
partial environment binding, or unknown key ID fails verification. The
`verify_attested_environment_manifest(...)` helper additionally checks the
exact manifest bytes against the signed digest and compares the embedded
commit, workflow run, Lean toolchain, and Mathlib revision with the receipt.

Ed25519 support uses the `cryptography` package. Private keys are raw
32-byte values at the API boundary; use a secrets manager or hardware-backed
key store in production rather than committing or embedding them. Public
keys can be distributed to envelope consumers. Key ID selection must be
controlled by a trusted registry, with explicit rotation and revocation
policies. The library's `generate_ed25519_keypair` helper is for key
provisioning/testing; it does not persist or protect keys.

The signed attestation schema is versioned as `1.0`; unknown versions are
rejected rather than interpreted as compatible. The normative JSON Schema is published at
`schemas/lean-runner-attestation-v1.schema.json`; it requires every v1
property and forbids additional properties. Its canonical payload uses
UTF-8 JSON with lexicographically sorted ASCII property names, compact
separators, and Unicode scalar values emitted directly (`ensure_ascii=False`).
JSON object keys and string values must be valid Unicode scalar sequences;
duplicate keys, non-standard constants such as NaN/Infinity, and malformed
UTF-8 are rejected. The current signed fields contain no JSON numbers, which
avoids cross-language numeric formatting differences. The conformance vectors in
`tests/fixtures/lean_receipt_v1_vector.json` and
`tests/fixtures/lean_receipt_v1_unicode_vector.json` fix canonical payload
hashes and deterministic Ed25519 signatures, including non-ASCII text and a
supplementary Unicode character, so independent implementations can test
byte-for-byte compatibility.

Consumers can maintain a `LeanTrustedKey` registry and call
`verify_with_keyring`. Keys marked `active` can verify current receipts;
`retired` keys remain usable for historical verification; `revoked` keys
are rejected. This registry is an application-supplied trust policy, not a
remote key-discovery service. The current receipt format has no signed
issuance timestamp, so a revoked key is rejected for all receipts rather
than attempting to infer whether a receipt predates revocation. Rotation
requires publishing the new key under a new key ID and retaining old
non-revoked keys while historical verification is required.

This is an asymmetric signature protocol, not remote attestation of the
runner's machine. It proves that the holder of the configured private key
signed the bound statement. It does not independently prove that the machine
was uncompromised or that the claimed Lean executable was genuine. The
deployment must isolate the runner, protect the private key, and control
which runner software is authorized to sign.



## Reproducible Lean environment and build provenance

The polynomial Lean project pins Lean 4.36.0 in
`formal/polynomial/lean-toolchain`, pins Mathlib and its transitive Lake
dependencies in `formal/polynomial/lake-manifest.json`, and declares the
Mathlib revision in `lakefile.lean`. CI installs that toolchain, obtains the
Lake cache, and runs the project plus request-bound Python-to-Lean checks
against the real Lean executable.

After those checks pass, CI runs
`scripts/create_lean_provenance.py`. The generator fails closed if the
toolchain or Mathlib revision differs from the expected pins, then records the
observed Lean version, complete Lake manifest digest, project source digests,
repository commit, and workflow execution identifiers in
`lean-provenance.json`. GitHub Actions signs that exact JSON artifact with
the workflow's OIDC identity using `actions/attest@v4` (Sigstore-backed
artifact attestation). The attestation binds the manifest's digest to the
repository, commit, and workflow identity; it is stronger than a self-asserted
runner ID or a locally generated hash.

CI also writes `lean-proof-attestation.json`, containing the complete Ed25519
proof receipt, its public key, the exact environment-manifest digest, and the
successful exact-source replay result. GitHub attests both files and uploads
them together as the `lean-proof-provenance` workflow artifact. Verify either
downloaded subject with:

```sh
gh attestation verify lean-provenance.json -R Puronbo/MOSAIC
gh attestation verify lean-proof-attestation.json -R Puronbo/MOSAIC
```

The proof receipt's Ed25519 key is ephemeral in CI. Its standalone signature
is therefore not a persistent identity; the GitHub artifact attestation is
the externally verifiable binding to the repository workflow and commit.

### Cross-language receipt verification

A dependency-free Node.js verifier independently implements the version 1.0
Ed25519 payload check. It uses Node's built-in Ed25519 support and a strict
JSON parser that rejects duplicate object keys. Run it with a trusted
base64-encoded 32-byte public key:

```sh
node scripts/verify_lean_receipt.mjs lean-proof-attestation.json TRUSTED_PUBLIC_KEY_B64
```

The same verifier is exercised against the fixed Python-generated vector by
`node --test tests/test_verify_lean_receipt.mjs`. It checks the exact
canonical UTF-8 JSON payload, Ed25519 signature, proof-source digest, schema
version, and complete environment-binding shape. This is a signature-level
cross-language conformance check, not a replacement for validating the
GitHub artifact attestation, request/candidate bindings, and environment
manifest. Use the Python bundle verifier for those additional external
bindings, or implement them in the consuming system before accepting the
receipt as a complete proof bundle.

### Independent receipt verification

After downloading both artifacts, first verify their GitHub attestations as
shown above. Then provide the original request JSON, exact candidate bytes,
and a trusted Ed25519 public key to the standalone verifier:

```sh
python scripts/verify_lean_proof_receipt.py \\
  --receipt lean-proof-attestation.json \\
  --manifest lean-provenance.json \\
  --request original-request.json \\
  --candidate candidate.txt \\
  --public-key-b64 trusted-public-key.txt \\
  --replay
```

The public-key file contains the base64-encoded 32-byte Ed25519 public key.
The verifier rejects duplicate JSON object keys and unknown bundle fields,
then checks the receipt signature, source digest, exact manifest digest and
identifiers, original request fingerprint, and candidate digest.
The optional replay flag independently executes the exact signed proof source
with the local pinned Lake project. The key embedded in the receipt is only
compared with the supplied trust key; it is never trusted merely because it
appears in the receipt. For the ephemeral CI key, obtain and trust that key
only after the GitHub artifact attestation for the receipt has been verified.


The manifest and attestation establish the provenance of the declared and
observed environment metadata. They do not by themselves attest every
individual theorem invocation, preserve each generated temporary proof source,
or prove that the runner host was uncompromised. The affine and polynomial transformation checkers now retain the exact generated Lean source alongside its SHA-256 digest. Ed25519 runner attestations include those exact source bytes in the signed payload, and signed evidence events preserve the source so a consumer can inspect it and verify its digest. `replay_attested_proof_source(...)` verifies the signature and re-runs the retained source through `lake env lean` in the pinned polynomial Lake project. It returns `None` when the replay environment is unavailable or times out; a replay is a fresh check in the current environment, not proof that the original runner host was uncompromised. CI creates the pinned environment manifest after dependency installation, binds its digest and identifying fields into the Ed25519 proof receipt, and independently replays the exact signed source. GitHub publishes the manifest attestation only after the proof and replay steps succeed. This makes each CI proof receipt point to the exact manifest artifact that the workflow later attests. The source is preserved in the signed attestation and event, while theorem invocation logs and complete machine-level execution traces remain future work. GitHub's hosted
runner image is identified at a broad platform level, not pinned to an
immutable machine image. Reproducibility is therefore improved, not absolute.
