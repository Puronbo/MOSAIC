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

For independent full-bundle verification, also supply the exact environment
manifest, original request JSON, and candidate bytes:

```sh
node scripts/verify_lean_receipt.mjs lean-proof-attestation.json TRUSTED_PUBLIC_KEY_B64 lean-provenance.json request.json candidate.txt
```

This mode checks the embedded public key against the trusted key, Ed25519
signature, exact manifest bytes and digest, manifest commit/run/toolchain/
Mathlib bindings, normalized `MathRequest` fingerprint, exact candidate
bytes, proof-source digest, and recorded replay marker. As with the Python
verifier, consumers must verify the GitHub artifact attestations separately
before treating the receipt and manifest as authenticated CI outputs. A
recorded replay marker is not a fresh local replay.

The complete cross-language bundle vector is
`tests/fixtures/lean_receipt_v1_bundle_vector.json`; both Python and Node
tests independently validate its external bindings and reject altered
candidate, request, manifest, or replay data.

The wrapper itself is specified by
`schemas/lean-proof-receipt-bundle-v1.schema.json`, which references the
signed-attestation schema and requires the manifest digest and successful
exact-source replay record. The original request is specified by
`schemas/math-request-v1.schema.json`; request fingerprinting applies the
model defaults (`schema_version="1.0"`, `variable="x"`, `rhs=null`) before
canonical serialization. Missing fields and explicitly supplied defaults
therefore produce the same normalized request fingerprint, while explicit
nulls for non-nullable fields are rejected. The replay field is a CI-recorded statement; it
does not replace optional fresh replay by the verifier.


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


## Enforcing GitHub producer identity

A valid Ed25519 receipt signature is not sufficient to establish who produced
the receipt. For CI artifacts, consumers must first run GitHub's cryptographic
artifact-attestation verifier, then apply MOSAIC's stricter producer policy
to the verifier's JSON result. The policy is stored in
`policies/github-lean-attestation-v1.json` and pins:

- Repository name plus immutable GitHub repository and owner IDs
  (`Puronbo/MOSAIC`, repository ID `1468522236`, owner ID `297216003`).
- The only authorized signer/build workflow:
  `.github/workflows/lean-polynomial.yml`.
- Protected source ref `refs/heads/main`.
- GitHub Actions OIDC issuer and SLSA provenance predicate type.
- GitHub-hosted runner environment and verified timestamp evidence.

The repository ID is important: repository names can be reused after a
rename or deletion, while the numeric ID is immutable. Obtain the current ID
from the GitHub API rather than relying only on a repository name.

For each downloaded artifact, use GitHub CLI to verify cryptographic
authenticity and enforce repository, signer workflow, and source ref before
saving the JSON result:

```sh
gh attestation verify lean-provenance.json \
  --repo Puronbo/MOSAIC \
  --signer-workflow Puronbo/MOSAIC/.github/workflows/lean-polynomial.yml \
  --source-ref refs/heads/main \
  --deny-self-hosted-runners \
  --format json > manifest-attestation-verified.json

gh attestation verify lean-proof-attestation.json \
  --repo Puronbo/MOSAIC \
  --signer-workflow Puronbo/MOSAIC/.github/workflows/lean-polynomial.yml \
  --source-ref refs/heads/main \
  --deny-self-hosted-runners \
  --format json > receipt-attestation-verified.json
```

Then apply the MOSAIC policy to each verified result. The expected commit,
run ID, and subject digest must come from the independently selected workflow
run and the exact local artifact bytes, not from the attestation predicate:

```sh
COMMIT=<expected-40-character-commit>
RUN_ID=<expected-github-actions-run-id>

python scripts/verify_github_attestation_policy.py \
  --verification-json manifest-attestation-verified.json \
  --commit "$COMMIT" --run-id "$RUN_ID" \
  --subject-sha256 "$(sha256sum lean-provenance.json | cut -d' ' -f1)"

python scripts/verify_github_attestation_policy.py \
  --verification-json receipt-attestation-verified.json \
  --commit "$COMMIT" --run-id "$RUN_ID" \
  --subject-sha256 "$(sha256sum lean-proof-attestation.json | cut -d' ' -f1)"
```

The policy checker rejects mismatched repository IDs, commit/ref, signer or
build-config URI, run invocation, runner environment, predicate type, subject
digest, missing timestamp evidence, and unexpected policy fields. Every
verified attestation returned by GitHub CLI must satisfy policy. It does not
implement Sigstore verification itself: the input must be the JSON output of
a successful `gh attestation verify` invocation. Do not pass arbitrary JSON
or an unverified bundle to this policy checker.

Only after both artifact attestations pass this policy should the consumer
extract the receipt's Ed25519 public key and pass it as the explicit trusted
key to the complete bundle verifier. This ordering prevents a self-supplied
key inside an otherwise valid receipt from bootstrapping its own trust.

GitHub's CLI documentation describes the verified JSON certificate and
timestamp fields and the importance of checking immutable repository IDs:
https://cli.github.com/manual/gh_attestation_verify and
https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/verify-attestations-offline.


## Historical receipt trust and key lifecycle (v2)

The original signed receipt schema (`1.0`) remains supported for ordinary
signature verification. It has no signed issuance time and therefore cannot
be used for historical key-lifecycle decisions. New historical decisions use
`HistoricalSignedLeanAttestation` (`schema_version="2.0"`), whose
`issued_at_utc` is included in the Ed25519-signed canonical payload.
The normative shape is `schemas/historical-lean-trust-v2.schema.json`.

An issuance timestamp is a claim made by the signing key. It is not proof of
when the signature existed. Historical acceptance therefore additionally
requires a verified external timestamp from the enclosing GitHub artifact
attestation. The caller must first verify the artifact with
`gh attestation verify`, enforce the pinned producer policy, match the
artifact subject digest, and only then supply the timestamp as trusted evidence
to `verify_historical_with_keyring(...)`. A Boolean assertion by an untrusted
caller is not a substitute for this verification sequence.

`HistoricalLeanTrustedKey` records activation, retirement, revocation, and
compromise-effective UTC times. Its portable registry entry is specified by
`schemas/historical-lean-key-v1.schema.json`. The verifier applies these rules:

- The signed issuance time cannot precede key activation.
- The external verified timestamp cannot precede signed issuance.
- An active key must have no retirement, revocation, or compromise boundary.
- A retired key is accepted only when issuance and independently witnessed
  existence both precede retirement.
- A revoked key is accepted historically only when independently witnessed
  existence precedes revocation and signed issuance precedes revocation.
- If a compromise-effective time is recorded, any receipt issued at or after
  that time is rejected, even if it claims an earlier timestamp.
- A v1 receipt without signed issuance time is never accepted by the historical
  verifier.

This design prevents a compromised key from creating a newly signed,
backdated receipt and claiming that it predates revocation: the independent
timestamp must also prove the artifact existed before the lifecycle boundary.
The exact trust semantics of a revocation timestamp must be chosen by the
registry operator; compromise-effective time should reflect the earliest
credible compromise, not merely the administrative discovery date.

GitHub's verified timestamp objects are cryptographically verified transparency
log or timestamp-authority evidence; they are distinct from workflow-controlled
predicate fields. See the
[GitHub CLI verification reference](https://cli.github.com/manual/gh_attestation_verify).


## Content-addressed historical trust policies

Historical v2 receipts now carry `trust_policy_sha256` inside the Ed25519
signature. The digest is SHA-256 over the exact canonical UTF-8 JSON bytes of
an immutable `HistoricalTrustPolicy` document. The normative policy shape is
`schemas/historical-trust-policy-v1.schema.json`; registry records follow
`schemas/historical-trust-policy-record-v1.schema.json` and include policy
activation and optional retirement times. A policy change creates a new digest and must not overwrite the old
policy document.

The verifier receives an explicit map of trusted policy records. It rejects
unknown digests, digest/document mismatches, policies not active at the
independently verified timestamp, and receipts whose checker or kernel is
outside the policy allowlists. Policy rules also explicitly govern whether
retired-key or revoked-key history is accepted and bound the allowed lag
between signed issuance and independent timestamp evidence. The selected
policy digest is part of the signed receipt, so a caller cannot silently
substitute a more permissive current policy during historical verification.

Policy registry distribution and the truth of activation/retirement metadata
remain external trust responsibilities. A registry operator must preserve
immutable policy documents and authenticate registry updates; a local SHA-256
digest establishes content identity, not publisher authenticity. Policy
timestamps are evaluated against the independently verified artifact
timestamp, never the runner's wall clock.


## Authenticated historical trust-policy registry

`mosaic.verification.policy_registry` defines a signed, hash-linked policy
publication log. Each entry binds a sequence number, previous-entry digest,
complete content-addressed policy record, publication timestamp, and publisher
key ID in an Ed25519 signature. Consumers verify publisher signatures using
public keys provisioned independently of the registry.

The first entry has sequence zero and no predecessor. Every subsequent entry
must increment the sequence by one and name the SHA-256 digest of the complete
previous signed entry. Reordering, omission, mutation, and invalid signatures
are rejected. The entry schema is
`schemas/signed-policy-registry-entry-v1.schema.json`.

A valid chain alone does **not** prove that it is the newest chain: an attacker
could replay an older, correctly signed prefix. Consumers that need rollback
protection must persist or obtain an expected head sequence and digest through
a separate trusted channel. `verify_policy_registry` supports this checkpoint,
and `verify_historical_with_policy_registry` requires it before accepting a
historical receipt against a policy in the registry.

Publisher public keys and registry checkpoints are trust roots; distributing
them through the same untrusted registry would defeat the design. This module
does not implement publisher-key rotation, transparency publication, quorum
signing, or freshness discovery. A signed publication timestamp is still a
publisher claim, not an independent timestamp authority. Historical receipt
acceptance continues to require separately verified external timestamp
evidence.


### Publisher-key lifecycle and quorum governance

`mosaic.verification.policy_governance` adds an independently provisioned
publisher keyring. Each `PolicyPublisherKey` binds a publisher ID to a base64
Ed25519 public key and activation/revocation boundaries. Registry signatures
are accepted only when their publication timestamp falls within that key's
permitted interval. A revoked publisher cannot authorize entries published
at or after its revocation boundary. Historical entries signed before
revocation remain verifiable, subject to the separately trusted keyring and
registry checkpoint.

Optional `PolicyPublisherApproval` records let additional publishers approve
the exact digest and sequence of a signed entry. The primary entry signer
counts as one approval; additional approvals must come from distinct keys,
be lifecycle-valid at approval time, and occur no earlier than publication.
`verify_policy_registry_with_keyring` enforces the requested minimum quorum
across every entry. Duplicate approvals, approvals for another entry, unknown
publishers, and revoked or not-yet-active keys are rejected. The publisher
key and approval schemas are `schemas/policy-publisher-key-v1.schema.json`
and `schemas/policy-publisher-approval-v1.schema.json`.

This is a verification primitive, not a key-distribution or governance service.
Publisher keyrings and expected registry-head checkpoints must be provisioned
and updated through an independent trusted channel. Key revocation timestamps
are policy inputs supplied by that channel; they are not self-authenticating.
A compromised publisher can still sign false statements before its revocation
is recorded, and a quorum is only as independent as the people and systems
controlling its keys. No automatic publisher-key rotation, hardware-backed
signing, transparency-log publication, or anti-equivocation gossip is claimed.


## Policy-registry transparency checkpoints and equivocation

G-EP92 adds `mosaic.verification.policy_transparency`. A
`PolicyRegistryCheckpoint` signs a named log ID, sequence, exact signed-entry
head digest, previous-checkpoint digest, issuance time, and signer key ID.
The checkpoint signer is checked against the independently provisioned
publisher-key lifecycle keyring. Its normative schema is
`schemas/policy-registry-checkpoint-v1.schema.json`.

A checkpoint can carry independent `PolicyCheckpointWitness` signatures over
the exact checkpoint digest. Witness keys have their own independently
provisioned lifecycle records; duplicate witness IDs, unknown keys, invalid
signatures, pre-checkpoint witness times, and revoked/not-yet-active keys are
rejected. The witness record is specified by
`schemas/policy-checkpoint-witness-v1.schema.json`. Consumers can require a
minimum distinct-witness quorum.

When a previously trusted checkpoint is supplied, verification requires the
same log ID, a strictly increasing sequence, an exact link to the prior
checkpoint digest, and the old head digest at its sequence in the supplied
new registry prefix. The complete entry chain is signature- and hash-link
verified. This is an explicit prefix check over supplied entries, not a
cryptographic Merkle consistency proof. A caller must retain the old trusted
checkpoint and obtain the new one through an authenticated channel.

`find_checkpoint_equivocations` reports different head digests presented for
the same log ID and sequence. This provides a deterministic local detector
when a consumer has collected multiple views; it does not discover split
views by itself. The repository does not yet operate a distributed witness
network, publish checkpoints to a public transparency service, exchange
gossip, or guarantee freshness. Witness quorum independence depends on
separate key custody, and a signed checkpoint timestamp is still a signer
claim rather than trusted timestamp evidence. Consumers must persist trusted
checkpoints outside the registry and compare independently obtained views.


## Durable policy trust-state and recovery

G-EP93 adds `mosaic.verification.policy_trust_state.PolicyCheckpointStore`,
a local SQLite-backed store for trusted policy-registry heads. It uses
transactional compare-and-advance operations, SQLite WAL journaling, and
`synchronous=FULL` commits. Accepted checkpoint history and trust incidents
are retained alongside the current head. Reopening the store recovers the
persisted checkpoint rather than reconstructing trust from an untrusted
registry export.

An older or replayed checkpoint cannot replace a newer head. A valid signed
checkpoint presenting a different head at the same log ID and sequence causes
a durable equivocation incident and quarantines that log. Once quarantined,
normal advancement is blocked. A conflicting claim is only recorded when its
entry chain, checkpoint signature, and configured witness quorum verify; an
arbitrary malformed packet cannot quarantine the store.

Recovery is an explicit operator action. The operator must supply a non-empty
reason and explicit confirmation, and the selected checkpoint must verify
from a complete genesis-rooted registry history. Recovery clears quarantine
and appends a separate audit incident; it does not erase the original
conflict. The software cannot determine which of two cryptographically valid
forks is truthful. The operator must investigate independent registry exports,
witness statements, and publisher custody before selecting a view.

The SQLite file is a local persistence boundary, not a hardware-backed
monotonic counter. A privileged attacker who can replace or roll back the
database and its backups may roll back local trust state. Production
deployments should protect the database and backups with OS permissions,
independent backups, host integrity controls, and preferably an external
monotonic or remote witness checkpoint. SQLite's transaction durability does
not itself make the machine or storage trustworthy. Do not copy only the main
database file while WAL activity is in progress; use SQLite's backup API or
a coordinated shutdown/backup procedure to preserve a consistent state.


## Stateful independent policy checkpoint witnesses

G-EP94 adds `mosaic.verification.policy_witness_state.PolicyWitnessStateStore`.
Each witness runs with its own SQLite database and key custody, retains its
last accepted checkpoint per log, and signs only after independently checking
the complete supplied registry prefix and a strict extension of its retained
checkpoint. A stale checkpoint, replay, unlinked extension, invalid registry
prefix, or mismatched private/public key is not endorsed. State advancement is
transactional and survives process restart.

A witness that receives a cryptographically valid, genesis-rooted checkpoint
with a different head at the same sequence records a durable incident and
quarantines that log. It will not endorse further checkpoints while
quarantined. Invalid fork packets do not trigger quarantine, and a checkpoint
refresh that names the same registry head is not treated as equivocation.
This design deliberately does not provide automatic witness recovery: a
quarantined witness requires an out-of-band administrative recovery procedure
or replacement from independently audited state. Reinitializing its database
from an untrusted export would defeat its retained-history property.

Witness databases must be held by genuinely separate custodians or systems;
several databases under one administrator are not independent witnesses.
The SQLite store remains vulnerable to privileged database and backup rollback.
A signature proves that a configured key endorsed a checkpoint, not that the
checkpoint is truthful or fresh. There is no network service, gossip,
automated witness discovery, remote monotonic counter, or distributed
consensus implementation in this milestone. The incident export shape is
specified by `schemas/policy-witness-state-incident-v1.schema.json`.


## Portable signed witness-state snapshots

G-EP95 adds `mosaic.verification.policy_witness_snapshot.SignedPolicyWitnessSnapshot`
and snapshot export/import methods on `PolicyWitnessStateStore`. A snapshot
binds the log ID, exact checkpoint, quarantine flag, retained incident history,
witness key ID, and export timestamp in an Ed25519 signature. Its normative
shape is `schemas/policy-witness-state-snapshot-v1.schema.json`.

Import requires an independently provisioned witness keyring, a valid
snapshot signature and lifecycle timestamp, and a separately verified
publisher-signed registry prefix for the checkpoint. An empty store can be
bootstrapped from a trusted snapshot. An existing store accepts only the same
checkpoint with matching identity or a strict checkpoint extension of its
retained head. Older snapshots are rejected. Incident records are merged
without duplicating exact records, and imported quarantine is preserved.
Import cannot clear an existing quarantine; conflicting same-sequence signed
snapshot heads quarantine the receiving witness.

A snapshot signature authenticates the snapshot's contents and signer, not
the freshness of the snapshot. A first-time import into an empty database
cannot detect that the snapshot itself is old unless the operator supplies
an independently retained expected checkpoint or other external freshness
anchor. Similarly, an attacker able to roll back both a witness database and
all external snapshots can defeat local anti-rollback. Snapshot migration must
therefore be accompanied by an independently communicated latest snapshot
digest/checkpoint and protected key custody. This is a portable recovery
format, not a remote backup service, hardware monotonic counter, or
distributed consensus protocol.


## Multi-witness snapshot reconciliation

The read-only helper `reconcile_policy_witness_snapshots(...)` verifies each
witness snapshot signature and its complete genesis-rooted checkpoint history,
then compares the exact checkpoint digests across witnesses. It reports one of:

- `agreement`: every supplied witness has the same complete history;
- `compatible_extension`: histories share the complete shorter history and
  one or more witnesses retain a verified extension;
- `divergence`: histories differ at a checkpoint sequence;
- `invalid_input`: a signature, witness identity, log scope, or checkpoint
  history failed validation.

The report includes verified/rejected witness key IDs, the common-prefix
length, the first divergent sequence when present, head digests, and retained
quarantine indicators. The function is deliberately read-only: it does not
import snapshots, change quarantine state, endorse a checkpoint, or select a
winner. Duplicate witness key IDs are rejected rather than counted as
independent witnesses.

A compatible extension is not automatically fresh. A consumer must compare
the selected candidate against a separately provisioned freshness anchor.
Agreement does not prove that all witnesses have the latest state. Divergence
requires preserving all snapshots and investigating the signed histories with
independent evidence; witness count or majority vote cannot determine which
history is truthful. The report is a decision aid, not consensus or recovery.


## Signed authorization for witness recovery

A quarantined stateful witness can now be recovered with
`PolicyWitnessStateStore.recover_from_signed_snapshot(...)`, but only by
presenting a `SignedPolicyWitnessRecoveryAuthorization`. The Ed25519 approval
binds the log ID, exact selected snapshot digest, digest of the witness's
current retained incident history, digest of the independently reviewed
evidence, a reason, operator key ID, and approval time. The operator key is
lifecycle-checked and must be cryptographically distinct from the snapshot
witness key and the registry signer keys.

Recovery re-verifies the selected witness snapshot and its complete
genesis-rooted checkpoint chain, checks that the local witness is currently
quarantined, and compares the authorization's incident digest with the exact
local incident history inside one SQLite transaction. A changed incident
history, altered snapshot, wrong operator key, replayed authorization, or
unquarantined store is rejected. On success, the selected checkpoint history
is retained alongside prior conflicting history, the quarantine is cleared,
and the complete signed authorization is persisted in an append-only recovery
audit table. Original incidents are never deleted.

The evidence digest is a binding to evidence bytes supplied and reviewed by
the external operator workflow; this library does not retrieve, inspect, or
judge those bytes. The reason and signed approval document an accountable
decision, not mathematical truth. A compromised or improperly provisioned
operator key can authorize a bad recovery. Operator key custody, separation
of duties, evidence retention, and freshness anchors remain deployment
responsibilities. This recovery mechanism is local SQLite state, not
distributed consensus or hardware anti-rollback protection.


## Multi-operator recovery governance

Deployments can pass a `PolicyWitnessRecoveryPolicy` and a list of
`SignedPolicyWitnessRecoveryApproval` records to
`recover_from_signed_snapshot(...)`. The original recovery authorization is
the first operator's signed proposal. Additional approvals sign its exact
authorization digest, so they cannot be transferred to another snapshot,
incident history, evidence digest, or reason.

The policy supports a minimum approval count (including the proposal signer),
required operator key IDs, and prohibited operator key IDs. Every counted
identity must have a valid lifecycle at its signed approval time. Duplicate
key IDs, duplicate public keys, revoked keys, key reuse with the witness or
registry signers, malformed policy constraints, and approvals for a different
authorization are rejected. The approval policy is supplied by the caller and
must itself be provisioned through a trusted deployment configuration; this
module does not establish who is entitled to set that policy.

The default remains a one-operator threshold for compatibility with earlier
deployments. Security-sensitive deployments should explicitly configure a
threshold and required identities. The signed approval records are inputs to
the recovery operation; the durable recovery audit currently stores the
proposal authorization digest and signed proposal. Deployments requiring
long-term audit of each co-approval should retain the supplied approval
records alongside their evidence package. Revocation is evaluated against
each approval's signed time, so key compromise discovered later requires an
explicit deployment policy for retrospective invalidation.


## Signed recovery-policy governance (G-EP99)

Witness recovery thresholds can themselves be governed by an append-only
signed policy registry. The
`mosaic.verification.policy_witness_recovery_policy_registry` module defines
`SignedPolicyWitnessRecoveryPolicyEntry`, which binds a registry identity,
contiguous sequence, predecessor digest, exact
`PolicyWitnessRecoveryPolicy`, publication time, and lifecycle-authorized
publisher signature. The registry verifier rejects gaps, reordered entries,
cross-registry links, invalid policy constraints, altered entries, and
publishers outside their activation/revocation window.

A separately signed
`SignedPolicyWitnessRecoveryPolicyCheckpoint` binds the expected registry
head sequence and entry digest. Consumers must retain or obtain this
checkpoint through a trust channel independent of the registry being checked,
then call `verify_policy_witness_recovery_policy_registry`. An otherwise
valid older prefix is rejected when it does not match that trusted head.
Entry and checkpoint schemas are published alongside the policy schema.

This is a policy-governance primitive, not automatic policy distribution or
an implicit replacement for the recovery API's explicitly supplied policy.
A deployment must verify the signed registry and pass its selected policy to
the recovery workflow, persist the newest checkpoint outside the registry,
and protect publisher/checkpoint keys. If an attacker can replace both the
registry and the supposedly trusted checkpoint, rollback remains possible.
The signature authenticates a policy statement; it does not prove that its
threshold or operator identities are wise, independently administered, or
mathematically correct. Existing recovery calls that supply a policy directly
remain supported for compatibility.
