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


### Enforcing registry-governed recovery (G-EP100)

`PolicyWitnessStateStore.recover_from_signed_snapshot(...)` now supports
`require_trusted_recovery_policy=True`. In this mode, recovery fails closed
unless the caller supplies the complete signed recovery-policy registry,
a trusted signed head checkpoint, and the publisher/checkpoint keyrings.
The method verifies the entire registry chain and checkpoint before deriving
the effective approval policy from the registry's final entry. A direct
`recovery_policy` override is rejected in this mode, as are registry
arguments supplied while the enforcement flag is disabled.

This enforcement occurs before the recovery transaction and before any
witness state changes. Missing, stale, altered, wrongly signed, or
lifecycle-invalid policy data cannot authorize recovery. The selected
registry head should still be persisted independently by the deployment;
the method verifies the checkpoint supplied for this operation but does not
provide a remote freshness service or durable policy-head store of its own.
The older direct-policy path remains available when the enforcement flag is
false for backwards compatibility. Production deployments should enable the
flag and source the checkpoint and keyrings from separately controlled trust
configuration.


### Durable recovery-policy checkpoint state (G-EP101)

`RecoveryPolicyCheckpointStore` in
`mosaic.verification.recovery_policy_checkpoint_state` persists a trusted
recovery-policy registry head in SQLite (WAL, FULL synchronous writes).
`pin_checkpoint` verifies the complete signed registry and checkpoint
before pinning or advancing the head. It rejects older checkpoints, records
rollback incidents, checks that previously retained registry entries remain
an exact prefix, and quarantines the registry on same-sequence equivocation
or history divergence. The state survives process restart.

Fail-closed witness recovery now additionally requires this store and checks
that the supplied signed checkpoint exactly matches its non-quarantined local
head. A registry/checkpoint pair that verifies cryptographically but is not
the locally pinned head cannot authorize recovery.

The first `pin_checkpoint` is an explicit trust-on-first-use operation, not
proof of freshness. Bootstrap it from an independently authenticated
checkpoint; do not blindly pin a checkpoint received alongside an untrusted
registry. SQLite protects against ordinary process restarts and concurrent
transactions, not a privileged attacker who can replace or roll back the
database and all backups. Deployments should back up the database using
SQLite's backup API or a coordinated shutdown and retain an external
freshness anchor. A policy rollback incident requires an explicit
administrative investigation and re-bootstrap; this store never silently
clears quarantine.



### Administrative recovery of quarantined recovery-policy heads (G-EP102)

The module `mosaic.verification.recovery_policy_checkpoint_recovery` adds
threshold-signed administrative rebootstrap for a quarantined
`RecoveryPolicyCheckpointStore`. An operator-signed intent binds the exact
registry ID, currently retained checkpoint digest, complete current incident
history digest, selected replacement checkpoint digest, evidence digest,
reason, operator identity, and approval time. Additional Ed25519 approvals
sign the exact intent digest. The default rebootstrap policy requires at least
two distinct operator identities and public keys; lifecycle-valid operator
keys must be separate from the registry publisher and checkpoint signer keys.
Deployments can require or prohibit specific operator IDs.

A successful rebootstrap is accepted only while the local registry is
quarantined and only if the retained head and incident-history digests still
match inside the SQLite write transaction. The complete proposed registry
chain and signed checkpoint are re-verified. Replayed intents, stale state,
insufficient or duplicate approvals, wrong selected checkpoints, and invalid
signatures are rejected without clearing quarantine.

Rebootstrap starts a new numbered history epoch. The prior epoch entries,
incident rows, and complete signed operator approvals remain retained; no
conflicting old entry is overwritten. Subsequent ordinary checkpoint
advancement checks the active epoch's prefix, so an explicitly selected fork
can advance without erasing the evidence for the previous branch. A durable
audit row records the signed intent, all supplied approvals, selected
checkpoint, and epoch. Existing databases are migrated to epoch zero when
opened.

This is an accountable administrative selection, not an automated truth
oracle. The evidence digest binds externally reviewed evidence bytes but this
library does not fetch or assess them. Two distinct keys do not guarantee two
independent humans or custodians. The policy and operator keyring must be
provisioned independently. SQLite still cannot prevent a privileged attacker
from replacing or rolling back the database and its backups; retain external
freshness anchors and protected backups.



### Independently verifiable recovery-policy rebootstrap audit (G-EP103)

G-EP103 extends `mosaic.verification.recovery_policy_checkpoint_recovery`
with `export_rebootstrap_audit(...)` and
`verify_rebootstrap_audit_export(...)`. Each new rebootstrap audit record
retains the signed intent, every co-approval, the governing threshold policy,
the complete signed policy-registry entries, and the selected signed
checkpoint. This permits a verifier to re-check operator key lifecycle and
signatures, threshold and identity separation, the selected checkpoint
digest, and the complete publisher-signed registry chain without trusting
the SQLite database's current head.

Audit records are hash-linked per registry and exports include record count
and the computed head digest. The verifier rejects modified record contents,
broken links, non-increasing epochs, malformed or incomplete exports,
invalid signatures, invalid policy registry material, and a mismatched
externally expected head digest. Retain the exported head digest in a
separately controlled system and compare it during later audits: an
unkeyed local hash chain detects edits and internal gaps but cannot detect
truncation of the final records if an attacker can also rewrite the export's
head. The verifier therefore accepts an independently retained
`expected_head_sha256`.

Exports from pre-G-EP103 audit rows may not contain the newly retained signed
registry material and are not independently verifiable by this version;
preserve those legacy rows and their original external evidence packages.
The hash chain is an integrity structure, not a signature or external
timestamp. Database rollback, audit-head custody, evidence retention, and
operator-key governance remain deployment responsibilities.



### Audit verification lifecycle and legacy handling (G-EP104)

G-EP104 adds
`verify_rebootstrap_audit_export_report(...)`, returning a structured
`RecoveryPolicyCheckpointAuditVerificationReport` with status,
record/verified/legacy counts, the verifiable chain head, an optional expected
head, and diagnostic errors. Statuses distinguish `verified`, `empty`,
`legacy_unverifiable`, and `invalid`. The boolean
`verify_rebootstrap_audit_export(...)` remains a strict compatibility
wrapper: it returns true only for fully verified or genuinely empty exports.
Legacy rows are preserved and explicitly counted, never silently promoted to
verified evidence.

New v1 records chain from the most recent verifiable v1 record. If a database
contains only pre-G-EP103 rows, the first v1 record starts a fresh chain at
the zero digest; the legacy rows remain visible in the export but do not
pretend to authenticate that chain's predecessor. The export head identifies
the latest verifiable v1 record, or the zero digest when none exists.
Operators should retain the report and expected head outside the SQLite
database. An externally retained head detects database rollback that removes
later audit records; without that independent anchor, a self-consistent old
database image cannot prove that it is stale.

This report classifies historical records, not their truth. A legacy row is
unverifiable because it lacks the signed policy-registry material introduced
in G-EP103; it is not thereby proven malicious or intact. SQLite transaction
atomicity protects a rebootstrap operation against partial commits, but
database replacement, backup rollback, external-head custody, and genuinely
independent operator-key administration remain deployment responsibilities.



### Concurrent administrative recovery and replay resistance (G-EP105)

G-EP105 exercises two independently constructed
`RecoveryPolicyCheckpointStore` instances against the same SQLite database.
Both submit the same fully signed, threshold-approved rebootstrap intent at
the same time. The test requires exactly one successful transition, one
retained audit row, and one set of new-epoch entries. The losing operation
must observe the post-commit state and fail rather than repeat the transition.
A subsequent replay of the same signed intent is also rejected.

The rebootstrap operation obtains a SQLite `BEGIN IMMEDIATE` write
transaction, then rechecks quarantine state, retained checkpoint digest,
incident-history digest, and replay status before changing epoch entries,
the trusted head, and the audit row. SQLite serializes competing writers;
the transactional rechecks are the authorization boundary, not the timing
or outcome of pre-transaction signature validation. A competing request
whose proposal no longer matches the state is rejected.

This test covers same-database local concurrency, not a distributed lock
service or multi-host consensus. It assumes SQLite's configured locking and
storage semantics are honored. Independent database copies can still accept
conflicting administrative decisions, and privileged rollback remains
detectable only when compared with an independently retained audit-head
anchor. Successful concurrency tests do not establish independent human
approval or trustworthy evidence.



### Competing valid recovery proposals (G-EP106)

G-EP106 tests two separately threshold-approved proposals that bind the same
quarantined retained head and incident-history digest but select different,
independently publisher-signed and checkpoint-signed registry forks. The
proposals use disjoint operator identities and distinct evidence digests.
They race through independent store instances against one SQLite database.

Exactly one proposal may commit. The test then verifies that the trusted head,
new epoch entries, and sole audit record all identify the winning proposal;
the losing fork is not trusted; and the incident history is unchanged.
It verifies the winner's audit export with the combined operator keyring and
an externally retained audit-head digest. A second attempt with the losing
proposal must fail without changing the audit export, trusted head, or
incident history.

This is a state-transition integrity test, not a method for deciding which
proposal is substantively correct. Both candidate forks can be validly
signed and structurally verified; authorization is determined by the
threshold policy and the exact state-bound intent. Whichever proposal wins
the database race is not thereby proven wiser or truer. A production process
must resolve competing evidence and authorize a single intended selection
before enabling simultaneous submissions where deterministic priority is
required. The test covers one shared SQLite database, not competing copies,
distributed consensus, or independent human judgment.



### Recovery proposal attribution and execution-time key lifecycle (G-EP107)

The recovery API accepts an optional `authorization_time_utc`. When supplied,
the implementation checks every proposing and approving operator key against
its activation and revocation interval at that authorization time, and rejects
future-dated approvals. Thus a signature can remain historically verifiable
while no longer being eligible to authorize a new recovery transition after
the signer's key is revoked. The check occurs before the transactional state
change. Deployments should supply a trusted, canonical UTC time; omission
retains backward compatibility by evaluating lifecycle status at the latest
approval timestamp, which does not detect revocation occurring after signing.

Historical audit verification intentionally continues to validate signatures
at their signed times. Later revocation does not retroactively erase the
cryptographic fact that an approval was signed; it does prevent that key from
authorizing a later transaction when execution-time checking is enabled.

`report_rebootstrap_proposal_conflicts` compares submitted intent digests
with retained v1 audit records. It attributes a submitted proposal as the
winner only when its exact digest appears in the audit. When a winner is
identified, the other submitted alternatives are reported as losing proposals;
when no submitted proposal matches the audit, unmatched proposals remain
unattributed. If multiple submitted proposals appear across multiple retained
epochs, the latest matching audit record determines the reported winner; audit order, not caller order, timestamps, or digest sorting,
provides attribution. This report does not validate evidence quality, select
a winner, or prove that the selected policy is mathematically correct.

The execution-time check depends on the caller's keyring being a current and
authoritative lifecycle snapshot and on a trustworthy authorization clock.
A stale or attacker-controlled keyring/time can defeat the check; key
revocation distribution and clock trust remain deployment responsibilities.



### Persisted operator lifecycle evidence for recovery (G-EP108)

New rebootstrap audit records retain the canonical authorization time and,
for every proposing or approving operator, the exact operator key record
available to the transaction: key ID, public-key material, activation and
revocation boundary, signed timestamp, authorization-time timestamp, and
booleans recording lifecycle eligibility at signing and execution. Each key
record has a SHA-256 digest, and the complete evidence is included in the
hash-linked audit payload. Independent audit verification recomputes the
digests, checks the key records against the supplied operator keyring,
re-evaluates both lifecycle decisions, and rejects altered or inconsistent
evidence. Historical G-EP103 v1 records without these fields remain
verifiable under their original format.

The key record in this evidence is a snapshot supplied by the transaction's
operator keyring. It is not itself a cryptographically signed key-registry
statement. The audit hash chain protects the retained bytes against
undetected alteration relative to a trusted external audit-head anchor, but
does not prove that the keyring snapshot was authoritative when captured.
Deployments requiring independent proof of lifecycle state must distribute
and verify signed key-registry checkpoints (or another externally governed
key-state attestation) and retain the corresponding trust anchor. The
authorization timestamp must likewise come from a trusted clock. A
subsequent revocation does not retroactively invalidate an approval that
was authorized at execution; later compromise handling requires its own
incident and recovery policy.


## Signed operator lifecycle checkpoints

`mosaic.verification.recovery_operator_lifecycle` defines
`SignedOperatorLifecycleCheckpoint`, an authority-signed snapshot of the
operator key records used by administrative recovery. Each checkpoint binds a
registry identifier, monotonically assigned sequence, predecessor digest,
canonical issuance time, authority key ID, and a sorted complete key snapshot.
`verify_operator_lifecycle_checkpoint(...)` checks the Ed25519 authority
signature, key-record structure, chain position, optional externally retained
checkpoint digest, and optional authorization time.

The authority public key must be provisioned independently. Consumers should
retain the latest accepted sequence and digest outside the recovery database;
a valid signature alone cannot detect replay of an older valid checkpoint.
The checkpoint is a signed snapshot, not a distributed consensus protocol or
a trusted timestamp. A compromised lifecycle authority can sign misleading
snapshots. This helper is a separately verifiable trust primitive; callers
must explicitly integrate its result into recovery authorization policy.
The normative shape is `schemas/operator-lifecycle-checkpoint-v1.schema.json`.


### G-EP110: lifecycle-checkpoint-bound recovery

Administrative recovery can now accept a
`SignedOperatorLifecycleCheckpoint` together with its independently
provisioned authority keyring and externally retained checkpoint digest.
Every operator who signed or approved the rebootstrap must appear in that
same snapshot, and each complete key record must match the execution keyring.
The checkpoint is verified at the supplied authorization time before the
SQLite state transition. The signed checkpoint and its digest are persisted
inside the hash-linked recovery audit.

Independent audit verification accepts the lifecycle authority keyring and,
when supplied, the externally retained expected lifecycle checkpoint digest.
A missing authority keyring or altered expected digest rejects checkpoint-bound
audit evidence. Omitting lifecycle checkpoint arguments remains a compatibility
path for older deployments; it does not provide this stronger lifecycle
governance. The lifecycle authority and expected digest remain external trust
anchors, and the checkpoint chain is not a distributed consensus mechanism.


### G-EP111: fail-closed lifecycle trust policy

`RecoveryOperatorLifecycleTrustPolicy` pins the operator lifecycle registry ID,
authority key ID, minimum accepted sequence, and exact expected checkpoint
digest. Supplying this policy to recovery execution makes the lifecycle
checkpoint mandatory: missing checkpoints, absent authority keys, mismatched
digests, wrong registry/authority identities, or insufficient sequence are
rejected before state mutation. The same policy can be supplied to independent
audit verification, which rejects audit records without the pinned checkpoint.

The exact digest pin is the freshness/rollback anchor; the sequence floor alone
is not sufficient. Deployments must update the policy through their trusted
configuration channel when accepting a new lifecycle checkpoint. The library
does not maintain a distributed monotonic counter or automatically discover
new checkpoints. Legacy recovery remains available only when no strict policy
is supplied, so production callers must explicitly configure this policy to
obtain fail-closed enforcement.


### G-EP112: contiguous lifecycle checkpoint advancement

`verify_operator_lifecycle_checkpoint_advance` validates a proposed lifecycle
checkpoint against one externally pinned predecessor. It requires the
predecessor digest to match the external anchor, verifies both authority
signatures, and requires an unchanged registry and authority identity, exactly
one sequence increment, the candidate's predecessor digest to equal the
predecessor digest, and strictly increasing issuance time. It returns a
structured report with deterministic rejection reasons.

This is deliberately a one-step verifier. A deployment must atomically retain
the newly accepted candidate digest and sequence in its trusted configuration
or control plane before accepting a later step. It does not discover skipped
history, provide distributed consensus, or make a local database rollback
resistant by itself. A caller must reject the report unless `accepted` is
true, and must not advance its external anchor on rejection.


### G-EP113: durable lifecycle trust-anchor compare-and-swap

`RecoveryOperatorLifecycleTrustAnchorStore` persists one lifecycle head per
registry in SQLite using WAL mode, full synchronous durability, and
`BEGIN IMMEDIATE` writer serialization. Initial provisioning is insert-only;
it cannot silently replace an existing anchor. Advancement checks the stored
sequence and digest against the caller's expected predecessor, verifies the
signed contiguous transition, and commits the new sequence/digest in the same
transaction. Competing writers based on one predecessor cannot both advance;
a stale retry is rejected.

Provision the initial sequence and digest from an independent trusted channel.
After restart, read the retained anchor and require the next candidate to extend
it. If a process stops before commit, SQLite transaction rollback leaves the
old anchor; after commit, the new anchor is durable. This store is not itself
an external root of trust: privileged replacement or rollback of the database
file remains possible. Deployments needing that threat model must replicate or
seal the head in an independently protected control plane.


### G-EP114: signed portable lifecycle trust-anchor receipts

`SignedOperatorLifecycleTrustAnchorReceipt` packages a registry ID, sequence,
checkpoint digest, authority key ID, and issuance time into a separately
authority-signed receipt. Its verifier checks the receipt signature, the
authority-signed lifecycle checkpoint, their exact field/digest binding, and
caller-supplied expected registry, sequence, and checkpoint digest. A receipt
cannot make an arbitrary checkpoint trusted: verification requires both
signatures and an independently supplied expected digest.

The receipt is portable JSON and has a versioned schema at
`schemas/operator-lifecycle-trust-anchor-receipt-v1.schema.json`. A deployment
can retain or transfer the receipt alongside the checkpoint and verify it
without opening the originating SQLite database. Receipt issuance does not
replace independent distribution of the authority key or external retention
of the expected checkpoint digest. A signed stale receipt remains stale unless
the verifier's current expected digest accepts it.


### G-EP115: guarded portable lifecycle receipt export and restoration

RecoveryOperatorLifecycleTrustAnchorStore.export_receipt(...) signs a portable receipt only when the supplied signed checkpoint exactly matches the store's retained registry, sequence, and digest. A stale or mismatched checkpoint cannot be exported as the current local head.

restore_receipt(...) verifies the receipt signature, checkpoint signature, registry, sequence, digest, authority-key lifecycle, and optional authorization time before opening its write transaction. An empty store can be initialized only with explicit allow_initial=True and caller-supplied external registry, sequence, and exact checkpoint-digest expectations. Restoring an exact already-retained head is idempotent. A lower sequence, same-sequence fork/equivocation, or any other conflicting head is rejected without changing the database.

This restore operation intentionally does not advance an existing head. Advancement requires the predecessor checkpoint and the contiguous checkpoint-advance verifier; a portable receipt is not a substitute for missing history. The receipt and checkpoint are portable evidence, not a backup of the full lifecycle history. The authority public key and expected digest/sequence must still come from an independent trusted channel. SQLite transactions prevent partial local writes but cannot prevent privileged replacement or rollback of the database file.


### G-EP116: portable contiguous lifecycle checkpoint-chain bundles

OperatorLifecycleCheckpointChainBundle packages a non-empty ordered suffix of signed lifecycle checkpoints. The bundle records the registry, starting sequence, and starting checkpoint digest, but deliberately does not claim that those values are trusted by virtue of appearing in the bundle. The verifier requires the caller to supply the starting checkpoint and independently retained starting digest, then checks every transition with the single-step advancement verifier.

The verifier rejects a wrong registry or starting anchor, invalid signatures, skipped sequences, predecessor forks, non-monotonic issuance times, and mismatched externally expected ending sequence or digest. Its report records the number of transitions actually verified and deterministic errors. The JSON Schema is schemas/operator-lifecycle-checkpoint-chain-bundle-v1.schema.json; each member references the signed checkpoint v1 schema.

A bundle is a portable proof of a contiguous signed suffix relative to its externally trusted starting checkpoint; it is not a trust root, distributed consensus, or proof that the authority's statements are substantively true. Deployments must independently provision the authority key and starting digest, and should pin the expected ending digest when accepting a particular head. A bundle cannot authenticate an omitted predecessor or repair a sequence gap by itself.



### G-EP117: transactional restoration of lifecycle checkpoint-chain bundles

`RecoveryOperatorLifecycleTrustAnchorStore.restore_checkpoint_chain_bundle(...)`
restores a portable contiguous checkpoint suffix only after the complete bundle
has been independently verified against the caller-supplied starting checkpoint,
authority keyring, registry identity, external starting digest, and exact expected
ending sequence and digest. Verification occurs before mutation; the database
transaction then rechecks the current head while holding SQLite
`BEGIN IMMEDIATE`.

An empty store is initialized only when the caller explicitly sets
`allow_initial=True`. This does not make the bundle's embedded starting anchor
trusted: the starting checkpoint and its expected digest, authority keyring,
and expected final head must still come from independently controlled sources.
For a non-empty store, the supplied starting checkpoint must exactly match the
retained local sequence and digest. The operation rejects stale predecessors,
same-sequence forks, newer local heads, rollback attempts, invalid signatures,
and incomplete or discontinuous bundles. An exact already-retained ending head
is accepted idempotently after the entire supplied bundle has been verified.

The final checkpoint head is written in one transaction, so rejected imports
leave the local state unchanged and concurrent writers cannot overwrite a head
that changed after pre-verification. SQLite atomicity and writer serialization
do not protect against privileged replacement or rollback of the database file;
deployments must continue to retain freshness anchors outside this store.



### G-EP118: signed receipts for checkpoint-chain restoration

`restore_checkpoint_chain_bundle_with_receipt(...)` combines the guarded
G-EP117 restoration path with a portable Ed25519-signed receipt. The receipt
binds the exact bundle digest, registry, externally anchored starting sequence
and digest, resulting ending sequence and digest, number of verified
transitions, authority key ID, and canonical issuance time. It is returned only
when the complete chain verifies and the store accepts the restoration (or an
exact idempotent replay); rejected imports produce no receipt.

`verify_operator_lifecycle_checkpoint_chain_restore_receipt(...)` independently
re-verifies every bundle transition and the receipt signature and field
bindings. Verification requires the caller's authority keyring, starting
checkpoint and independently retained starting digest, and expected ending
sequence and digest. The versioned JSON Schema is
`schemas/operator-lifecycle-checkpoint-chain-restore-receipt-v1.schema.json`.

The receipt is signed evidence of an accepted restore operation as reported by
the restoring process. It is not a trusted timestamp, proof of durable storage
outside the store's stated SQLite guarantees, proof that the authority's
snapshot is substantively correct, or protection against later privileged
database rollback. Retain the receipt and expected final digest independently.



### G-EP119: durable checkpoint-chain restoration receipt ledger

The lifecycle trust-anchor store now retains each signed checkpoint-chain
restoration receipt in an append-only SQLite event table. The receipt is
recorded in the same `BEGIN IMMEDIATE` transaction as the trust-head insert
or compare-and-swap update. A successful restoration therefore cannot commit
the new head while omitting its corresponding local receipt record; a failed
head transition cannot leave behind a success receipt.

`read_checkpoint_chain_restore_receipts(registry_id)` returns the retained
receipt payloads in insertion order. Each payload remains an independently
verifiable Ed25519-signed receipt; local storage does not itself confer trust.
Exact restoration replays may add another event when they carry a distinct
valid receipt, while re-inserting the identical receipt digest is idempotent.
The ledger is append-only through this API, but it shares the SQLite file's
privileged rollback and deletion limitations. Export or replicate receipts to
an independently protected system when tamper evidence across database
restoration is required.


### G-EP120: externally anchored hash-linked restoration ledger

The local restoration receipt ledger now assigns each event a monotonically
increasing sequence and a predecessor link. Each ledger-entry digest commits
to the registry ID, event sequence, previous entry digest, and digest of the
authority-signed restoration receipt. The store exposes
`read_checkpoint_chain_restore_ledger(registry_id)` and the independent
`verify_operator_lifecycle_restore_ledger(...)` verifier.

Verification checks event ordering, predecessor links, receipt digests,
authority signatures, and caller-supplied terminal event sequence and ledger
digest. An optional expected ending checkpoint digest additionally binds the
last receipt to the externally pinned trust-anchor head. A truncated history,
reordered entry, altered receipt, or modified link is rejected when compared
with the independently retained terminal sequence and digest.

This is tamper evidence, not immutable storage: an attacker able to rewrite
the database can recompute an unanchored suffix. Retain the terminal ledger
sequence and digest outside the SQLite database (for example, in a separately
controlled deployment record or transparency service). The ledger's receipt
history and the checkpoint authority signature remain separate trust layers.


### G-EP121: portable signed restoration-ledger head checkpoints

The lifecycle trust-anchor store can export a
`SignedOperatorLifecycleRestoreLedgerHead` after independently verifying
the complete locally retained restoration-receipt ledger. The portable head
binds the registry, terminal event sequence, terminal ledger-entry digest,
terminal signed-receipt digest, a separate ledger-authority key ID, and
canonical issuance time. Its Ed25519 signature is verified by
`verify_operator_lifecycle_restore_ledger_head(...)` against a separately
provisioned authority keyring and caller-supplied expected registry, sequence,
and terminal digest (with an optional exact receipt-digest pin).

The ledger-head signer is intentionally distinct from the authority that
signed the underlying restoration receipts. This separates the role of
attesting to a verified ledger snapshot from the role of authorizing the
checkpoint-chain restoration itself. The store refuses to export a head for
an empty or locally unverifiable ledger. The JSON Schema is
`schemas/operator-lifecycle-restore-ledger-head-v1.schema.json`.

A signed head is a portable external checkpoint, not an automatically
independent trust anchor: deployments must retain and distribute it outside
the SQLite file (for example, through a separately controlled transparency
service or deployment control plane). Verification proves that the named
ledger authority signed these exact head values; it does not prove that the
signer performed a correct independent audit, provide trusted time, or
prevent rollback unless the consumer compares against its latest independently
retained head. The receipt-signing authority and ledger-head authority remain
separate trust decisions.


### G-EP122: fail-closed migration of legacy restoration receipt ledgers

The SQLite trust-anchor store now upgrades legacy G-EP119 receipt tables that
predate G-EP120's event-sequence and hash-link columns. Migration runs under
`BEGIN IMMEDIATE` and processes each registry's rows in durable SQLite
insertion order. It validates each stored receipt JSON against the signed
receipt model and checks that the receipt digest and denormalized registry,
ending checkpoint, bundle, sequence, and timestamp fields agree before
rebuilding contiguous event sequences, predecessor links, and ledger-entry
hashes. Signed receipt payloads are preserved byte-for-byte as stored JSON;
only the new ledger metadata is populated.

The migration is idempotent. A malformed receipt or disagreement between its
signed payload and stored row metadata aborts the transaction and raises an
error rather than fabricating a trustworthy history or silently dropping an
event. The migration reconstructs internal continuity, but it cannot establish
that the legacy database was never truncated or rolled back before migration.
Only a previously retained external ledger-head checkpoint can provide that
independent continuity anchor.


### G-EP123: monotonic advancement of externally pinned restore-ledger heads

`verify_operator_lifecycle_restore_ledger_head_advance(...)` verifies that a
new independently signed ledger-head checkpoint extends a previously retained
external pin. It verifies both head signatures against the ledger-authority
keyring, requires the candidate sequence and issuance time to be monotonic,
checks that the prior head's exact sequence, ledger-entry digest, and receipt
digest occur in the supplied history, and validates the complete history to
the candidate head using the receipt-authority keyring.

A candidate that is merely well-signed but represents a different history,
repeats or regresses the previous sequence, omits the prior pin, or truncates
the supplied history is rejected. Consumers should persist the accepted
candidate head outside the SQLite store before treating it as the next
rollback-detection anchor. This verifier does not provide a distributed
consensus protocol or trusted timestamping; those remain deployment concerns.



### G-EP124: dual-signed ledger-head authority rotation

`SignedOperatorLifecycleLedgerAuthorityRotation` records a transition
between restoration-ledger head-signing authorities. Each statement binds the
registry, contiguous rotation sequence, predecessor rotation digest, previous
and new key IDs, SHA-256 fingerprints of both public keys, and canonical
effective time. The previous authority signs to authorize the change; the new
authority signs the same payload to prove possession and acceptance of its
private key.

`verify_operator_lifecycle_ledger_authority_rotation_chain(...)` starts
from a caller-pinned initial key ID and verifies every rotation in order. It
rejects gaps, reordered or forked records, registry/key-identity changes,
fingerprint mismatches, invalid dual signatures, keys outside their activation
or revocation windows, non-monotonic effective times, and rotations not yet
effective at the supplied authorization time. The chain's terminal key ID
becomes the active ledger-head authority.

`verify_operator_lifecycle_restore_ledger_head_with_rotation_chain(...)`
requires a head to be signed by that terminal active key, then applies the
existing exact external head-pin and signature checks. The versioned record
shape is defined by
`schemas/operator-lifecycle-restore-ledger-authority-rotation-v1.schema.json`.

The initial key ID and its public key remain independently provisioned trust
anchors; the rotation records do not bootstrap their own root of trust. Keep
the full rotation chain and key lifecycle records in independently retained
storage. Dual signatures prove authorization by the previous key and
possession by the new key, not that either authority is uncompromised or that
the rotation was approved by an external governance process. Effective times
are policy timestamps, not trusted timestamps.



### G-EP125: externally pinned ledger-authority rotation heads

`SignedOperatorLifecycleLedgerAuthorityRotationHead` provides a portable,
signed checkpoint for the authority-rotation chain itself. It binds the
registry, terminal rotation sequence and digest, active key ID, and issuance
time. The genesis checkpoint uses sequence zero and a null rotation digest;
subsequent checkpoints are signed by the active authority established by the
rotation chain.

`verify_operator_lifecycle_ledger_authority_rotation_head(...)` verifies
the complete supplied rotation history from the independently pinned initial
key, checks the exact expected sequence and digest, confirms the active key,
and verifies the head signature. The
`verify_operator_lifecycle_ledger_authority_rotation_head_advance(...)`
helper verifies both the previous and candidate external checkpoints against
their respective prefixes/full history and requires a strictly newer sequence
and non-regressing issuance time. This detects a truncated, forked, replayed,
or replaced rotation history when the consumer supplies its latest external
head and retains that new head outside the mutable repository or database.

The JSON Schema is
`schemas/operator-lifecycle-restore-ledger-authority-rotation-head-v1.schema.json`.
The initial authority key ID remains a separately provisioned root. Consumers
must atomically persist each accepted new rotation-head checkpoint in an
independent control plane; the helper does not provide distributed consensus,
trusted timestamping, or immutable storage. A rotation chain without an
independent latest-head pin remains susceptible to wholesale rollback.


### G-EP126: composition of external rotation pins and restore-ledger heads

`verify_operator_lifecycle_restore_ledger_head_with_external_rotation_head(...)`
composes the G-EP125 rotation-chain checkpoint with the G-EP121 restore-ledger
head. It first verifies the supplied rotation history from the independently
provisioned initial key against the caller's exact expected rotation sequence
and digest and the separately retained signed rotation head. It then requires
the restore-ledger head to be signed by the active key established by that
verified rotation history and checks its exact registry, event sequence,
ledger-entry digest, and optional receipt digest pins.

The restore-ledger head's issuance time must not precede the final rotation's
effective time. This prevents a valid signature from an incoming key from
being presented as a ledger-head statement issued before that key's declared
activation. The helper also accepts an authorization-time bound, which callers
may use when their environment has a trusted time policy.

This is composition of signed evidence, not a new trust root. The initial
rotation key, expected rotation sequence/digest, external rotation-head
checkpoint, receipt authority keyring, and restore-ledger expectations must
still be supplied through independently controlled channels. Issuance and
effective timestamps are signed policy data, not trusted timestamps; this
helper does not provide consensus, trusted time, or immutable storage.


### G-EP127: portable composed lifecycle recovery evidence envelope

`OperatorLifecycleRecoveryEvidenceEnvelope` packages the registry identity,
independently provisioned initial authority key ID, complete supplied rotation
history, signed external rotation head, and signed restoration-ledger head into
one canonical portable JSON artifact. Its `digest()` identifies the exact
serialized evidence bundle.

`verify_operator_lifecycle_recovery_evidence_envelope(...)` checks the
envelope against caller-supplied independent expectations for the registry,
initial authority key, rotation-head digest and terminal rotation sequence /
digest, plus the restore-ledger event sequence, ledger-entry digest, and
receipt digest. It delegates cryptographic and activation checks to the
composed G-EP126 verifier. Any mismatch in either evidence layer rejects the
whole envelope. The JSON Schema is
`schemas/operator-lifecycle-recovery-evidence-envelope-v1.schema.json`.

The envelope is a transport format, not a self-authenticating trust root.
Expected pins and authority public keys must come from outside the artifact
and outside mutable storage controlled by the same threat domain. Its digest
provides stable content identification, not truth or immutability. The
envelope does not include the full restore receipt ledger; consumers that
need to independently audit the ledger history must also obtain and verify
that history against the signed ledger head. Signed timestamps remain policy
data, not trusted time.

### G-EP128: complete portable restoration-ledger evidence envelope

The G-EP127 recovery envelope now carries the complete ordered restoration
receipt ledger in addition to its signed terminal ledger head. The verifier
requires a separately retained exact digest of that signed head, validates
every ledger event's sequence, predecessor link, entry digest, receipt digest,
and receipt-authority signature, and checks that the terminal receipt matches
the independently pinned terminal receipt digest. Empty, truncated, reordered,
forked, or tampered histories are rejected.

The JSON Schema remains
`schemas/operator-lifecycle-recovery-evidence-envelope-v1.schema.json` and
now includes the complete ledger entries, each referencing the signed
checkpoint-chain restore-receipt schema. The envelope digest covers the
ledger as well as the rotation and ledger-head evidence.

This remains independently anchored evidence, not a self-authenticating
artifact: retain the restore-ledger-head digest and authority key material
outside the envelope and its mutable storage domain. The ledger verifier
checks signed receipt statements and hash-linked continuity; it does not
establish trusted time, immutable storage, consensus, or the substantive truth
of the underlying restoration claims.
