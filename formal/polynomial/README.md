# Isolated polynomial proof project

This optional Lake project pins Lean 4.36.0 and Mathlib at
`fc4f59e577feb1a4956671bc04ac18aaaf8cd842`. It is deliberately separate
from the core Lean executable used by MOSAIC's closed-Nat and affine checkers.

Run from this directory:

```sh
lake exe cache get
lake env lean Main.lean
```

The source contains positive, universally quantified polynomial identity
probes over `Int`. It does not yet expose a Python/API checker and must not
be treated as evidence that arbitrary user expressions are supported.


## Reproducible CI environment

Both the repository-root `lean-toolchain` and this project's
`lean-toolchain` pin `leanprover/lean4:v4.36.0`. The committed
`lake-manifest.json` pins Mathlib and its transitive Lake dependencies by
full Git commit. Do not run `lake update` as part of ordinary verification;
review and commit intentional manifest changes.

The polynomial CI job installs the declared toolchain, obtains Mathlib's
cached build, and runs the proof entrypoint with Lake. It then runs
`scripts/create_lean_provenance.py`, which fails closed unless the root and
project toolchain pins agree, the observed Lean version matches the pin, and
the installed `.lake/packages/mathlib` checkout is exactly the Mathlib
revision in the manifest. The output records Lean, Lake, and Elan version strings; SHA-256 hashes of
the resolved Lean, Lake, and Elan executables; both toolchain-file hashes;
the observed and declared Mathlib revision; the Lake manifest hash; source
hashes; Python runtime; commit; and workflow identity. Its structure is described by
`schemas/lean-build-provenance-v1.schema.json`.

MOSAIC's Python/CI dependencies are installed from the committed
`uv.lock` using uv 0.9.11 and `uv sync --locked --extra dev`; Lean
integration scripts run through `uv run --locked`.

These records and pins make the declared inputs inspectable and reject
dependency drift in the configured CI path. They do not make hosted runners
bit-for-bit deterministic, prove the runner host is uncompromised, or turn
environment metadata into a mathematical proof. Formal proof status still
comes from the Lean kernel checking the generated theorem.


## Independent replay environment matching

When `scripts/verify_lean_proof_receipt.py --replay` is used, the verifier
now compares the local replay host against the exact signed provenance
manifest before invoking Lean. It checks the recorded Python version and platform against the local runtime, plus Lean, Lake, and Elan version output;
the SHA-256 of each resolved executable; both toolchain-file hashes; the
declared and observed Mathlib revision; the Lake manifest and lakefile hashes;
and the proof entrypoint hash. Any missing input or mismatch fails closed and
prevents replay. A matching fingerprint establishes environment equivalence
for these recorded inputs only; it does not attest the local host's integrity
or prove the theorem. Lean still has to accept the exact signed source during
the subsequent replay.


Before replay, the portable verifier also requires the manifest to conform to
the pinned `mosaic.lean-build-provenance.v1` structure: exact top-level and
environment fields, a repository and full source commit, a numeric CI run ID,
nonempty version/runtime metadata, and correctly sized lowercase SHA-256
fingerprints. Unknown schema versions, missing fields, extra fields, malformed
identifiers, and incomplete execution metadata fail closed. The receipt
signature and manifest digest still bind the manifest to its recorded source
commit, workflow run, toolchain, and Mathlib revision.


The replay manifest gate also validates the CI execution identity itself:
workflow name, numeric run ID, numeric attempt, and runner OS must all be
present. Both declared and observed Mathlib revisions must be full lowercase
40-character Git object IDs, and the Lean toolchain identifier must match the
project's pinned version. These checks prevent incomplete local or hand-edited
metadata from being treated as a CI-produced replay environment.


The provenance generator itself now refuses to emit a CI manifest if any
GitHub Actions identity field is absent or malformed. It requires a repository
name in `owner/repository` form, a workflow name, positive numeric run ID and
run attempt, and a recognized runner OS (`Linux`, `Windows`, or `macOS`). It
also checks that the source revision is a full lowercase commit ID. This avoids
producing a superficially successful but schema-invalid manifest outside a
fully identified CI execution.


## Current proof entrypoint

`Main.lean` contains kernel-checked examples for integer polynomial
identities, monotonicity of natural-number powers, and the comparison
`2^(n - 1) ≤ n^(n - 1)` for `n ≥ 2`. It also proves
`n^n ≠ 3` for every natural number `n`, via the auxiliary lower bound
`4 ≤ 2^n` for `n ≥ 2`. This is the discrete statement corresponding to
the real equation `x^x = 3`: it rules out natural-number solutions but does
not rule out positive real solutions.

The real-valued polynomial derivative checker is a separate bounded
integration path exercised by the same CI workflow. It verifies derivatives
of supported univariate polynomials using Mathlib's `HasDerivAt` API; it
does not establish a general theorem about `x^x`, logarithms, or Lambert
`W`. The real solution and its uniqueness remain an analytic argument
documented in the worked example, not a theorem in this Lean entrypoint.

The workflow also exercises request-bound verification and replays a signed
proof source against the recorded pinned environment. A successful CI run
is evidence for those exact checked sources and execution steps; it is not
a proof that arbitrary mathematical expressions are supported.
