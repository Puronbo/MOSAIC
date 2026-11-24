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
manifest before invoking Lean. It checks Lean, Lake, and Elan version output;
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
