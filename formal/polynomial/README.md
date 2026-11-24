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
