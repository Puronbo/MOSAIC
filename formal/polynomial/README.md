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
