import Lake
open Lake DSL

package mosaicPolynomial where
  -- The toolchain and Mathlib revision are pinned independently of MOSAIC's
  -- core Lean project so the existing lightweight checker remains unchanged.

require mathlib from git
  "https://github.com/leanprover-community/mathlib4" @ "fc4f59e577feb1a4956671bc04ac18aaaf8cd842"

lean_lib MosaicPolynomial
