import Mathlib.Tactic.Ring

/-!
MOSAIC's first real-kernel nonlinear polynomial acceptance probes.
These are universally quantified identities over the integers.
-/

namespace MosaicPolynomial

theorem square_add_one (x : Int) :
    (x + 1)^2 = x^2 + 2*x + 1 := by
  ring

theorem difference_of_squares (x y : Int) :
    (x + y) * (x - y) = x^2 - y^2 := by
  ring

theorem collect_terms (x y : Int) :
    3*x + 2*y + x - y = 4*x + y := by
  ring

end MosaicPolynomial
