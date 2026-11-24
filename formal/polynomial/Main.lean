import Mathlib

/-!
MOSAIC's real-kernel acceptance probes.

The polynomial identities below are universally quantified over the integers.
The natural-number power monotonicity lemma is a small independently checked
arithmetic fact used in the rapid-series comparison example.
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

/-- Natural-number exponentiation preserves the order of its base. -/
theorem nat_pow_mono {a b k : Nat} (h : a ≤ b) : a^k ≤ b^k := by
  induction k with
  | zero =>
      simp
  | succ k ih =>
      rw [Nat.pow_succ, Nat.pow_succ]
      exact Nat.mul_le_mul ih h

/-- For n ≥ 2, the geometric comparison denominator is no larger
than the corresponding denominator n^(n-1). -/
theorem rapid_series_power_comparison (n : Nat) (hn : 2 ≤ n) :
    2^(n - 1) ≤ n^(n - 1) :=
  nat_pow_mono hn

/-- Powers of two are at least four from exponent two onward. -/
theorem four_le_two_pow (k : Nat) (hk : 2 ≤ k) : 4 ≤ 2^k := by
  induction k with
  | zero =>
      omega
  | succ k ih =>
      cases k with
      | zero =>
          norm_num
      | succ k =>
          have hprev : 4 ≤ 2^(k + 1) := ih (by omega)
          rw [Nat.pow_succ]
          nlinarith [Nat.zero_le (2^(k + 1))]

/-- The natural-number equation n^n = 3 has no solution.
This is the discrete counterpart of n^n - 1 = 2. -/
theorem no_nat_solution_n_pow_eq_three (n : Nat) : n^n ≠ 3 := by
  intro h
  by_cases hn : n < 2
  · interval_cases n <;> norm_num at h
  · have hn2 : 2 ≤ n := by omega
    have hpow2 : 4 ≤ 2^n := four_le_two_pow n hn2
    have hpow : 2^n ≤ n^n := nat_pow_mono hn2
    omega

end MosaicPolynomial
