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
  have hbound : ∀ m : Nat, 2 ≤ m → 4 ≤ 2^m := by
    intro m
    induction m with
    | zero =>
        intro hm
        omega
    | succ m ih =>
        intro hm
        by_cases hm2 : 2 ≤ m
        · have hprev := ih hm2
          rw [Nat.pow_succ]
          nlinarith
        · have hmEq : m = 1 := by omega
          subst m
          norm_num
  exact hbound k hk

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

/-- The map x ↦ x * log x is strictly increasing for x > 1. -/
theorem strictMonoOn_mul_log : StrictMonoOn (fun x : ℝ => x * Real.log x) (Set.Ioi 1) := by
  intro a ha b hb hab
  have ha' : 1 < a := ha
  have hb' : 1 < b := hb
  have hloga : 0 < Real.log a := Real.log_pos ha'
  have hlogab : Real.log a < Real.log b :=
    Real.log_lt_log (by linarith) hab
  calc
    a * Real.log a < b * Real.log a :=
      mul_lt_mul_of_pos_right hab hloga
    _ < b * Real.log b :=
      mul_lt_mul_of_pos_left hlogab (by linarith)

/-- Any positive real solution of x^x = 3 is greater than one. -/
theorem one_lt_of_pos_rpow_eq_three {x : ℝ}
    (hx : 0 < x) (heq : x ^ x = 3) : 1 < x := by
  by_contra h
  have hle : x ≤ 1 := le_of_not_gt h
  have hlog : x * Real.log x = Real.log 3 := by
    calc
      x * Real.log x = Real.log (x ^ x) := by
        rw [Real.log_rpow hx x]
      _ = Real.log 3 := congrArg Real.log heq
  have hlogx : Real.log x ≤ 0 := Real.log_nonpos hx.le hle
  have hprod : x * Real.log x ≤ 0 := mul_nonpos_of_nonneg_of_nonpos hx.le hlogx
  have hthree : 0 < Real.log 3 := Real.log_pos (by norm_num)
  linarith

/-- The equation x^x = 3 has at most one positive real solution. -/
theorem eq_of_pos_rpow_eq_three {x y : ℝ}
    (hx : 0 < x) (hy : 0 < y)
    (hxeq : x ^ x = 3) (hyeq : y ^ y = 3) : x = y := by
  have hxgt : 1 < x := one_lt_of_pos_rpow_eq_three hx hxeq
  have hygt : 1 < y := one_lt_of_pos_rpow_eq_three hy hyeq
  have hxlog : x * Real.log x = Real.log 3 := by
    calc
      x * Real.log x = Real.log (x ^ x) := by
        rw [Real.log_rpow hx x]
      _ = Real.log 3 := congrArg Real.log hxeq
  have hylog : y * Real.log y = Real.log 3 := by
    calc
      y * Real.log y = Real.log (y ^ y) := by
        rw [Real.log_rpow hy y]
      _ = Real.log 3 := congrArg Real.log hyeq
  exact strictMonoOn_mul_log.injOn
    (Set.mem_Ioi.mpr hxgt) (Set.mem_Ioi.mpr hygt) (hxlog.trans hylog.symm)

end MosaicPolynomial


/-! ## Exponent-increment system

The exponent shift is represented with a natural-number index.  Keeping the
base as a natural number makes the exponent unambiguous, while the value is
embedded in the reals so that differences and strict growth are ordinary
ordered-real statements.  This theorem family deliberately excludes zero and
negative bases from the real-valued monotonicity claim.
-/

namespace MosaicExponentShift

/-- The k-th unit increment of n^n. -/
def value (n k : Nat) : ℝ := (n : ℝ) ^ (n + k)

/-- One unit of exponent increment multiplies the value by the base. -/
theorem successor (n k : Nat) :
    value n (k + 1) = (n : ℝ) * value n k := by
  simp only [value]
  rw [show n + (k + 1) = (n + k) + 1 by omega]
  rw [pow_succ]
  ring

/-- The first forward difference is (n - 1) times the current value. -/
theorem first_difference (n k : Nat) :
    value n (k + 1) - value n k =
      ((n : ℝ) - 1) * value n k := by
  rw [successor]
  ring

/-- For natural bases at least two, every unit increment is strictly positive. -/
theorem strictly_increasing (n k : Nat) (hn : 2 ≤ n) :
    value n k < value n (k + 1) := by
  rw [successor]
  have hn' : 1 < (n : ℝ) := by exact_mod_cast (show 1 < n by omega)
  have hvalue : 0 < value n k := by
    unfold value
    exact pow_pos (by exact_mod_cast (show 0 < n by omega)) _
  nlinarith

/-- At base one, every exponent shift is stationary. -/
theorem one_is_fixed (k : Nat) : value 1 k = 1 := by
  simp [value]

/-- At base zero, the initial term uses 0^0 and is intentionally not given
a blanket real-valued recurrence theorem. -/
theorem zero_base_after_first_step (k : Nat) (hk : 1 ≤ k) :
    value 0 k = 0 := by
  unfold value
  have hne : 0 + k ≠ 0 := by omega
  simp [hne]

end MosaicExponentShift
