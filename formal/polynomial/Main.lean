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
  have hk0 : k ≠ 0 := by omega
  simp [hk0]


/-- One forward finite difference of a sequence. -/
def forwardDifference (f : Nat → ℝ) (k : Nat) : ℝ :=
  f (k + 1) - f k

/-- The r-th iterated forward difference of the exponent-shift sequence. -/
def iteratedDifference (n : Nat) : Nat → Nat → ℝ
  | 0, k => value n k
  | r + 1, k => forwardDifference (iteratedDifference n r) k

/-- Every order of forward difference has the same geometric form. -/
theorem iterated_difference (n k r : Nat) :
    iteratedDifference n r k =
      ((n : ℝ) - 1) ^ r * value n k := by
  induction r generalizing k with
  | zero =>
      simp [iteratedDifference, value]
  | succ r ih =>
      simp only [iteratedDifference, forwardDifference]
      rw [ih (k + 1), ih k, successor]
      ring

/-- The second forward difference is the square of the base-minus-one
multiplier times the current value. -/
theorem second_difference (n k : Nat) :
    forwardDifference (fun j => forwardDifference (fun i => value n i) j) k =
      ((n : ℝ) - 1) ^ 2 * value n k := by
  simpa [forwardDifference, iteratedDifference] using
    (iterated_difference n k 2)

/-- All iterated differences are strictly positive when n ≥ 2. -/
theorem iterated_difference_pos (n k r : Nat) (hn : 2 ≤ n) :
    0 < iteratedDifference n r k := by
  rw [iterated_difference]
  have hbase : 1 < (n : ℝ) := by
    exact_mod_cast (show 1 < n by omega)
  have hvalue : 0 < value n k := by
    unfold value
    exact pow_pos (by exact_mod_cast (show 0 < n by omega)) _
  exact mul_pos (pow_pos (by linarith) _) hvalue



/-- Shifting the exponent index by m multiplies the value by n^m. -/
theorem arbitrary_shift (n k m : Nat) :
    value n (k + m) = (n : ℝ) ^ m * value n k := by
  unfold value
  rw [show n + (k + m) = (n + k) + m by omega, pow_add]
  ring

/-- A forward difference over an arbitrary natural-number step. -/
def forwardDifferenceBy (f : Nat → ℝ) (m k : Nat) : ℝ :=
  f (k + m) - f k

/-- The r-th iterated m-step forward difference. -/
def iteratedDifferenceBy (n m : Nat) : Nat → Nat → ℝ
  | 0, k => value n k
  | r + 1, k => forwardDifferenceBy (iteratedDifferenceBy n m r) m k

/-- Every order of m-step difference has multiplier (n^m - 1)^r. -/
theorem iterated_difference_by (n m k r : Nat) :
    iteratedDifferenceBy n m r k =
      ((n : ℝ) ^ m - 1) ^ r * value n k := by
  induction r generalizing k with
  | zero =>
      simp [iteratedDifferenceBy, value]
  | succ r ih =>
      simp only [iteratedDifferenceBy, forwardDifferenceBy]
      rw [ih (k + m), ih k, arbitrary_shift]
      ring




/-- Shift an arbitrary natural-indexed sequence forward by m places. -/
def shiftOperator (f : Nat → ℝ) (m k : Nat) : ℝ :=
  f (k + m)

/-- Zero shift is the identity operator. -/
theorem shift_zero (f : Nat → ℝ) (k : Nat) :
    shiftOperator f 0 k = f k := by
  simp [shiftOperator]

/-- Forward shifts compose by adding their offsets. -/
theorem shift_compose (f : Nat → ℝ) (a b k : Nat) :
    shiftOperator (fun j => shiftOperator f b j) a k =
      shiftOperator f (a + b) k := by
  simp [shiftOperator, Nat.add_assoc, Nat.add_left_comm, Nat.add_comm]

/-- The shift operator acts on the exponent-increment sequence by
multiplication with the corresponding base power. -/
theorem shift_value (n m k : Nat) :
    shiftOperator (value n) m k =
      (n : ℝ) ^ m * value n k := by
  exact arbitrary_shift n k m

/-- A forward difference commutes with a forward shift. -/
theorem difference_shift_commute (f : Nat → ℝ) (m k : Nat) :
    forwardDifference (fun j => shiftOperator f m j) k =
      shiftOperator (fun j => forwardDifference f j) m k := by
  simp [forwardDifference, shiftOperator, Nat.add_assoc,
    Nat.add_left_comm, Nat.add_comm]



/-- The first m-step difference is the base-power increment times the value. -/
theorem arbitrary_step_first_difference (n m k : Nat) :
    value n (k + m) - value n k =
      ((n : ℝ) ^ m - 1) * value n k := by
  rw [arbitrary_shift]
  ring

/-- A zero-sized step has zero difference at every positive iteration order. -/
theorem zero_step_difference (n k r : Nat) :
    iteratedDifferenceBy n 0 (r + 1) k = 0 := by
  simp [iteratedDifferenceBy, forwardDifferenceBy]

end MosaicExponentShift


/-! ## Bi-infinite integer shift group

Unlike natural-indexed sequences, integer-indexed sequences have values in
both directions. Translation by an integer therefore has a genuine inverse.
This layer is stated for arbitrary real-valued sequences; it does not assume
that every sequence is an exponent-power sequence.
-/

namespace MosaicIntegerShift

/-- Translate a bi-infinite sequence by an integer offset. -/
def shiftOperator (f : ℤ → ℝ) (m k : ℤ) : ℝ :=
  f (k + m)

/-- Translation by zero is the identity. -/
theorem shift_zero (f : ℤ → ℝ) (k : ℤ) :
    shiftOperator f 0 k = f k := by
  simp [shiftOperator]

/-- Integer translations compose by addition. -/
theorem shift_compose (f : ℤ → ℝ) (a b k : ℤ) :
    shiftOperator (fun j => shiftOperator f b j) a k =
      shiftOperator f (a + b) k := by
  simp [shiftOperator, Int.add_assoc]

/-- Translation by the negative offset is a left inverse. -/
theorem shift_inverse_left (f : ℤ → ℝ) (m k : ℤ) :
    shiftOperator (fun j => shiftOperator f (-m) j) m k = f k := by
  simp [shiftOperator, Int.add_assoc]

/-- Translation by the negative offset is a right inverse. -/
theorem shift_inverse_right (f : ℤ → ℝ) (m k : ℤ) :
    shiftOperator (fun j => shiftOperator f m j) (-m) k = f k := by
  simp [shiftOperator, Int.add_assoc]

/-- The unit forward difference on a bi-infinite sequence. -/
def forwardDifference (f : ℤ → ℝ) (k : ℤ) : ℝ :=
  f (k + 1) - f k

/-- Integer translations commute with the unit forward difference. -/
theorem difference_shift_commute (f : ℤ → ℝ) (m k : ℤ) :
    forwardDifference (fun j => shiftOperator f m j) k =
      shiftOperator (fun j => forwardDifference f j) m k := by
  simp only [forwardDifference, shiftOperator]
  congr 1 <;> ring

/-- The integer translations form a group action on bi-infinite sequences:
the inverse law is witnessed by translation through the negated offset. -/
theorem translation_group_laws (f : ℤ → ℝ) (m k : ℤ) :
    shiftOperator (fun j => shiftOperator f (-m) j) m k = f k ∧
    shiftOperator (fun j => shiftOperator f m j) (-m) k = f k := by
  exact ⟨shift_inverse_left f m k, shift_inverse_right f m k⟩

end MosaicIntegerShift


/-! ## Continuous positive-real exponent shifts

For a fixed positive base, the real-indexed family has a genuine derivative.
This is the infinitesimal limit of its finite-step difference quotient.
-/

namespace MosaicRealExponentShift

/-- The real-parameter exponent family, written with the translated
parameter first so the derivative is a direct constant-base rpow chain rule. -/
noncomputable def value (x t : ℝ) : ℝ :=
  x ^ (t + x)

/-- For every positive base, the derivative with respect to the exponent
parameter is the value multiplied by the natural logarithm of the base. -/
theorem derivative (x t : ℝ) (hx : 0 < x) :
    HasDerivAt (fun s : ℝ => value x s)
      (value x t * Real.log x) t := by
  have hlinear : HasDerivAt (fun s : ℝ => s + x) 1 t := by
    simpa using (hasDerivAt_id t).add_const x
  simpa [value, mul_comm, mul_left_comm, mul_assoc] using
    (HasDerivAt.const_rpow hx hlinear)

/-- The derivative is positive above base one, zero at base one, and
negative between zero and one, since the family itself is positive. -/
theorem derivative_sign (x t : ℝ) (hx : 0 < x) :
    (0 < Real.log x → 0 < (value x t * Real.log x)) ∧
    (Real.log x = 0 → value x t * Real.log x = 0) ∧
    (Real.log x < 0 → value x t * Real.log x < 0) := by
  have hvalue : 0 < value x t := by
    unfold value
    exact Real.rpow_pos_of_pos hx _
  constructor
  · intro hlog
    exact mul_pos hvalue hlog
  constructor
  · intro hlog
    rw [hlog, mul_zero]
  · intro hlog
    exact mul_neg_of_pos_of_neg hvalue hlog


/-- The secant slope based at t with nonzero real step h. -/
noncomputable def secantSlope (x t h : ℝ) : ℝ :=
  h⁻¹ • (value x (t + h) - value x t)

/-- As the nonzero step tends to zero, the secant slope converges to the
tangent slope. This is the explicit difference-quotient limit behind the
derivative theorem. -/
theorem secant_slope_limit (x t : ℝ) (hx : 0 < x) :
    Filter.Tendsto (fun h : ℝ => secantSlope x t h)
      (nhdsWithin 0 ({0}ᶜ))
      (nhds (value x t * Real.log x)) := by
  simpa [secantSlope] using (derivative x t hx).tendsto_slope_zero

/-- The same limiting slope is obtained from positive steps (approaching
from the right). -/
theorem secant_slope_limit_right (x t : ℝ) (hx : 0 < x) :
    Filter.Tendsto (fun h : ℝ => secantSlope x t h)
      (nhdsWithin 0 (Set.Ioi 0))
      (nhds (value x t * Real.log x)) := by
  simpa [secantSlope] using (derivative x t hx).tendsto_slope_zero_right

/-- The same limiting slope is obtained from negative steps (approaching
from the left). -/
theorem secant_slope_limit_left (x t : ℝ) (hx : 0 < x) :
    Filter.Tendsto (fun h : ℝ => secantSlope x t h)
      (nhdsWithin 0 (Set.Iio 0))
      (nhds (value x t * Real.log x)) := by
  simpa [secantSlope] using (derivative x t hx).tendsto_slope_zero_left


/-- The r-th formal derivative function of the fixed-base exponent family. -/
noncomputable def iteratedDerivative (x : ℝ) : Nat → ℝ → ℝ
  | 0, t => value x t
  | r + 1, t => iteratedDerivative x r t * Real.log x

/-- Every order of derivative exists, and differentiating once more
multiplies the current derivative by log x. -/
theorem iterated_derivative (x t : ℝ) (r : Nat) (hx : 0 < x) :
    HasDerivAt (fun s => iteratedDerivative x r s)
      (iteratedDerivative x r t * Real.log x) t := by
  induction r generalizing t with
  | zero =>
      simpa [iteratedDerivative] using derivative x t hx
  | succ r ih =>
      have h := (ih t).mul_const (Real.log x)
      simpa [iteratedDerivative, mul_assoc] using h

/-- Closed form for every iterated derivative:
the r-th derivative is (log x)^r times the original value. -/
theorem iterated_derivative_formula (x t : ℝ) (r : Nat) :
    iteratedDerivative x r t = (Real.log x) ^ r * value x t := by
  induction r with
  | zero =>
      simp [iteratedDerivative]
  | succ r ih =>
      rw [iteratedDerivative, ih]
      ring


/-- The joint positive-base exponent family, with both base and exponent
parameter visible. -/
noncomputable def jointValue (x t : ℝ) : ℝ :=
  x ^ (x + t)

/-- Differentiating the joint family with respect to its base gives the
power-rule contribution plus the logarithmic contribution from the
base-dependent exponent. -/
theorem base_derivative (x t : ℝ) (hx : 0 < x) :
    HasDerivAt (fun s : ℝ => jointValue s t)
      ((x + t) * x ^ (x + t - 1) +
        jointValue x t * Real.log x) x := by
  have hbase : HasDerivAt (fun s : ℝ => s) 1 x := hasDerivAt_id x
  have hexponent : HasDerivAt (fun s : ℝ => s + t) 1 x := by
    simpa using (hasDerivAt_id x).add_const t
  simpa [jointValue, mul_comm, mul_left_comm, mul_assoc] using
    hbase.rpow hexponent hx

/-- The exponent-parameter partial derivative of the joint family. -/
theorem exponent_partial_derivative (x t : ℝ) (hx : 0 < x) :
    HasDerivAt (fun s : ℝ => jointValue x s)
      (jointValue x t * Real.log x) t := by
  simpa [jointValue, value, add_comm] using derivative x t hx


/-- The second derivative in the exponent coordinate. Since the base is
fixed, each differentiation contributes one factor of the logarithm. -/
theorem exponent_second_derivative (x t : ℝ) (hx : 0 < x) :
    HasDerivAt (fun s : ℝ => jointValue x s * Real.log x)
      (jointValue x t * (Real.log x) ^ 2) t := by
  have h := (derivative x t hx).mul_const (Real.log x)
  simpa [jointValue, value, pow_two, add_comm, mul_assoc] using h


/-- The third derivative in the exponent coordinate, obtained by
applying the fixed-base iterated-derivative theorem to the joint family. -/
theorem exponent_third_derivative (x t : ℝ) (hx : 0 < x) :
    HasDerivAt
      (fun s : ℝ => jointValue x s * (Real.log x) ^ 2)
      (jointValue x t * (Real.log x) ^ 3) t := by
  have h := iterated_derivative x t 2 hx
  have hfun :
      (fun s : ℝ => iteratedDerivative x 2 s) =
        (fun s : ℝ => jointValue x s * (Real.log x) ^ 2) := by
    funext s
    rw [iterated_derivative_formula]
    simp [jointValue, value, add_comm, pow_two]
    ring
  rw [hfun] at h
  have hvalue :
      iteratedDerivative x 2 t = jointValue x t * (Real.log x) ^ 2 :=
    congrFun hfun t
  rw [hvalue] at h
  convert h using 1 <;> simp [pow_succ, mul_assoc]



/-- Differentiate the exponent partial with respect to the base. This is
the mixed coordinate derivative obtained by differentiating G(x,t) log x
in x; the product rule separates the changing joint value and log factor. -/
theorem exponent_partial_base_derivative (x t : ℝ) (hx : 0 < x) :
    HasDerivAt (fun s : ℝ => jointValue s t * Real.log s)
      (((x + t) * x ^ (x + t - 1) + jointValue x t * Real.log x) *
        Real.log x + jointValue x t * x⁻¹) x := by
  have hbase := base_derivative x t hx
  have hlog : HasDerivAt Real.log x⁻¹ x := Real.hasDerivAt_log (ne_of_gt hx)
  change HasDerivAt ((fun s : ℝ => jointValue s t) * Real.log) _ _
  exact hbase.mul hlog



/-- Differentiate the base partial with respect to the exponent
coordinate. This gives the other mixed-coordinate derivative directly. -/
theorem base_partial_exponent_derivative (x t : ℝ) (hx : 0 < x) :
    HasDerivAt
      (fun s : ℝ =>
        (x + s) * x ^ (x + s - 1) + jointValue x s * Real.log x)
      (x ^ (x + t - 1) +
        (x + t) * x ^ (x + t - 1) * Real.log x +
        jointValue x t * (Real.log x) ^ 2) t := by
  have hlinear : HasDerivAt (fun s : ℝ => x + s) 1 t := by
    simpa using (hasDerivAt_id t).const_add x
  have hexponent : HasDerivAt (fun s : ℝ => x + s - 1) 1 t := by
    convert hlinear.sub_const 1 using 1 <;> ring
  have hpower : HasDerivAt (fun s : ℝ => x ^ (x + s - 1))
      (x ^ (x + t - 1) * Real.log x) t := by
    simpa [mul_comm, mul_left_comm, mul_assoc] using
      (HasDerivAt.const_rpow hx hexponent)
  have hfirst := hlinear.mul hpower
  have hsecond := (exponent_partial_derivative x t hx).mul_const (Real.log x)
  have hsum := hfirst.add hsecond
  convert hsum using 1 <;> simp [jointValue, pow_two, mul_assoc] <;> ring


/-- Differentiate the base partial once more. This product-rule form is
algebraically equivalent to the compact logarithmic Hessian formula. -/
theorem base_second_derivative (x t : ℝ) (hx : 0 < x) :
    HasDerivAt
      (fun s : ℝ =>
        (s + t) * s ^ (s + t - 1) + jointValue s t * Real.log s)
      ((x + t) * ((x + t - 1) * x ^ (x + t - 2) +
          x ^ (x + t - 1) * Real.log x) +
        x ^ (x + t - 1) +
        ((x + t) * x ^ (x + t - 1) +
          jointValue x t * Real.log x) * Real.log x +
        jointValue x t * x⁻¹) x := by
  have hlinear : HasDerivAt (fun s : ℝ => s + t) 1 x := by
    simpa using (hasDerivAt_id x).add_const t
  have hexponent : HasDerivAt (fun s : ℝ => s + t - 1) 1 x := by
    convert hlinear.sub_const 1 using 1 <;> ring
  have hpower : HasDerivAt (fun s : ℝ => s ^ (s + t - 1))
      ((x + t - 1) * x ^ ((x + t - 1) - 1) +
        x ^ (x + t - 1) * Real.log x) x := by
    convert (hasDerivAt_id x).rpow hexponent hx using 1 <;>
      simp [sub_eq_add_neg, add_comm, add_left_comm, add_assoc] <;> ring
  have hfirst := hlinear.mul hpower
  have hmixed := exponent_partial_base_derivative x t hx
  have hsum := hfirst.add hmixed
  convert hsum using 1 <;> simp [jointValue] <;> ring


/-- Evaluate the joint exponent family along a differentiable base path. -/
noncomputable def alongBasePath (u : ℝ → ℝ) (t : ℝ) : ℝ :=
  u t ^ (u t + t)

/-- Chain rule along a differentiable positive-base path. This combines
the changing-base and changing-exponent contributions in one derivative. -/
theorem along_base_path_derivative
    (u : ℝ → ℝ) (u' t : ℝ)
    (hu : HasDerivAt u u' t) (hx : 0 < u t) :
    HasDerivAt (fun s : ℝ => alongBasePath u s)
      (u' * (u t + t) * u t ^ (u t + t - 1) +
        (u' + 1) * alongBasePath u t * Real.log (u t)) t := by
  have hexponent : HasDerivAt (fun s : ℝ => u s + s) (u' + 1) t := by
    convert hu.add (hasDerivAt_id t) using 1 <;> funext s <;> simp
  simpa [alongBasePath, mul_assoc] using hu.rpow hexponent hx


/-- Evaluate the positive-base exponent family along two differentiable
coordinate paths. -/
noncomputable def alongJointPath (u v : ℝ → ℝ) (s : ℝ) : ℝ :=
  u s ^ (u s + v s)

/-- General two-coordinate path chain rule. The derivative separates into
the changing-base contribution and the changing-exponent contribution. -/
theorem along_joint_path_derivative
    (u v : ℝ → ℝ) (u' v' t : ℝ)
    (hu : HasDerivAt u u' t) (hv : HasDerivAt v v' t)
    (hx : 0 < u t) :
    HasDerivAt (fun s : ℝ => alongJointPath u v s)
      (u' * (u t + v t) * u t ^ (u t + v t - 1) +
        (u' + v') * alongJointPath u v t * Real.log (u t)) t := by
  have hexponent : HasDerivAt (fun s : ℝ => u s + v s) (u' + v') t := by
    convert hu.add hv using 1 <;> funext s <;> simp
  simpa [alongJointPath, mul_assoc] using hu.rpow hexponent hx


/-- Joint exponentiation of two differentiable real-valued coordinate maps
on an arbitrary real normed space. -/
noncomputable def jointMap {E : Type*} [NormedAddCommGroup E] [NormedSpace ℝ E]
    (f g : E → ℝ) (z : E) : ℝ :=
  f z ^ (f z + g z)

/-- Full Fréchet chain rule for the joint exponent map. This is stronger than
a one-dimensional path theorem: the domain may be any real normed space, and
the derivative is a continuous linear map on that domain. -/
theorem joint_map_fderiv
    {E : Type*} [NormedAddCommGroup E] [NormedSpace ℝ E]
    (f g : E → ℝ) (f' g' : E →L[ℝ] ℝ) (z : E)
    (hf : HasFDerivAt f f' z) (hg : HasFDerivAt g g' z)
    (hx : 0 < f z) :
    HasFDerivAt (fun w : E => jointMap f g w)
      (((f z + g z) * f z ^ (f z + g z - 1)) • f' +
        (f z ^ (f z + g z) * Real.log (f z)) • (f' + g')) z := by
  have hexponent : HasFDerivAt (fun w : E => f w + g w) (f' + g') z := by
    exact hf.add hg
  have h := hf.rpow hexponent hx
  convert h using 1 <;> simp [jointMap, smul_add, add_smul, mul_comm,
    mul_left_comm, mul_assoc]

end MosaicRealExponentShift


namespace MosaicRealExponentShift

/-- The two mixed-coordinate derivative formulas agree. This is the
explicit symmetry identity for the mixed second partials of the joint
positive-base exponent family. -/
theorem mixed_partials_equal (x t : ℝ) (hx : 0 < x) :
    (((x + t) * x ^ (x + t - 1) + jointValue x t * Real.log x) *
        Real.log x + jointValue x t * x⁻¹) =
      (x ^ (x + t - 1) +
        (x + t) * x ^ (x + t - 1) * Real.log x +
        jointValue x t * (Real.log x) ^ 2) := by
  have hpow : x ^ (x + t) = x * x ^ (x + t - 1) := by
    rw [show x + t = (x + t - 1) + 1 by ring,
      Real.rpow_add hx]
    rw [Real.rpow_one]
    ring
  rw [jointValue, hpow]
  field_simp [ne_of_gt hx]
  <;> ring


/-- The two first-partial stationarity equations have exactly one solution
on the positive-base domain. -/
theorem stationary_point_unique (x t : ℝ) (hx : 0 < x)
    (hExponent : jointValue x t * Real.log x = 0)
    (hBase :
      (x + t) * x ^ (x + t - 1) +
        jointValue x t * Real.log x = 0) :
    x = 1 ∧ t = -1 := by
  have hG : 0 < jointValue x t := by
    unfold jointValue
    exact Real.rpow_pos_of_pos hx _
  have hlog : Real.log x = 0 := by
    rcases mul_eq_zero.mp hExponent with hzero | hzero
    · exact (False.elim (ne_of_gt hG hzero))
    · exact hzero
  have hxone : x = 1 := by
    rcases Real.log_eq_zero.mp hlog with hzero | hone | hneg
    · exact False.elim (ne_of_gt hx hzero)
    · exact hone
    · rw [hneg] at hx
      norm_num at hx
  constructor
  · exact hxone
  · subst x
    have ht : 1 + t = 0 := by
      simpa [jointValue] using hBase
    linarith

end MosaicRealExponentShift


namespace MosaicSphericalGeometry

/-- First coordinate of stereographic projection from the plane to the
unit sphere. -/
noncomputable def sphereX (u t : ℝ) : ℝ :=
  2 * u / (1 + u ^ 2 + t ^ 2)

/-- Second coordinate of stereographic projection from the plane to the
unit sphere. -/
noncomputable def sphereY (u t : ℝ) : ℝ :=
  2 * t / (1 + u ^ 2 + t ^ 2)

/-- Third coordinate of stereographic projection from the plane to the
unit sphere. -/
noncomputable def sphereZ (u t : ℝ) : ℝ :=
  (u ^ 2 + t ^ 2 - 1) / (1 + u ^ 2 + t ^ 2)

/-- Every finite point under stereographic projection lies on the unit
sphere. This is the algebraic invariant underlying the spherical model. -/
theorem stereographic_sphere_identity (u t : ℝ) :
    (sphereX u t) ^ 2 + (sphereY u t) ^ 2 +
      (sphereZ u t) ^ 2 = 1 := by
  unfold sphereX sphereY sphereZ
  have hden : 1 + u ^ 2 + t ^ 2 ≠ 0 := by
    positivity
  field_simp
  <;> ring

/-- Reflection in the first coordinate axis. -/
def reflectFirst (p : ℝ × ℝ) : ℝ × ℝ :=
  (-p.1, p.2)

/-- Reflection in the second coordinate axis. -/
def reflectSecond (p : ℝ × ℝ) : ℝ × ℝ :=
  (p.1, -p.2)

/-- Each coordinate reflection is an involution. -/
theorem reflectFirst_involutive (p : ℝ × ℝ) :
    reflectFirst (reflectFirst p) = p := by
  cases p
  simp [reflectFirst]

/-- The second coordinate reflection is also an involution. -/
theorem reflectSecond_involutive (p : ℝ × ℝ) :
    reflectSecond (reflectSecond p) = p := by
  cases p
  simp [reflectSecond]

/-- The two independent coordinate reflections commute. -/
theorem coordinate_reflections_commute (p : ℝ × ℝ) :
    reflectFirst (reflectSecond p) =
      reflectSecond (reflectFirst p) := by
  cases p
  simp [reflectFirst, reflectSecond]


/-- Squared Euclidean radius in the stereographic parameter plane. -/
def squaredRadius (p : ℝ × ℝ) : ℝ :=
  p.1 ^ 2 + p.2 ^ 2

/-- Reflection in the first coordinate preserves squared radius. -/
theorem reflectFirst_preserves_squaredRadius (p : ℝ × ℝ) :
    squaredRadius (reflectFirst p) = squaredRadius p := by
  cases p
  simp [squaredRadius, reflectFirst]

/-- Reflection in the second coordinate preserves squared radius. -/
theorem reflectSecond_preserves_squaredRadius (p : ℝ × ℝ) :
    squaredRadius (reflectSecond p) = squaredRadius p := by
  cases p
  simp [squaredRadius, reflectSecond]

/-- Simultaneous sign reversal, the composition of the two reflections. -/
def reflectBoth (p : ℝ × ℝ) : ℝ × ℝ :=
  (-p.1, -p.2)

/-- Simultaneous sign reversal is an involution. -/
theorem reflectBoth_involutive (p : ℝ × ℝ) :
    reflectBoth (reflectBoth p) = p := by
  cases p
  simp [reflectBoth]

/-- Simultaneous sign reversal also preserves squared radius. -/
theorem reflectBoth_preserves_squaredRadius (p : ℝ × ℝ) :
    squaredRadius (reflectBoth p) = squaredRadius p := by
  cases p
  simp [squaredRadius, reflectBoth]

/-- The simultaneous reversal is exactly the composition of the
independent coordinate reflections. -/
theorem reflectBoth_eq_composition (p : ℝ × ℝ) :
    reflectBoth p = reflectFirst (reflectSecond p) := by
  cases p
  rfl


/-- Stereographic projection intertwines reflection of the first plane
coordinate with reflection of the first sphere coordinate. -/
theorem stereographic_reflect_first (u t : ℝ) :
    (sphereX (-u) t, sphereY (-u) t, sphereZ (-u) t) =
      (-sphereX u t, sphereY u t, sphereZ u t) := by
  simp [sphereX, sphereY, sphereZ]
  <;> ring

/-- Stereographic projection intertwines reflection of the second plane
coordinate with reflection of the second sphere coordinate. -/
theorem stereographic_reflect_second (u t : ℝ) :
    (sphereX u (-t), sphereY u (-t), sphereZ u (-t)) =
      (sphereX u t, -sphereY u t, sphereZ u t) := by
  simp [sphereX, sphereY, sphereZ]
  <;> ring


/-- Coordinatewise multiplication by a sign vector on a finite-dimensional
real coordinate space. -/
def signChange {n : Nat} (ε x : Fin n → ℝ) : Fin n → ℝ :=
  fun i => ε i * x i

/-- Any coordinatewise sign vector (entries whose squares are one)
preserves the sum of coordinate squares in every finite dimension. -/
theorem sign_change_preserves_sum_squares {n : Nat}
    (ε x : Fin n → ℝ) (hε : ∀ i, ε i ^ 2 = 1) :
    (∑ i : Fin n, (signChange ε x i) ^ 2) =
      ∑ i : Fin n, (x i) ^ 2 := by
  unfold signChange
  apply Finset.sum_congr rfl
  intro i hi
  rw [mul_pow, hε i]
  ring


/-- Coordinatewise sign changes preserve the unit sphere in every finite
dimension. -/
theorem sign_change_preserves_unit_sphere {n : Nat}
    (ε x : Fin n → ℝ) (hε : ∀ i, ε i ^ 2 = 1)
    (hx : (∑ i : Fin n, (x i) ^ 2) = 1) :
    (∑ i : Fin n, (signChange ε x i) ^ 2) = 1 := by
  rw [sign_change_preserves_sum_squares ε x hε]
  exact hx

/-- Applying two coordinatewise sign changes is multiplication by their
pointwise product. -/
theorem sign_change_compose {n : Nat} (ε δ x : Fin n → ℝ) :
    signChange ε (signChange δ x) =
      signChange (fun i => ε i * δ i) x := by
  funext i
  simp [signChange, mul_assoc]


/-- A sign change is an involution whenever every sign entry squares to
one. -/
theorem sign_change_involutive {n : Nat}
    (ε x : Fin n → ℝ) (hε : ∀ i, ε i ^ 2 = 1) :
    signChange ε (signChange ε x) = x := by
  funext i
  change ε i * (ε i * x i) = x i
  calc
    ε i * (ε i * x i) = (ε i) ^ 2 * x i := by ring
    _ = 1 * x i := by rw [hε i]
    _ = x i := by ring


/-- Coordinatewise sign changes preserve Euclidean squared distance, not
just distance from the origin. -/
theorem sign_change_preserves_squared_distance {n : Nat}
    (ε x y : Fin n → ℝ) (hε : ∀ i, ε i ^ 2 = 1) :
    (∑ i : Fin n, (signChange ε x i - signChange ε y i) ^ 2) =
      ∑ i : Fin n, (x i - y i) ^ 2 := by
  unfold signChange
  apply Finset.sum_congr rfl
  intro i hi
  rw [show ε i * x i - ε i * y i = ε i * (x i - y i) by ring]
  rw [mul_pow, hε i]
  ring


/-- A Boolean choice encodes one of the two coordinate signs. -/
def boolSign (b : Bool) : ℝ :=
  if b then 1 else -1

/-- Every Boolean sign has square one. -/
theorem boolSign_sq (b : Bool) : (boolSign b) ^ 2 = 1 := by
  cases b <;> norm_num [boolSign]

/-- The finite sign vector associated with a Boolean sign pattern. -/
def booleanSignVector {n : Nat} (b : Fin n → Bool) : Fin n → ℝ :=
  fun i => boolSign (b i)

/-- Every Boolean sign pattern preserves squared Euclidean norm. -/
theorem boolean_sign_preserves_sum_squares {n : Nat}
    (b : Fin n → Bool) (x : Fin n → ℝ) :
    (∑ i : Fin n, (signChange (booleanSignVector b) x i) ^ 2) =
      ∑ i : Fin n, (x i) ^ 2 := by
  apply sign_change_preserves_sum_squares
  intro i
  exact boolSign_sq (b i)

/-- Distinct Boolean patterns give distinct sign vectors. -/
theorem booleanSignVector_injective {n : Nat} :
    Function.Injective (booleanSignVector (n := n)) := by
  intro b c h
  funext i
  have hi := congrFun h i
  change boolSign (b i) = boolSign (c i) at hi
  cases hb : b i <;> cases hc : c i
  · rfl
  · exfalso
    have hbad : (-1 : ℝ) = 1 := by simpa [boolSign, hb, hc] using hi
    norm_num at hbad
  · exfalso
    have hbad : (1 : ℝ) = -1 := by simpa [boolSign, hb, hc] using hi
    norm_num at hbad
  · rfl

/-- There are exactly 2^n Boolean sign patterns in dimension n. -/
theorem boolean_sign_pattern_cardinality (n : Nat) :
    Fintype.card (Fin n → Bool) = 2 ^ n := by
  simp


/-- Every real sign vector whose coordinates square to one is represented
by a Boolean sign pattern. -/
theorem booleanSignVector_surjective_onto_signs {n : Nat}
    (ε : Fin n → ℝ) (hε : ∀ i, ε i ^ 2 = 1) :
    ∃ b : Fin n → Bool, booleanSignVector b = ε := by
  let b : Fin n → Bool := fun i => decide (ε i = 1)
  refine ⟨b, ?_⟩
  funext i
  by_cases h : ε i = 1
  · simp [booleanSignVector, b, h, boolSign]
  · have hfactor : (ε i - 1) * (ε i + 1) = 0 := by
      nlinarith [hε i]
    have hneg : ε i = -1 := by
      rcases mul_eq_zero.mp hfactor with hone | hminus
      · have heq : ε i = 1 := by linarith
        exfalso
        exact h heq
      · linarith
    change boolSign (b i) = ε i
    rw [show b i = false by simp [b, hneg], boolSign]
    exact hneg


/-- An open orthant specified by a vector of coordinate signs. -/
def signedOrthant {n : Nat} (ε : Fin n → ℝ) : Set (Fin n → ℝ) :=
  {x | ∀ i, 0 < ε i * x i}

/-- Coordinate sign changes carry a signed orthant onto the orthant
whose sign vector is multiplied coordinatewise by the acting signs. -/
theorem sign_change_maps_signed_orthant {n : Nat}
    (ε δ : Fin n → ℝ) (hδ : ∀ i, δ i ^ 2 = 1) :
    signChange δ '' signedOrthant ε =
      signedOrthant (fun i => ε i * δ i) := by
  apply Set.Subset.antisymm
  · rintro y ⟨x, hx, rfl⟩
    intro i
    have heq : (ε i * δ i) * (δ i * x i) = ε i * x i := by
      calc
        (ε i * δ i) * (δ i * x i) =
            ε i * ((δ i) ^ 2 * x i) := by ring
        _ = ε i * (1 * x i) := by rw [hδ i]
        _ = ε i * x i := by ring
    change 0 < (ε i * δ i) * (δ i * x i)
    rw [heq]
    exact hx i
  · intro y hy
    refine ⟨signChange δ y, ?_, sign_change_involutive δ y hδ⟩
    intro i
    have heq : ε i * (δ i * y i) = (ε i * δ i) * y i := by ring
    change 0 < ε i * (δ i * y i)
    rw [heq]
    exact hy i

/-- Any two signed orthants are related by a coordinate sign change.
This is the transitivity statement needed for equal-measure arguments. -/
theorem signed_orthants_transitive {n : Nat}
    (ε η : Fin n → ℝ)
    (hε : ∀ i, ε i ^ 2 = 1) (hη : ∀ i, η i ^ 2 = 1) :
    ∃ δ : Fin n → ℝ, (∀ i, δ i ^ 2 = 1) ∧
      signChange δ '' signedOrthant ε = signedOrthant η := by
  let δ : Fin n → ℝ := fun i => ε i * η i
  have hδ : ∀ i, δ i ^ 2 = 1 := by
    intro i
    simp only [δ, mul_pow, hε i, hη i]
    norm_num
  refine ⟨δ, hδ, ?_⟩
  rw [sign_change_maps_signed_orthant ε δ hδ]
  have hsign : (fun i => ε i * δ i) = η := by
    funext i
    dsimp [δ]
    calc
      ε i * (ε i * η i) = (ε i) ^ 2 * η i := by ring
      _ = 1 * η i := by rw [hε i]
      _ = η i := by ring
  rw [hsign]


/-- Different sign vectors specify different open orthants. -/
theorem signedOrthant_ne_of_ne {n : Nat}
    (ε η : Fin n → ℝ)
    (hε : ∀ i, ε i ^ 2 = 1) (hη : ∀ i, η i ^ 2 = 1)
    (hne : ε ≠ η) :
    signedOrthant ε ≠ signedOrthant η := by
  intro hsets
  obtain ⟨i, hi⟩ := Function.ne_iff.mp hne
  have hmem : ε ∈ signedOrthant ε := by
    intro j
    change 0 < ε j * ε j
    nlinarith [hε j]
  have hmem' : ε ∈ signedOrthant η := by
    rw [← hsets]
    exact hmem
  have hprod_sq : (ε i * η i) ^ 2 = 1 := by
    rw [mul_pow, hε i, hη i]
    norm_num
  have hprod_ne : ε i * η i ≠ 1 := by
    intro h
    apply hi
    calc
      ε i = ε i * 1 := by ring
      _ = ε i * (η i * η i) := by
        have hηmul : η i * η i = 1 := by nlinarith [hη i]
        rw [hηmul]
      _ = (ε i * η i) * η i := by ring
      _ = 1 * η i := by rw [h]
      _ = η i := by ring
  have hfactor :
      (ε i * η i - 1) * (ε i * η i + 1) = 0 := by
    nlinarith [hprod_sq]
  have hpos := hmem' i
  change 0 < η i * ε i at hpos
  rw [mul_comm] at hpos
  rcases mul_eq_zero.mp hfactor with h | h
  · apply hprod_ne
    linarith
  · linarith

/-- Distinct sign vectors with entries squaring to one define disjoint
open orthants. -/
theorem signedOrthant_disjoint_of_ne {n : Nat}
    (ε η : Fin n → ℝ)
    (hε : ∀ i, ε i ^ 2 = 1) (hη : ∀ i, η i ^ 2 = 1)
    (hne : ε ≠ η) :
    Disjoint (signedOrthant ε) (signedOrthant η) := by
  obtain ⟨i, hi⟩ := Function.ne_iff.mp hne
  rw [Set.disjoint_left]
  intro x hx hy
  have hprod_sq : (ε i * η i) ^ 2 = 1 := by
    rw [mul_pow, hε i, hη i]
    norm_num
  have hprod_ne : ε i * η i ≠ 1 := by
    intro h
    apply hi
    calc
      ε i = ε i * 1 := by ring
      _ = ε i * (η i * η i) := by
        have hηmul : η i * η i = 1 := by nlinarith [hη i]
        rw [hηmul]
      _ = (ε i * η i) * η i := by ring
      _ = 1 * η i := by rw [h]
      _ = η i := by ring
  have hfactor :
      (ε i * η i - 1) * (ε i * η i + 1) = 0 := by
    nlinarith [hprod_sq]
  have hpos : 0 < ε i * x i := hx i
  have hpos' : 0 < η i * x i := hy i
  have hmul : (ε i * x i) * (η i * x i) =
      (ε i * η i) * (x i * x i) := by ring
  have hxne : x i ≠ 0 := by
    intro hz
    rw [hz] at hpos
    norm_num at hpos
  have hxx : 0 < x i * x i := mul_self_pos.mpr hxne
  have hprod : 0 < (ε i * x i) * (η i * x i) :=
    mul_pos hpos hpos'
  rw [hmul] at hprod
  have hprodpos : 0 < ε i * η i := by
    nlinarith [hprod, hxx]
  rcases mul_eq_zero.mp hfactor with hplus | hminus
  · have : ε i * η i = 1 := by linarith
    exact hprod_ne this
  · have : ε i * η i = -1 := by linarith
    linarith


/-- The union of all Boolean-indexed open orthants is exactly the
set of vectors with no zero coordinate. -/
theorem exists_boolean_orthant_iff_all_coordinates_ne_zero {n : Nat}
    (x : Fin n → ℝ) :
    (∃ b : Fin n → Bool,
      x ∈ signedOrthant (booleanSignVector b)) ↔
      ∀ i, x i ≠ 0 := by
  constructor
  · rintro ⟨b, hb⟩ i hzero
    have hpos := hb i
    rw [hzero] at hpos
    simp [booleanSignVector, boolSign] at hpos
  · intro hx
    let b : Fin n → Bool := fun i => decide (0 < x i)
    refine ⟨b, ?_⟩
    intro i
    by_cases hpos : 0 < x i
    · simp [booleanSignVector, b, hpos, boolSign]
    · have hle : x i ≤ 0 := le_of_not_gt hpos
      have hneg : x i < 0 := lt_of_le_of_ne hle (hx i)
      simp [booleanSignVector, b, hpos, boolSign]
      nlinarith


/-- The unit sphere in finite-dimensional real coordinate space. -/
def coordinateUnitSphere {n : Nat} : Set (Fin n → ℝ) :=
  {x | ∑ i : Fin n, (x i) ^ 2 = 1}

/-- The Boolean-indexed spherical orthants cover exactly the part of the
unit sphere away from all coordinate hyperplanes. -/
theorem spherical_orthant_cover_iff {n : Nat}
    (x : Fin n → ℝ) (hx : x ∈ coordinateUnitSphere) :
    (∃ b : Fin n → Bool,
      x ∈ signedOrthant (booleanSignVector b)) ↔
      ∀ i, x i ≠ 0 := by
  exact exists_boolean_orthant_iff_all_coordinates_ne_zero x


/-- Distinct Boolean-indexed spherical orthants are disjoint. -/
theorem boolean_spherical_orthants_disjoint {n : Nat}
    (b c : Fin n → Bool) (hbc : b ≠ c) :
    Disjoint
      (coordinateUnitSphere ∩ signedOrthant (booleanSignVector b))
      (coordinateUnitSphere ∩ signedOrthant (booleanSignVector c)) := by
  apply Set.disjoint_left.mpr
  intro x hx hy
  have hne : booleanSignVector b ≠ booleanSignVector c :=
    booleanSignVector_injective.ne hbc
  exact (signedOrthant_disjoint_of_ne
    (booleanSignVector b) (booleanSignVector c)
    (fun i => boolSign_sq (b i))
    (fun i => boolSign_sq (c i)) hne) hx.2 hy.2


/-- Boolean patterns enumerate distinct open orthants: the map from
Boolean coordinate choices to their corresponding open orthant is injective. -/
theorem boolean_orthant_injective {n : Nat} :
    Function.Injective
      (fun b : Fin n → Bool => signedOrthant (booleanSignVector b)) := by
  intro b c hsets
  apply booleanSignVector_injective
  by_contra hne
  have hneOrth :
      signedOrthant (booleanSignVector b) ≠
        signedOrthant (booleanSignVector c) :=
    signedOrthant_ne_of_ne
      (booleanSignVector b) (booleanSignVector c)
      (fun i => boolSign_sq (b i))
      (fun i => boolSign_sq (c i)) hne
  exact hneOrth hsets


/-- The finite family of Boolean-indexed open orthants has exactly
2^n members. -/
theorem boolean_orthant_cardinality (n : Nat) :
    Fintype.card
      (Set.range
        (fun b : Fin n → Bool =>
          signedOrthant (booleanSignVector b))) = 2 ^ n := by
  classical
  calc
    Fintype.card
        (Set.range
          (fun b : Fin n → Bool =>
            signedOrthant (booleanSignVector b))) =
        Fintype.card (Fin n → Bool) :=
      Fintype.card_congr
        (Equiv.ofInjective
          (fun b : Fin n → Bool =>
            signedOrthant (booleanSignVector b))
          boolean_orthant_injective).symm
    _ = 2 ^ n := boolean_sign_pattern_cardinality n


end MosaicSphericalGeometry


/-!
A reusable measure-theoretic bridge for the orthant argument:
a measurable equivalence that preserves a measure and maps one measurable
region onto another forces the two regions to have equal measure.
-/
namespace MosaicMeasureSymmetry

open MeasureTheory

/-- A measure-preserving measurable equivalence carries measurable sets
to sets of equal measure. -/
theorem measure_eq_of_measure_preserving_equiv
    {α : Type*} [MeasurableSpace α] (μ : Measure α)
    (s t : Set α) (hs : MeasurableSet s) (ht : MeasurableSet t)
    (e : α ≃ᵐ α)
    (hpres : MeasurePreserving (fun x => e x) μ μ)
    (himage : e '' s = t) :
    μ s = μ t := by
  have hpre : e ⁻¹' t = s := by
    ext x
    change e x ∈ t ↔ x ∈ s
    rw [← himage]
    constructor
    · rintro ⟨y, hy, hxy⟩
      have hEq : y = x := e.injective hxy
      simpa [hEq] using hy
    · intro hx
      exact ⟨x, hx, rfl⟩
  have hmap := congrArg (fun ν : Measure α => ν t) hpres.map_eq
  rw [Measure.map_apply hpres.measurable ht] at hmap
  rw [hpre] at hmap
  exact hmap

/-- Transitivity by measure-preserving measurable equivalences forces all
regions in a finite family to have equal measure. -/
theorem all_regions_equal_measure
    {α : Type*} [MeasurableSpace α] (μ : Measure α)
    {ι : Type*} (A : ι → Set α)
    (hmeas : ∀ i, MeasurableSet (A i))
    (htrans : ∀ i j, ∃ e : α ≃ᵐ α,
      MeasurePreserving (fun x => e x) μ μ ∧ e '' A i = A j) :
    ∀ i j, μ (A i) = μ (A j) := by
  intro i j
  obtain ⟨e, hpres, himage⟩ := htrans i j
  exact measure_eq_of_measure_preserving_equiv μ (A i) (A j)
    (hmeas i) (hmeas j) e hpres himage

/-- If a finite family of measurable regions is related transitively by
measure-preserving equivalences, then summing their measures is the
cardinality of the family times the measure of any chosen region. -/
theorem sum_region_measures
    {α : Type*} [MeasurableSpace α] (μ : Measure α)
    {ι : Type*} [Fintype ι] (A : ι → Set α)
    (hmeas : ∀ i, MeasurableSet (A i))
    (htrans : ∀ i j, ∃ e : α ≃ᵐ α,
      MeasurePreserving (fun x => e x) μ μ ∧ e '' A i = A j)
    (i₀ : ι) :
    (∑ i : ι, μ (A i)) =
      (Fintype.card ι : ENNReal) * μ (A i₀) := by
  classical
  have heq := all_regions_equal_measure μ A hmeas htrans
  calc
    (∑ i : ι, μ (A i)) = ∑ i : ι, μ (A i₀) := by
      apply Finset.sum_congr rfl
      intro i hi
      exact heq i i₀
    _ = (Fintype.card ι : ENNReal) * μ (A i₀) := by
      simp

end MosaicMeasureSymmetry
